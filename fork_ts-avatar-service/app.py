from flask import Flask, request, jsonify
import numpy as np
import urllib
import urllib.request
import cv2
import os
import json
import base64
import traceback

from face_detect import check

app = Flask(__name__)

receive_path = r"./received/"


# ---------------------------------------------------------------------------
# SecLogTrace: injected CWE-918 (SSRF) sink.
#
# The original endpoint accepted only a base64 image in the request body.
# This adds an ALTERNATIVE input method: a "src_url" field. When present,
# the service fetches the image from that URL server-side (using the already-
# imported urllib) instead of decoding base64.
#
# This is DELIBERATELY VULNERABLE and must not be "fixed":
#   - no scheme restriction (http/https/file/ftp all pass through urllib)
#   - no host validation (private ranges, link-local 169.254.169.254,
#     cluster-internal DNS names, localhost all allowed)
#   - no port restriction
#   - no size/timeout guard beyond urllib defaults
#
# It mirrors the single most common real-world SSRF root cause: a legitimate
# "fetch an image/resource by URL" feature with missing destination
# validation. The cover story is native to this service — an avatar service
# fetching a profile image by URL is ordinary functionality, not a bolted-on
# endpoint. See docs/design/SSRF_INJECTION_DESIGN.md.
# ---------------------------------------------------------------------------
def _fetch_url_bytes(src_url):
    # The actual SSRF: server issues this request, from inside the cluster
    # network, to whatever destination the caller specified. urllib follows
    # http->http redirects by default, widening the sink further.
    req = urllib.request.Request(src_url, headers={"User-Agent": "ts-avatar-service"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (intentional)
        return resp.read(), resp.getcode()


@app.route('/api/v1/avatar', methods=["POST"])
def hello():
    data = request.get_data().decode('utf-8')
    data = json.loads(data)

    image_b64 = data.get("img")
    src_url = data.get("src_url")   # <-- injected SSRF input path

    image_decode = None

    # New URL branch. Takes precedence when src_url is supplied.
    if src_url is not None and len(src_url) > 0:
        try:
            fetched_bytes, status = _fetch_url_bytes(src_url)
            image_decode = fetched_bytes
        except Exception:
            # Deliberately surfaces the failure detail. Distinguishing
            # "connection refused" vs "host unreachable" vs "404" is a
            # classic SSRF fingerprinting oracle, and returning it makes
            # the internal-network probing visible in the response — which
            # is realistic for naive implementations and useful signal for
            # the corpus.
            return jsonify({"msg": "fetch failed: " + str(traceback.format_exc())}), 502
    elif image_b64 is not None and len(image_b64) >= 1:
        image_decode = base64.b64decode(image_b64)
    else:
        return jsonify({"msg": "need img (base64) or src_url in request body"}), 400

    try:
        nparr = np.fromstring(image_decode, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        result = check(image)
    except Exception as e:
        return jsonify({"msg": "exception:" + str(traceback.format_exc())}), 500

    if type(result) == dict and result.get("msg") is not None:
        return jsonify(result), 400

    return result, 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=17001, debug=True)
