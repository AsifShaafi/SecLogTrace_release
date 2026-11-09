FROM python:3.9.6
RUN /bin/cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo 'Asia/Shanghai' >/etc/timezone
RUN apt update -y
RUN apt install -y cmake
RUN apt install -y libgl1-mesa-glx
ENV PYTHONUNBUFFERED=TRUE
RUN mkdir -p /app
ADD ts-avatar-service /app/
WORKDIR /app
RUN pip install -r requirements.txt

# ---------------------------------------------------------------------------
# SecLogTrace: OpenTelemetry instrumentation for this Python service.
#
# The 40+ Java services get traced by the OTel Java agent. This Flask
# service is Python and the Java agent cannot touch it, which is why
# ts-avatar-service never appeared in Jaeger. Without this, the injected
# SSRF endpoint produces NO traces and cannot participate in the trace-based
# detection corpus.
#
# opentelemetry-instrument auto-instruments Flask (inbound spans) AND urllib
# (the outbound SSRF request) — so the malicious outbound fetch shows up as
# a child span, which is exactly the signal the detector should catch. It
# also propagates W3C trace context, so these traces join the rest of the
# corpus on trace_id.
# ---------------------------------------------------------------------------
RUN pip install \
      opentelemetry-distro==0.41b0 \
      opentelemetry-exporter-otlp==1.20.0 \
      opentelemetry-instrumentation-flask==0.41b0 \
      opentelemetry-instrumentation-urllib==0.41b0
RUN opentelemetry-bootstrap -a install

# Point at the same OTLP collector the Java services use. Confirm the
# endpoint against a working Java service's OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
# env before building — the value below is the common in-cluster form but
# must match this deployment.
ENV OTEL_SERVICE_NAME=ts-avatar-service
ENV OTEL_TRACES_EXPORTER=otlp
ENV OTEL_EXPORTER_OTLP_PROTOCOL=grpc
ENV OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger-collector:4317
ENV OTEL_PROPAGATORS=tracecontext,baggage

# gunicorn must be launched THROUGH opentelemetry-instrument. The original
# CMD was: gunicorn -w 4 -b 0.0.0.0:17001 app:app
# Note: with OTel + gunicorn prefork workers, a post_fork hook is the robust
# pattern, but for -w 4 the wrapper below works for span export in practice;
# if spans are missing under load, switch to a gunicorn.conf.py post_fork
# initializer (see design doc follow-up note).
CMD ["opentelemetry-instrument", "gunicorn", "-w", "4", "-b", "0.0.0.0:17001", "app:app"]
EXPOSE 17001
