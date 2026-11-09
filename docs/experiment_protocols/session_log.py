#!/usr/bin/env python3
"""
session_log.py — SecLogTrace coverage sweep helper

Type a short description of what you are about to do, press Enter, then do
it in the browser. The script stamps the time for you. Nothing is typed by
hand except the description.

Run it:      python3 session_log.py
Windows:     py session_log.py

Every line is written to disk immediately, so nothing is lost if the
terminal closes.

Commands (type these instead of a description):
    ok          mark the previous entry as succeeded
    fail <msg>  mark the previous entry as failed, with a reason
    note <msg>  add a free-text note without starting a new entry
    done        end the session and print the summary block
"""

import datetime
import os
import sys

FILENAME = "coverage_sweep_session_log.txt"


def now():
    # Local time WITH the UTC offset attached. The offset is not optional:
    # the export query is built from these timestamps and a missing offset
    # silently shifts the window by hours.
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def write(fh, line):
    fh.write(line + "\n")
    fh.flush()
    os.fsync(fh.fileno())


def main():
    start = now()
    tz = datetime.datetime.now().astimezone().tzname()
    offset = datetime.datetime.now().astimezone().strftime("%z")

    exists = os.path.exists(FILENAME)
    fh = open(FILENAME, "a", encoding="utf-8")

    if exists:
        write(fh, "")
        write(fh, "--- session resumed ---")

    write(fh, "=" * 68)
    write(fh, "SecLogTrace coverage sweep — session log")
    write(fh, f"SESSION START : {start}")
    write(fh, f"TIMEZONE      : {tz} (UTC{offset})")
    write(fh, f"MACHINE       : {os.uname().nodename if hasattr(os, 'uname') else 'windows'}")
    write(fh, "=" * 68)

    print()
    print("=" * 68)
    print("  SecLogTrace coverage sweep — session logger")
    print("=" * 68)
    print(f"  Session started : {start}")
    print(f"  Timezone        : {tz} (UTC{offset})")
    print(f"  Writing to      : {os.path.abspath(FILENAME)}")
    print()
    print("  Before each action, type what you are about to do, press Enter,")
    print("  THEN do it in the browser. Type 'ok' or 'fail <reason>' after.")
    print("  Type 'done' when the session is over.")
    print("=" * 68)
    print()

    n = 0
    last = None
    try:
        while True:
            try:
                raw = input(f"[{n + 1:>3}] > ").strip()
            except EOFError:
                raw = "done"

            if not raw:
                continue

            low = raw.lower()

            if low == "done":
                end = now()
                write(fh, "")
                write(fh, "=" * 68)
                write(fh, f"SESSION END   : {end}")
                write(fh, f"ENTRIES       : {n}")
                write(fh, "=" * 68)
                print()
                print("=" * 68)
                print("  SESSION COMPLETE")
                print("=" * 68)
                print(f"  Start   : {start}")
                print(f"  End     : {end}")
                print(f"  Entries : {n}")
                print(f"  File    : {os.path.abspath(FILENAME)}")
                print()
                print("  Send Shaafi BOTH of these:")
                print(f"    1. {FILENAME}")
                print("    2. Your exported HAR file from the browser")
                print()
                print("  Paste this into your message to him:")
                print()
                print(f"    SESSION START : {start}")
                print(f"    SESSION END   : {end}")
                print(f"    TIMEZONE      : {tz} (UTC{offset})")
                print(f"    ENTRIES       : {n}")
                print()
                break

            if low == "ok":
                if last is None:
                    print("      (nothing to mark yet)")
                    continue
                write(fh, f"        -> OK        {now()}")
                print("      marked OK")
                continue

            if low.startswith("fail"):
                msg = raw[4:].strip(" :-") or "no reason given"
                write(fh, f"        -> FAILED    {now()}  |  {msg}")
                print(f"      marked FAILED: {msg}")
                continue

            if low.startswith("note"):
                msg = raw[4:].strip(" :-")
                write(fh, f"        #  NOTE      {now()}  |  {msg}")
                print("      note recorded")
                continue

            n += 1
            last = raw
            write(fh, f"[{n:>3}] {now()}  |  {raw}")
            print(f"      logged. Do it now, then type 'ok' or 'fail <reason>'.")

    except KeyboardInterrupt:
        write(fh, "")
        write(fh, f"SESSION INTERRUPTED (Ctrl-C) : {now()}")
        write(fh, f"ENTRIES : {n}")
        print("\n\n  Interrupted. The log file is saved and still valid.")
        print(f"  File: {os.path.abspath(FILENAME)}")
    finally:
        fh.close()


if __name__ == "__main__":
    sys.exit(main())
