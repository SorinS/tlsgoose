#!/usr/bin/env python3
"""Extract the simple 1-RTT handshake of RFC 8448 (section 3) into
test/vectors/rfc8448.txt: one `label hex` line per value the trace prints,
labelled `<side>.<step>.<field>` from the RFC's own wording, so a test can
ask for "server.derive_write_traffic_keys_for_handshake_data.key_expanded".

    python3 scripts/rfc8448.py [rfc8448.txt]

Without a path the RFC is fetched from www.rfc-editor.org.
"""

import os
import re
import sys
import urllib.request

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def slug(s):
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def main():
    if len(sys.argv) > 1:
        text = open(sys.argv[1]).read()
    else:
        text = urllib.request.urlopen("https://www.rfc-editor.org/rfc/rfc8448.txt").read().decode()
    start = text.index("\n3.  Simple 1-RTT Handshake")
    end = text.index("\n4.  Resumed 0-RTT Handshake")
    lines = text[start:end].split("\n")
    # Drop the page breaks: footer, form feed, header.
    lines = [l for l in lines if not l.startswith(("Thomson ", "RFC 8448 ", "\f"))]
    out, seen = [], {}
    step = None
    field = None
    hexbuf = []

    def flush():
        nonlocal field, hexbuf
        if field is not None and hexbuf:
            label = f"{step}.{field}"
            seen[label] = seen.get(label, 0) + 1
            if seen[label] > 1:
                label += f".{seen[label]}"
            out.append(f"{label} {''.join(hexbuf)}")
        field, hexbuf = None, []

    for line in lines:
        m = re.match(r"^   \{(client|server)\}  (.*?):?\s*$", line)
        if m:
            flush()
            step = f"{m.group(1)}.{slug(m.group(2))}"
            continue
        m = re.match(r"^      ([A-Za-z][A-Za-z ]*?) \((\d+) octets\):  (.*)$", line)
        if m and step:
            flush()
            field = slug(m.group(1))
            hexbuf = [m.group(3).replace(" ", "")] if m.group(2) != "0" else []
            continue
        if field is not None and re.match(r"^         [0-9a-f ]+$", line):
            hexbuf.append(line.strip().replace(" ", ""))
            continue
        if line.strip() == "":
            continue
        flush()
    flush()
    path = os.path.join(ROOT, "test", "vectors", "rfc8448.txt")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {len(out)} values to {os.path.relpath(path, ROOT)}")


if __name__ == "__main__":
    main()
