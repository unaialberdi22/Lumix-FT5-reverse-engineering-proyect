#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
lumix_upd.py - inspect Panasonic Lumix "UPD" firmware update packages.

Tested on the publicly distributed update files of DMC-FT5 / TS5 (V1.1, V1.4)
and DMC-TZ40 / TZ41 (V1.3).  This tool only PARSES and COMPARES packages.
It does not decrypt anything (the key is not known) and it cannot build or
re-sign packages.

Sub-commands
  info      FILE            header, CRC32 check, module table
  compare   A B             per-module comparison of two packages
  extract   FILE OUTDIR     dump every module exactly as stored (still encrypted)
  romtxt2bin FILE.TXT OUT   convert a service-mode ROM BACKUP text dump to binary

Only the Python standard library is needed.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zlib

MAGIC = b"UPD\x00"
HDR1_OFF = 0x000          # first header
HDR2_OFF = 0x2A0          # second header (contains data start/length/count)
TABLE_OFF = 0x2EC         # module table starts right after the second header
ENTRY_SIZE = 92
MODULE_HEAD = 0x200       # first 0x200 bytes of every module ("head")
CRC_START = 0x200         # CRC32 covers file[0x200:]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def bcd_ok(b):
    return all((x >> 4) < 10 and (x & 15) < 10 for x in b)


def fmt_version(v):
    """0x0140 -> '1.40' (BCD, major in high byte)."""
    return "%x.%02x" % (v >> 8, v & 0xFF)


def fmt_build(b4):
    """4 bytes = minute, hour, day, month (BCD). Year is not stored."""
    if len(b4) == 4 and bcd_ok(b4):
        return "%02x-%02x %02x:%02x" % (b4[3], b4[2], b4[1], b4[0])
    return "raw:" + b4.hex()


def head_state(chunk):
    if chunk.count(0) == len(chunk):
        return "zero"
    if chunk.count(0xFF) == len(chunk):
        return "ff"
    return "data"


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def parse(data):
    if len(data) < TABLE_OFF + ENTRY_SIZE or data[:4] != MAGIC:
        raise ValueError("not a UPD package (bad magic at 0x0)")
    if data[HDR2_OFF:HDR2_OFF + 4] != MAGIC:
        raise ValueError("second UPD header not found at 0x2A0")

    hdr = {}
    hdr["size_a"], hdr["size_b"] = struct.unpack_from("<II", data, 4)
    hdr["model"] = data[0x0C:0x1C].split(b"\0")[0].decode("latin1")
    va, vb = struct.unpack_from("<HH", data, 0x1C)
    hdr["version_a"], hdr["version_b"] = fmt_version(va), fmt_version(vb)
    (hdr["field_0x20"],) = struct.unpack_from("<I", data, 0x20)
    hdr["build_stamp"] = fmt_build(data[0x24:0x28])
    hdr["data_end"], hdr["crc32_stored"] = struct.unpack_from("<II", data, 0x3C)
    hdr["vendor_tag"] = data[0x200:0x220].split(b"\0")[0].decode("latin1")
    hdr["sig64"] = data[0x220:0x260].hex()  # 64 random-looking bytes, purpose unknown
    dstart, dlen, count = struct.unpack_from("<III", data, HDR2_OFF + 0x40)
    hdr["data_start"], hdr["data_len"], hdr["count"] = dstart, dlen, count
    hdr["crc32_calc"] = zlib.crc32(data[CRC_START:]) & 0xFFFFFFFF
    hdr["crc32_ok"] = hdr["crc32_calc"] == hdr["crc32_stored"]
    hdr["file_size"] = len(data)
    table_end = TABLE_OFF + count * ENTRY_SIZE
    hdr["table_end"] = table_end
    hdr["table_overlaps_data"] = table_end > dstart

    mods, prev_end = [], None
    for i in range(count):
        o = TABLE_OFF + i * ENTRY_SIZE
        e = data[o:o + ENTRY_SIZE]
        if len(e) < ENTRY_SIZE:
            raise ValueError("module table runs past end of file")
        name = e[:12].split(b"\0")[0].decode("latin1")
        off, size, addr, flags = struct.unpack_from("<4I", e, 12)
        sha, param, pad = e[28:60], e[60:76], e[76:92]
        m = dict(index=i, name=name, offset=off, size=size, load_addr=addr,
                 flags=flags, digest=sha.hex(), param=param.hex(),
                 pad_zero=(pad == bytes(16)),
                 contiguous=(prev_end is None and off == dstart) or prev_end == off)
        if off + size <= len(data):
            head = data[off:off + min(MODULE_HEAD, size)]
            if off < table_end:
                m["head"] = "overlapped-by-table"
            else:
                m["head"] = head_state(head) if size else "-"
        else:
            m["head"] = "out-of-range"
        mods.append(m)
        prev_end = off + size
    hdr["modules_end"] = prev_end
    hdr["layout_ok"] = (prev_end == hdr["data_end"]) and all(m["contiguous"] for m in mods)
    return hdr, mods


def load(path):
    with open(path, "rb") as f:
        data = f.read()
    hdr, mods = parse(data)
    return data, hdr, mods


def digest_rule(data, m):
    """Return a description if the stored 32-byte digest can be reproduced.

    Known rule (verified on the modules that are stored in clear, flags=2):
        digest = SHA-256( blank_head || payload )
    where blank_head is 0x200 bytes of 0x00 or 0xFF (NOT the random-looking
    head stored in the file) and payload = module[0x200:] as plaintext.
    For encrypted modules the plaintext is unknown, except when it is a blank
    image (all 0xFF / 0x00): eep_net_a / eep_net_b are all 0xFF.
    """
    n, target = m["size"], bytes.fromhex(m["digest"])
    if n == 0:
        return "empty module (sha256 of empty string)" if hashlib.sha256(b"").digest() == target else ""
    raw = data[m["offset"]:m["offset"] + n]
    for hl, hb in (("00", 0x00), ("ff", 0xFF)):
        head = bytes([hb]) * MODULE_HEAD
        if m["flags"] == 2 and hashlib.sha256(head + raw[MODULE_HEAD:]).digest() == target:
            return "OK: sha256(%s*0x200 + stored payload)" % hl
        for fl, fb in (("00", 0x00), ("ff", 0xFF)):
            if hashlib.sha256(head + bytes([fb]) * (n - MODULE_HEAD)).digest() == target:
                return "plaintext is a blank image (head %s, fill %s)" % (hl, fl)
    return ""


# --------------------------------------------------------------------------
# sub-commands
# --------------------------------------------------------------------------
def cmd_info(a):
    data, hdr, mods = load(a.file)
    if a.check_hash:
        for m in mods:
            m["digest_rule"] = digest_rule(data, m)
    if a.json:
        print(json.dumps({"header": hdr, "modules": mods}, indent=2))
        return 0

    print("File        : %s (%d bytes, %#x)" % (a.file, hdr["file_size"], hdr["file_size"]))
    print("Model       : %s" % hdr["model"])
    print("Version     : %s / %s (BCD, stored twice)" % (hdr["version_a"], hdr["version_b"]))
    print("Build stamp : %s (MM-DD hh:mm, BCD; year not stored - interpretation)" % hdr["build_stamp"])
    print("Vendor tag  : %r at 0x200" % hdr["vendor_tag"])
    print("CRC32       : stored %#010x, calculated over file[0x200:] %#010x -> %s" % (
        hdr["crc32_stored"], hdr["crc32_calc"], "OK" if hdr["crc32_ok"] else "MISMATCH"))
    print("Data        : start %#x, length %#x, end %#x, modules %d" % (
        hdr["data_start"], hdr["data_len"], hdr["data_end"], hdr["count"]))
    print("Layout      : modules contiguous and end at data_end -> %s" % ("OK" if hdr["layout_ok"] else "NO"))
    if hdr["table_overlaps_data"]:
        print("Note        : module table ends at %#x, i.e. it runs %#x bytes into the data area\n"
              "              (over the otherwise empty 0x200-byte head of the first module)" % (
                  hdr["table_end"], hdr["table_end"] - hdr["data_start"]))
    print("64-byte block at 0x220: %s..." % hdr["sig64"][:32])
    print()
    cols = "%2s %-10s %10s %10s %10s %5s %-19s %-32s %s"
    print(cols % ("#", "name", "offset", "size", "load", "flags", "head", "param", "digest[:16]"))
    for m in mods:
        line = cols % (m["index"], m["name"], "%#x" % m["offset"], "%#x" % m["size"],
                       "%#x" % m["load_addr"], m["flags"], m["head"], m["param"], m["digest"][:16])
        if a.check_hash:
            line += "  digest-rule: " + (m["digest_rule"] or "not verified")
        print(line)
    return 0


def cmd_compare(a):
    da, ha, ma = load(a.a)
    db, hb, mb = load(a.b)
    print("A: %s  model=%s version=%s build=%s crc_ok=%s" % (a.a, ha["model"], ha["version_a"], ha["build_stamp"], ha["crc32_ok"]))
    print("B: %s  model=%s version=%s build=%s crc_ok=%s" % (a.b, hb["model"], hb["version_a"], hb["build_stamp"], hb["crc32_ok"]))
    print("64-byte block at 0x220 identical: %s" % (ha["sig64"] == hb["sig64"]))
    print()
    bmap = {m["name"]: m for m in mb}
    cols = "%-10s %-4s %-6s %-6s %-6s %-6s %s"
    print(cols % ("module", "fl", "size=", "digest=", "param=", "head=", "payload (after 0x200)"))
    for m in ma:
        n = bmap.get(m["name"])
        if not n:
            print("%-10s only in A" % m["name"])
            continue
        ra = da[m["offset"]:m["offset"] + m["size"]]
        rb = db[n["offset"]:n["offset"] + n["size"]]
        pa, pb = ra[MODULE_HEAD:], rb[MODULE_HEAD:]
        same_size = m["size"] == n["size"]
        if not same_size:
            pay = "size differs"
        elif pa == pb:
            pay = "identical"
        else:
            k = min(len(pa), a.sample)
            eq = sum(1 for x, y in zip(pa[:k], pb[:k]) if x == y) / max(k, 1)
            pay = "differs (equal-byte ratio %.4f on first %d bytes; random = 0.0039)" % (eq, k)
            if m["digest"] == n["digest"] and m["flags"] == 3:
                pay += "  <- same digest, new ciphertext"
        print(cols % (m["name"], m["flags"], same_size, m["digest"] == n["digest"],
                      m["param"] == n["param"], ra[:MODULE_HEAD] == rb[:MODULE_HEAD], pay))
    return 0


def cmd_extract(a):
    data, hdr, mods = load(a.file)
    os.makedirs(a.outdir, exist_ok=True)
    manifest = {"header": hdr, "modules": mods}
    for m in mods:
        if m["size"] == 0:
            continue
        path = os.path.join(a.outdir, "%02d_%s.bin" % (m["index"], m["name"]))
        with open(path, "wb") as f:
            f.write(data[m["offset"]:m["offset"] + m["size"]])
    with open(os.path.join(a.outdir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print("wrote %d module files + manifest.json to %s" % (sum(1 for m in mods if m["size"]), a.outdir))
    print("Modules with flags=3 are still ENCRYPTED; do not publish them (copyrighted firmware).")
    return 0


def rom_txt_to_bin(path):
    """Service-mode 'ROM BACKUP' text dump: lines 'Hxxx b0,b1,...' (hex bytes)."""
    out = bytearray()
    with open(path, errors="replace") as f:
        for line in f:
            m = re.match(r"H([0-9A-Fa-f]{3}) (.*)", line)
            if m:
                for w in m.group(2).strip().split(","):
                    w = w.strip()
                    if w:
                        out += bytes.fromhex(w)
    return bytes(out)


def cmd_rom(a):
    b = rom_txt_to_bin(a.file)
    with open(a.out, "wb") as f:
        f.write(b)
    print("%s -> %s (%d bytes)" % (a.file, a.out, len(b)))
    print("WARNING: <Model>F dumps contain the camera serial number; <Model>U dumps may contain user/Wi-Fi settings. Do not publish them.")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("info"); s.add_argument("file"); s.add_argument("--json", action="store_true")
    s.add_argument("--check-hash", action="store_true", help="verify the stored digest where the rule is known (see README)")
    s.set_defaults(fn=cmd_info)
    s = sp.add_parser("compare"); s.add_argument("a"); s.add_argument("b")
    s.add_argument("--sample", type=int, default=1 << 20, help="bytes per module for the equal-byte ratio")
    s.set_defaults(fn=cmd_compare)
    s = sp.add_parser("extract"); s.add_argument("file"); s.add_argument("outdir"); s.set_defaults(fn=cmd_extract)
    s = sp.add_parser("romtxt2bin"); s.add_argument("file"); s.add_argument("out"); s.set_defaults(fn=cmd_rom)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (ValueError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
