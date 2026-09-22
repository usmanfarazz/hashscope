#!/usr/bin/env python3
"""hashscope - identify likely hash types from a string.

Usage:
    python hashscope.py <hash> [<hash> ...]
    echo <hash> | python hashscope.py
"""
import re
import sys

# (name, regex, hashcat mode or None)
SIGNATURES = [
    ("bcrypt", r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", 3200),
    ("sha512crypt", r"^\$6\$[^$]{1,16}\$[./A-Za-z0-9]{86}$", 1800),
    ("sha256crypt", r"^\$5\$[^$]{1,16}\$[./A-Za-z0-9]{43}$", 7400),
    ("md5crypt", r"^\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$", 500),
    ("Argon2", r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$", None),
    ("yescrypt", r"^\$y\$[./A-Za-z0-9]+\$", None),
    ("MySQL 4.1+", r"^\*[A-F0-9]{40}$", 300),
    ("MD5", r"^[a-f0-9]{32}$", 0),
    ("NTLM", r"^[a-f0-9]{32}$", 1000),
    ("MD4", r"^[a-f0-9]{32}$", 900),
    ("SHA-1", r"^[a-f0-9]{40}$", 100),
    ("RIPEMD-160", r"^[a-f0-9]{40}$", 6000),
    ("SHA-224", r"^[a-f0-9]{56}$", 1300),
    ("SHA-256", r"^[a-f0-9]{64}$", 1400),
    ("SHA3-256", r"^[a-f0-9]{64}$", 17400),
    ("SHA-384", r"^[a-f0-9]{96}$", 10800),
    ("SHA-512", r"^[a-f0-9]{128}$", 1700),
    ("SHA3-512", r"^[a-f0-9]{128}$", 17600),
    ("CRC32", r"^[a-f0-9]{8}$", 11500),
]
_COMPILED = [(n, re.compile(p, re.IGNORECASE), m) for n, p, m in SIGNATURES]


def identify(value):
    """Return a list of (name, hashcat_mode) candidates for a hash string."""
    value = value.strip()
    return [(name, mode) for name, rx, mode in _COMPILED if rx.match(value)]


def main(argv):
    hashes = argv[1:] or [line for line in sys.stdin.read().split() if line]
    if not hashes:
        print(__doc__.strip())
        return 1
    for h in hashes:
        print(h)
        matches = identify(h)
        if not matches:
            print("  [-] unknown format")
        for name, mode in matches:
            suffix = f"  (hashcat -m {mode})" if mode is not None else ""
            print(f"  [+] {name}{suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
