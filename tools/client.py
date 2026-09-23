#!/usr/bin/env python3
"""Holder and candidate client for the Onym recovery trustee (binding draft-1).

So far it has one command, `share-fixtures`, which writes the SLIP-0039
fixtures the Rust tests read. Shares are generated and decoded by the
reference implementation (Trezor's python-shamir-mnemonic), so the trustee's
parser is checked against code it shares nothing with.
"""

import argparse
import json
import os
from pathlib import Path

from shamir_mnemonic import generate_mnemonics
from shamir_mnemonic.share import Share
from shamir_mnemonic.utils import MnemonicError

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "slip39"

# The Onym Shamir profile: one group, 256-bit secret, no extendable flag,
# exponent zero, empty passphrase. The library defaults differ
# (extendable=True, iteration_exponent=1), so every argument is explicit.
PROFILE_SETS = [(2, 3), (3, 5), (2, 16), (16, 16)]

# Reference error messages, by the class the fixture records.
ERRORS = {
    "Invalid mnemonic checksum": "checksum",
    "Invalid mnemonic padding": "padding",
    "Invalid mnemonic length": "length",
    "Group threshold cannot be greater than group count": "group-threshold",
    "Invalid mnemonic word": "word",
}


def decoded(mnemonic):
    """The reference decoding of one share, or the class of its error."""
    try:
        share = Share.from_mnemonic(mnemonic)
    except MnemonicError as error:
        return {"error": next(kind for text, kind in ERRORS.items() if text in str(error))}
    return {
        "identifier": share.identifier,
        "extendable": share.extendable,
        "iterationExponent": share.iteration_exponent,
        "groupIndex": share.group_index,
        "groupThreshold": share.group_threshold,
        "groupCount": share.group_count,
        "memberIndex": share.index,
        "memberThreshold": share.member_threshold,
        "valueBytes": len(share.value),
    }


def share_fixtures(_args):
    vectors = json.loads((FIXTURES / "vectors.json").read_text())
    official = [
        {"case": number, "description": description, "mnemonic": mnemonic, "reference": decoded(mnemonic)}
        for number, (description, mnemonics, _secret, _xprv) in enumerate(vectors, 1)
        for mnemonic in mnemonics
    ]
    generated = []
    for threshold, count in PROFILE_SETS:
        secret = os.urandom(32)
        [shares] = generate_mnemonics(
            1, [(threshold, count)], secret, b"", extendable=False, iteration_exponent=0
        )
        generated.append(
            {"memberThreshold": threshold, "memberCount": count, "masterSecret": secret.hex(), "shares": shares}
        )
    write("official-decoded.json", official)
    write("onym-generated.json", generated)


def write(name, cases):
    document = {"generator": "shamir-mnemonic 0.3.0 via tools/client.py share-fixtures", "cases": cases}
    (FIXTURES / name).write_text(json.dumps(document, indent=1) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(required=True)
    commands.add_parser(
        "share-fixtures", help="regenerate tests/fixtures/slip39 from the reference implementation"
    ).set_defaults(run=share_fixtures)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
