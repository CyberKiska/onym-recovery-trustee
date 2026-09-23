# Fixtures

Public test data only. No real secret appears here.

| Path | What it is | Source and licence |
|---|---|---|
| `slip39/vectors.json` | The 45 official SLIP-0039 test cases | [trezor/python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic) `17fcce1` (release 0.3.0 plus a version bump), MIT, © 2019 SatoshiLabs. SHA-256 `13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4` |
| `slip39/official-decoded.json` | Every official mnemonic with the reference implementation's own decoding, or the class of its error | `python3 tools/client.py share-fixtures` |
| `slip39/onym-generated.json` | Profile shares (2-of-3, 3-of-5, 2-of-16, 16-of-16; not extendable, exponent 0) and the random test master secrets they split | same command, `shamir-mnemonic==0.3.0` |
| `hpke/cfrg-base-x25519-sha256-aes256gcm.json` | The Base-mode entry for KEM 0x0020, KDF 0x0001, AEAD 0x0002, with `exports` removed | [cfrg/draft-irtf-cfrg-hpke](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json) `5f503c5`, the vector file of the final RFC 9180; full-file SHA-256 `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` |
| `canonical/*` | Canonical-JSON inputs and expected bytes, and the duplicate-key refusal case | [onymchat/onym-discovery](https://github.com/onymchat/onym-discovery/tree/db08076e84d5daf0d6d9b484b63ca0dda1a59e30/tests/fixtures) `db08076`, MIT, © 2026 onymchat |
| `binding/*` | Share envelope, protected artifact, enrollment context with sealed envelope, per-trustee session, signed contribution, and the expected digests and `info` strings (`vectors.json`) | `REGEN_FIXTURES=1 cargo test --test conformance` |

Notes:

- **Official cases.** Case 29 is labelled 256-bit but carries 20-word mnemonics. None of the 45 cases fits the Onym profile, so the accept path is tested with the generated shares only.
- **Binding vectors.**
  - They use fixed test seeds (see `vectors.json`) and member 1 of the generated 2-of-3 set.
  - The artifact ciphertext is synthetic: a trustee never decrypts it.
  - Sealed values carry fresh HPKE randomness, so they change on every regeneration. Tests open them instead of byte-comparing.
- **Word list.** `src/wordlist.txt` is Trezor's MIT copy of the SLIP-0039 word list (SHA-256 `bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3`). It is byte-identical to the list in the SLIP-0039 specification, whose repository is licensed CC BY-SA 4.0.
