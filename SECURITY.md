# Security

This is an unaudited reference implementation of a draft binding. Use it
with synthetic test secrets only.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting: the
repository's **Security** tab, **Report a vulnerability**. Please do not
open a public issue. Name the commit, and reproduce with test keys: never
send real shares, recovery keys or artifacts.

Useful reports include anything that lets a trustee release a share
outside the enrolled policy, lets anyone but the holder create, read or end
an enrollment, leaks a share, key, factor or private identifier through a
response, receipt or log, or lets one trustee stop a recovery that the
others can complete.

## Known limits

These are documented, not vulnerabilities in themselves (see the README's
[Limits](README.md#limits) and [`deploy/README.md`](deploy/README.md)):

- local state is trusted: a trustee restored from an old snapshot, or
  started with its clock set forward, is not detected;
- notices reach the holder only while an enrolled device polls;
- deletion is logical: snapshots and backups keep what they held;
- the service bounds how many requests reach its store at once, not how
  many each client sends;
- one factor profile, an independently held Ed25519 key.
