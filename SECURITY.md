# Security policy

Kryptos is experimental consensus and wallet software. There is no supported
production release or guarantee of compatibility between development revisions.
Use the exact revision agreed by your test-network operators. Passing CI is not
an independent security audit.

## Reporting a vulnerability

For this repository, use GitHub's private vulnerability report form:

<https://github.com/zkmagnus/Kryptos/security/advisories/new>

The form works only after repository maintainers enable **Private vulnerability
reporting** in GitHub's security settings. That hosting setting is separate from
this file. If the form is unavailable, contact a maintainer through a private
contact method published on their GitHub profile. If none is published, open an
issue asking only for a private security contact; do not include the finding,
exploit, affected accounts, or sensitive logs in that issue. No dedicated
security email or response-time commitment has been established yet.

Include the affected commit and platform, the expected and observed behavior,
a minimal reproduction using generated test keys, the estimated impact, and
any suggested fix. Report consensus disagreements, unauthorized spending,
inflation, privacy leaks, wallet/key exposure, and remotely induced resource
exhaustion through this private process. Never submit real seed phrases,
spending keys, viewing keys, wallet files, RPC tokens, or private witnesses.

Maintainers should reproduce the issue privately, assess affected versions and
network rules, arrange independent review, and coordinate a fix and disclosure
with the reporter. Consensus changes also need an explicit activation plan;
do not deploy incompatible rules under an existing revision.

## Current security boundaries

- ML-KEM establishes keys for coin-payload encryption. The proof system and
  spending authorization are not fully post-quantum.
- New addresses derive separate ML-KEM keys. Legacy addresses still share a
  linkable key, and using the same address again still reveals address reuse.
  See [the address derivation and recovery design](docs/diversified-ml-kem-addresses.md).
  Scanning cost grows with the number of address keys times the number of
  outputs; the wallet applies a local bound and needs an explicit recovery range.
- Wallet files and JSON backups currently contain plaintext secrets. Unix
  owner-only permissions reduce exposure but do not encrypt copies of files.
- RPC tokens grant privileged access. Keep node and wallet RPC on loopback or
  inside an authenticated encrypted tunnel. The HTTP servers do not provide
  TLS themselves; token authentication does not encrypt network traffic.
- Network transport encryption and transaction relay do not guarantee anonymity
  against all traffic analysis. Review the documented scan-timing limitations
  in [the audit-fix notes](docs/crypto-audit-fixes.md).

See [operations and release readiness](docs/operations.md) for deployment
boundaries, current verification blockers, and review requirements.
