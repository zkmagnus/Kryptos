# Contributing to Kryptos

Kryptos is experimental privacy-focused consensus software. Contributions
that change transaction validity, cryptographic relations, state effects, or
network compatibility need extra protocol review.

## Before opening a pull request

1. Check for an existing issue or design document describing the change.
2. For consensus or cryptography changes, write or update a proposal before
   changing implementation code. Include the motivation, exact rule changes,
   privacy impact, compatibility plan, and failure cases.
3. Keep pull requests focused. Separate formatting/refactors from behavior
   changes so protocol differences are easy to review.
4. Never include real spending keys, seeds, wallet databases, or private
   transaction witnesses in commits, examples, logs, or test vectors.

## Protocol change requirements

Any change that can alter whether nodes accept the same transaction or block
must document:

- the old and new consensus behavior;
- canonical encoding and version changes;
- public inputs, private witness, and public state effects;
- fee, state-tax, emission, and nullifier consequences;
- rejection behavior for malformed and boundary inputs;
- activation by network and height, including reorg behavior;
- test vectors and resource limits.

Transfers currently use native chain validation; there is no deployed
system-call dispatcher. Update the relevant protocol document under `docs/`
when changing these rules. Validation must check proofs and state effects
before applying canonical chain updates atomically.

Do not make two implementations valid at once without an explicit
height-based consensus rule. Do not change a program artifact or verifier
configuration under an existing program version.

## Review expectations

- Every pull request needs maintainer review before merge.
- Consensus, proof-system, cryptography, transaction-encoding, or state
  transition changes need two independent reviews before network activation;
  at least one reviewer should focus on protocol/consensus and one on the
  affected cryptographic or implementation area.
- A reviewer must not approve their own changes.
- If the project does not yet have enough qualified reviewers, keep the
  change in a draft pull request and do not activate it on a public network.
- Security-sensitive bugs should follow [`SECURITY.md`](SECURITY.md), not be
  disclosed first in a public issue.

## Tests and evidence

Run the checks relevant to the change and include the exact commands and
results in the pull request. At minimum, Rust changes should be formatted
and compile in the affected crate. Consensus and cryptography changes should
include regression tests for both accepted and rejected cases. ABI changes
must include canonical encoding, txid/sighash, and public-effect vectors.

The repository CI checks formatting, all-target compilation, workspace tests,
and dependency advisories. Use the pinned toolchain and commands in the
[operations guide](docs/operations.md). Existing failures must remain visible;
do not skip a failing test or broadly ignore advisories to make a change pass.

Do not claim an implementation is audited or secure because tests pass.
Record benchmark conditions when reporting proof-generation, verification,
memory, or transaction-size results.

## Pull request description

Include:

- what changed and why;
- affected crates, protocol documents, and network rules;
- how the change was tested;
- compatibility or activation requirements;
- privacy and resource implications;
- unresolved questions or assumptions.

## Contribution rights

By submitting a contribution, you confirm that you have the right to submit
it under the repository's GPL-3.0-or-later license. See [`LICENSE`](LICENSE).
