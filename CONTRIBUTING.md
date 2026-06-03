# Contributing to kitphishr

Thanks for your interest in improving kitphishr. This project is
maintained by Colin Hardy ([@cybercdh](https://github.com/cybercdh))
with help from the security community. Patches, bug reports, and feature ideas are
all welcome.

## How to contribute

- **Bugs and feature requests:** open a GitHub issue with as much
  detail as you can -- the URL list you ran against (sanitised),
  command-line flags, expected vs. actual behaviour, kitphishr version
  and Go version.
- **Patches:** open a pull request against `master`. Keep changes
  focused -- one PR per logical change is much easier to review than
  a grab-bag PR.
- **Detection improvements:** new feed sources, kit fingerprints,
  mail-drop extractors, or open-directory heuristics are particularly
  welcome. If you have a sample (sanitised) URL or kit that exercises
  your change, include a reference in the PR description.

## Coding style

- Standard Go formatting (`gofmt`). PRs should pass `go vet` clean.
- Match the surrounding style. kitphishr is intentionally a small,
  readable codebase -- avoid pulling in heavy frameworks or
  abstractions unless they pay for themselves.
- No emojis or decorative output in the tool itself; output should be
  greppable and pipeable.

## Inbound license terms

This is the important part. Please read it carefully.

kitphishr is dual-licensed. The open-source license is GPLv2 with
project-specific clarifications; commercial licenses are sold
separately to fund ongoing development. See [LICENSE](./LICENSE) and
[LICENSING.md](./LICENSING.md) for details.

For this dual-licensing model to work, the project needs the right to
relicense contributed code. **By submitting a patch, pull request, or
other contribution to kitphishr in any form (via email, GitHub PR, or
any other channel), you agree that, unless you explicitly state
otherwise in your submission:**

1. You are the original author of your contribution, or you have the
   right to submit it under these terms.
2. You grant the kitphishr project an unlimited, non-exclusive,
   perpetual, irrevocable, worldwide right to reuse, modify,
   sublicense, and relicense your contribution, including under both
   the open-source license and any commercial license offered by the
   project.
3. Your contribution is provided on an "as is" basis, with no
   warranties of any kind.

If you do **not** want your contribution available under these terms,
please say so clearly in your pull request description or commit
message. The project may then decide not to merge the contribution,
or to negotiate alternative terms with you.

This inbound grant is intentionally lightweight -- there is no
separate CLA to sign, no corporate paperwork, just the act of
submitting your patch. If your employer requires a more formal
agreement (e.g. you are contributing on company time and your
employer's policy requires a signed CLA), please reach out to
**cybercdh@gmail.com** before submitting and we will work something
out.

## Security disclosures

If you find a security issue **in kitphishr itself** (not in a
phishing kit it has downloaded), please email
**cybercdh@gmail.com** rather than opening a public issue.

For vulnerabilities discovered **in phishing kits via kitphishr**:
that is the tool working as intended. Share responsibly with the
affected brand owners and your local CERT / abuse contacts as
appropriate.

## A note on what you collect

Running kitphishr will cause you to download files from URLs you
supply. Those files may be malicious, may include victim data
exfiltrated by attackers, and may be subject to laws in your
jurisdiction around possession and handling of malware or personal
data. Operate responsibly, keep downloads in an isolated environment,
and dispose of victim data appropriately. The kitphishr project is
not responsible for how you handle what you collect.
