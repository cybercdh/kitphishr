# kitphishr Licensing

This document explains kitphishr's license in plain English. It is intended
for users, security teams, and corporate legal reviewers trying to decide
whether their intended use is permitted under the open-source license, or
whether they should reach out for a commercial license instead.

This document is a summary. The authoritative license text is in
[LICENSE](./LICENSE). Where this document and the LICENSE file conflict,
the LICENSE file wins.

## TL;DR

kitphishr is dual-licensed:

1. **GNU General Public License Version 2 (with kitphishr-specific
   clarifications)** for open, non-proprietary use.
2. **A commercial license** for use in proprietary products, embedded
   integrations, and other contexts where GPL obligations are
   incompatible with your goals.

If your use falls in the "free" column below, you can use kitphishr at
no cost under the GPL. If it falls in the "commercial" column, contact
**cybercdh@gmail.com** to discuss terms.

## Quick reference

| Use case                                                                  | Free under GPL? | Commercial license needed? |
| ------------------------------------------------------------------------- | --------------- | -------------------------- |
| Independent security research                                             | Yes             | No                         |
| Blue-team / SOC internal use at your own organisation                     | Yes             | No                         |
| Academic teaching and student projects                                    | Yes             | No                         |
| Personal use, CTFs, write-ups                                             | Yes             | No                         |
| Forking kitphishr and publishing a modified version under GPLv2           | Yes             | No                         |
| Bundling kitphishr (source or binary) inside a product you sell           | No              | Yes                        |
| Shipping kitphishr inside an installer, container image, or appliance     | No              | Yes                        |
| Calling kitphishr from a commercial product and parsing its output        | No              | Yes                        |
| Offering a hosted SaaS that runs kitphishr against customer-supplied URLs | No              | Yes                        |
| Embedding kitphishr in a commercial threat intelligence platform          | No              | Yes                        |

## Why the "executes and parses results" clause?

The kitphishr LICENSE explicitly says that executing kitphishr and
programmatically parsing its results is a derived work. This is broader
than how some readers interpret vanilla GPLv2, which is often assumed
to allow "mere aggregation" or shell-wrapper use.

The reason is straightforward: the most common commercial integration
pattern for a tool like kitphishr is exactly that -- a vendor calls
kitphishr as a subprocess, parses its output, and presents the results
inside their own commercial dashboard. We consider this to be embedding
kitphishr in a commercial product, and we want those integrations to
come through the commercial license path.

Casual human use from a shell -- e.g. running `kitphishr` at a
terminal, reading its output, copying URLs into a ticket -- is **not**
what this clause is about and is freely permitted under GPL.

## What the license does **not** cover

This is a source code license. It does not, and cannot, restrict:

- The kits or other data that kitphishr downloads as a result of you
  running it against URLs you supply. That data is yours, subject to
  any third-party laws that apply (e.g. malware-handling regulations,
  copyright in the kit contents, your local jurisdiction's rules on
  possession of malicious code).
- Code you write that happens to solve the same problem as kitphishr
  by independent means. The license restricts derivatives of
  kitphishr, not the problem space.
- Output of any future hosted kitphishr service. If such a service
  exists, its terms of use will be governed by a separate Terms of
  Service, not by this license.

## Contributing

By submitting a patch, pull request, or other contribution to
kitphishr, you agree (unless you state otherwise in your submission)
that the kitphishr project may reuse, modify, and relicense your
contribution without limitation. This is what enables the
dual-licensing model that keeps kitphishr sustainable.

If you do not wish for your contributions to be available under these
terms, please indicate so when you submit them. See
[CONTRIBUTING.md](./CONTRIBUTING.md) for more.

## Third-party dependencies

kitphishr depends on third-party Go modules listed in `go.mod`. Those
modules are licensed by their respective upstream authors under their
own terms (typically permissive licenses such as MIT, BSD, or Apache
2.0). The kitphishr license does not apply to those modules; you must
comply with their upstream licenses when using or redistributing
kitphishr.

## Commercial licensing

If any of the following applies to you, please reach out to
**cybercdh@gmail.com**:

- You want to embed kitphishr in a commercial product or service.
- You want to ship kitphishr as part of an appliance, installer, or
  container distribution.
- You want to run kitphishr behind a commercial API and resell access.
- You are unsure whether your use is permitted and want clarity in
  writing.
- Your legal team will not approve GPL-licensed software for your
  intended use case.

Commercial licensing is generally available on reasonable terms scaled
to the size and nature of your business and the depth of the
integration. We are happy to discuss.

## Disclaimer

This document is provided for explanatory purposes and does not
constitute legal advice. If you are uncertain about your obligations,
please consult a qualified attorney and/or contact us at
cybercdh@gmail.com.
