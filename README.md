# kitphishr

[![Test](https://github.com/cybercdh/kitphishr/actions/workflows/test.yml/badge.svg)](https://github.com/cybercdh/kitphishr/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-GPLv2%20%2B%20commercial-blue.svg)](./LICENSING.md)
[![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](https://go.dev/)

**Hunt phishing kits in the wild, and extract attacker intelligence from what you capture.**

kitphishr scans suspected phishing URLs for exposed kit archives — open directories, predictable filenames, redirect-handled paths — and produces structured intelligence about each kit it captures, including the attacker's mail drops, Telegram bot tokens, and Discord webhooks. It is built for blue teams, security researchers, and threat-intelligence providers who need to know where phishing campaigns are landing victim data.

## Highlights

- **Two subcommands.** `kitphishr` scans URLs for kits; `kitphishr analyze` extracts attacker indicators and classifies the impersonated brand from captured kits.
- **Built-in threat feeds.** Pulls fresh URLs from PhishTank, OpenPhish, PhishStats, and the Phishing.Database project — or accept a custom URL list on stdin.
- **Polite by default.** Per-host rate limiting, retry with exponential backoff, and graceful Ctrl-C handling.
- **Structured output.** JSONL records with SHA256-keyed deduplication and source-feed provenance, designed to stream into Elastic, Splunk, MISP, or any TI pipeline.
- **Configurable hunting.** Supply your own wordlists and extension sets to target specific kit naming conventions.

## Install

```bash
go install github.com/cybercdh/kitphishr@latest
```

Requires Go 1.25 or later.

## Quickstart

```bash
# Hunt for kits using built-in threat feeds, save what you find
kitphishr -d -o ./kits

# Hunt against your own URL list
cat urls.txt | kitphishr -d -v -o ./kits

# Extract attacker indicators from captured kits
ls kits/*.zip | kitphishr analyze -o intel.jsonl
```

## Output

Each saved kit appends a JSONL record to `kits/index.jsonl`:

```json
{"ts":"2026-06-03T12:00:00Z","url":"https://attacker.com/kit.zip","sha256":"a4b...","size":102400,"content_type":"application/zip","source":"openphish","saved_path":"kits/a4b....zip"}
```

`kitphishr analyze` produces records like:

```json
{"path":"kits/a4b....zip","sha256":"a4b...","size":102400,"files_scanned":17,"brands":[{"name":"Microsoft","hits":42}],"emails":["drop@attacker.ru","backup@attacker.ru"],"telegram_bots":["5234567890:AAE..."],"telegram_chat_ids":["987654321"],"discord_webhooks":["https://discord.com/api/webhooks/..."]}
```

Identical kits captured at different URLs are deduplicated by SHA256 — one file on disk, N entries in the index.

## Flags

### `kitphishr` (scan)

| Flag | Default | Description |
|---|---|---|
| `-c <int>` | `50` | concurrency level |
| `-d` | off | download suspected kits to disk |
| `-o <dir>` | `kits` | output directory |
| `-t <int>` | `45` | connection timeout in seconds |
| `-v` | off | verbose: log every URL attempt |
| `-u <string>` | (Chrome 131) | User-Agent header |
| `-rps <float>` | `2.0` | per-host requests per second |
| `-burst <int>` | `4` | per-host burst capacity |
| `-wordlist <path>` | (built-in) | archive-name wordlist; pass `/dev/null` to disable wordlist guessing |
| `-extensions <list>` | `zip` | archive extensions to guess (e.g. `zip,tar.gz,rar,7z`) |
| `-feeds` | off | always fetch URLs from the built-in threat-intel feeds (for scheduled / containerised runs with no stdin) |
| `-progress <dur>` | `30s` | interval between progress reports to stderr (`0` to disable) |
| `-timeout <dur>` | `0` (none) | max total scan duration; workers drain gracefully on deadline so partial captures survive |
| `-known-hashes <path>` | (none) | file of sha256s (one per line) to pre-seed the dedup index; matching captures get a dedup record but are not re-saved (cross-run capture dedup) |
| `-kit-json` | off | for each saved kit, also write `<sha>.kit.json` (capture metadata + analysis) for event-driven ingestion (requires `-d`) |
| `-scanned-urls <path>` | (none) | file of feed URLs (one per line) scanned within the dedup window; matching feed URLs are skipped (not re-explored/re-probed), and the URLs actually probed are written to `<output-dir>/scanned-urls.txt` (cross-run scan dedup) |

### `kitphishr analyze`

| Flag | Default | Description |
|---|---|---|
| `-o <path>` | `-` (stdout) | output destination |
| `-brands <path>` | (built-in) | JSON file of brand signatures (see `brands.go` for the default list and schema) |

Targets can be passed as arguments or piped via stdin.

## PhishTank configuration

PhishTank rate-limits anonymous feed access. If you have a [free API key](https://www.phishtank.com/api_register.php), export it and kitphishr will use it automatically:

```bash
export PT_API_KEY=<your_key>
```

## Demo

![](https://github.com/cybercdh/kitphishr/raw/assets/demo.gif)

## License

kitphishr is dual-licensed:

- **Open use** — security research, internal blue-team and SOC work, education, academic projects — is **free under GPLv2** with project-specific clarifications. See [LICENSE](./LICENSE).
- **Commercial integration** — embedding kitphishr into a product, threat-intelligence platform, SaaS offering, or appliance — requires a commercial license. Contact **cybercdh@gmail.com**.

A plain-English explainer with a quick-reference table for common use cases is in [LICENSING.md](./LICENSING.md).

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the lightweight inbound terms.

## Acknowledgements

Several Go idioms in this project come from [@tomnomnom](https://github.com/tomnomnom)'s [meg](https://github.com/tomnomnom/meg). The original idea was inspired by [Duo Labs' phish-collect](https://github.com/duo-labs/phish-collect) research.

## Maintainer

Colin Hardy ([@cybercdh](https://github.com/cybercdh)) — cybercdh@gmail.com
