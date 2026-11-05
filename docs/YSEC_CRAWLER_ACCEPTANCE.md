# YSec Crawler Interoperability Acceptance — 2026-10-25

## Evidence and provenance
- Baseline: production-confirmed 2.84.12 (historical coordinate normalized 2.85.2). Dev source also includes the previously declined 2.84.13 change to malware forensic export (normalized 2.85.3).
- Official provider sources (IP ranges fetched by WP-Cron, never bundled as permanent allowlists): https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests ; https://developers.openai.com/api/docs/bots ; https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler ; https://docs.perplexity.ai/docs/resources/perplexity-crawlers
- Provider claims are not actual verified identities. Evidence only; no WAF bypass. No DNS or network on visitor path.

## Status
- Implemented: SEC-01 provider profiles; SEC-02 official CIDR with fail-closed freshness; SEC-03 trusted proxy chain and CF-origin ingress trust; SEC-04 existing abuse risk remains independent; SEC-06 namespaced no-PII versioned request-contract output.
- Partial: SEC-02 DNS fallback for providers without usable fresh official CIDR evidence, cryptographic Web Bot Auth; SEC-05 existing forensics detail reused, no new summary dashboard or translated source strings added; SEC-04 expensive faceted GET is observed but not automatically blocked. This is deliberate to protect customers and indexing until performance benchmark/risk gating.
- Not verifiable from PHP alone: blocked upstream CDN/WAF, real external edge reachability, incident cause of 2026-10-22 near 09:45 UTC.
- Regression: original eight runnable 2.84.10 mock suites passed; obsolete pre-2.85.3 redirect-expectation mock not applicable; new CIDR/proxy/negative/spoofing/hotpath tests passed; PHP syntax and JS syntax passed.
- Pending on production: official WordPress Plugin Check for 2.86.0, live WooCommerce payment flow, verified source IP with actual external edge and measured throughput.

## Version coordinate provenance
Provisional historical internal labels: 2.84.10=>2.85.0; 2.84.11=>2.85.1; 2.84.12=>2.85.2; 2.84.13=>2.85.3. This feature batch is 2.86.0.

## Gate
Do not claim final production acceptance until production Plugin Check and WooCommerce flow pass. Never bundle handoffs or read-only incident diagnostics in the installable ZIP.
