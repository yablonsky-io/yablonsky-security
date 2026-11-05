=== Yablonsky Security ===
Contributors: yablonsky
Tags: security, firewall, malware, integrity, 2fa
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.88.5
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security, integrity, reconnaissance intelligence, login protection, auditing, and guarded response for WordPress.

== Description ==

Yablonsky Security provides a local-first, server-agnostic WordPress security control plane for observation, prevention, containment, verification and recovery. Core protection runs independently across supported web-server stacks, with optional server fast paths and optional AI assistance.

Core local protection is free. Optional external services are activated only by an administrator and are described below.

Features include:

* Guarded Autopilot: analyze, snapshot, apply, verify, prove, commit or automatically roll back.
* Application firewall with clean-room Minimal / 5G-class / 6G-class / 7G-class / 8G-class profiles.
* Context-aware adaptive response: harmful requests are denied first, mixed-behavior sources can retain safe read-only public discovery, and broader source containment is temporary, explainable and reversible.
* Yablonsky SEO interoperability boundary: SEO/search/AI crawler permissions stay in YSEO while YSec treats crawler User-Agent names as unverified claims unless a verifier explicitly enriches the evidence.
* Adaptive reconnaissance containment, durable allow/permanent-block policy, deny-only conditional firewall rules (method/path/auth/source scope), custom path denies and explicit full-source administrator blocks.
* Events, reconnaissance campaigns, contextual threat analytics, encrypted local source evidence, bounded hot-evidence retention with daily rollups, and explicit Yablonsky AI contextual review from Events / Reconnaissance / Firewall.
* WordPress and WooCommerce brute-force protection, CAPTCHA, login honeypot, optional trusted-network login policy, TOTP 2FA, recovery codes, session inventory/revocation and administrator-controlled registration approval.
* File integrity baselines, filesystem permission audit/repair and permission drift monitoring.
* Resumable complete wp-content malware scanning, real-time file-ingress screening, optional local ClamAV/clamd signatures, plus explicit encrypted quarantine, SHA-256 verification, restore and permanent quarantine deletion.
* WordPress hardening for XML-RPC/pingbacks, Application Passwords, built-in file editor, security headers and time-bounded emergency visitor lockdown.
* Portable security-policy JSON with validate → preview → apply flow and one-step rollback, while site secrets stay local.
* Version-aware local advisory intelligence with provenance, bounded virtual patches, software exposure inventory, compatibility/coexistence reporting, passive Security Doctor diagnostics, multisite policy-divergence diagnostics, REST status and WP-CLI foundation.
* Encrypted local YSec policy recovery checkpoints plus optional Yablonsky AI evidence analysis with explicit scope and human review.
* Anonymous-comment abuse protection with a local honeypot, optional bounded source-rate enforcement and 24-hour Hardening telemetry.
* Optional trusted-country deny policy based only on authoritative Cloudflare country evidence, with recovery surfaces preserved.
* Optional reviewed Nginx / Apache-LiteSpeed first-hit rules for secret/config probes, VCS metadata, database dumps and diagnostic artifacts.
* Read-only WP-CLI incident diagnostics, human-approved competitor mapping with one-step YSec rollback, post-cutover proof receipts, and a privacy-bounded administrator posture-report export.
* Private administration entry with private login/admin aliases, guarded default wp-login.php/wp-admin discovery reduction, recovery-token compatibility, Hide My WP Ghost standby handoff and emergency WP-CLI/wp-config recovery.
* Firewall Proof canary verifies the selected 5G–8G-class profile with both deterministic rule-engine evidence and an attributable same-site live HTTP loopback marker.

= Official crawler identity sources =

When explicitly enabled by an administrator, Yablonsky Security fetches public crawler IP range JSON files from Google's crawler infrastructure, Microsoft Bing, Apple, OpenAI, Anthropic and Perplexity through the standard WordPress HTTP API. Requests occur only during scheduled WordPress housekeeping, not during visitor requests. The provider may receive the website server's public IP, the plugin User-Agent and normal HTTPS request metadata; visitor IP addresses, page requests and security logs are never sent to these sources. Fetches are limited in size, time and frequency, and do not follow redirects. Cached ranges expire after 48 hours; expired or unavailable proof never grants trusted-bot status.

Official feeds and documentation:
* Google: https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests
* Microsoft Bing: https://www.bing.com/webmasters/help/verify-bingbot-2195837f
* Applebot: https://support.apple.com/en-us/119829
* OpenAI: https://developers.openai.com/api/docs/bots
* Anthropic: https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
* Perplexity: https://docs.perplexity.ai/docs/resources/perplexity-crawlers

Bot identification is evidence only. It is not permission to access private pages, bypass the firewall, or override search and discovery policy. Applebot and Bingbot have independently published official crawler IP feeds. Unavailable or expired lists are never treated as proof. Cryptographic signed-agent identification is not claimed without verification.

= External service: Cloudflare Turnstile =

Cloudflare Turnstile is an optional administrator-enabled verification layer. When selected and configured with site/secret keys, the browser loads Cloudflare's challenge runtime and the submitted challenge token, plus the client IP when available, is sent to Cloudflare's verification endpoint. Local firewall, integrity, malware, response and evidence features continue to run locally.

Service: https://www.cloudflare.com/products/turnstile/
Terms: https://www.cloudflare.com/website-terms/
Privacy: https://www.cloudflare.com/privacypolicy/

= External service: Google reCAPTCHA =

Google reCAPTCHA is an optional administrator-enabled verification layer. When selected and configured with site/secret keys, the browser loads Google's challenge runtime and the submitted challenge token, plus the client IP when available, is sent to Google's verification endpoint. Local protection continues to run locally.

Service: https://www.google.com/recaptcha/
Terms: https://policies.google.com/terms
Privacy: https://policies.google.com/privacy

= Optional crawler IP registry updates =

Disabled by default. Administrators can explicitly enable official provider IP registry updates in Settings > Network. Scheduled maintenance then contacts Google, Microsoft Bing, Apple, OpenAI, Anthropic and Perplexity to retrieve public crawler network ranges. YSec sends no visitor identifiers in these requests, never fetches from those hosts during normal visitor requests, and stops using stored ranges for verification immediately when consent is revoked. This is separate from Yablonsky AI account integration and does not change firewall rules.

= External service: Yablonsky AI =

Yablonsky AI is an optional administrator-invoked security-analysis and advisory remediation layer. Activation, page rendering, firewall decisions, login protection, scanning, event logging and automatic blocking stay local. Explicit Refresh account/model-canary actions may send the stored User API key to https://ai.yablonsky.io/ to read the connected account, authorized workspaces, account-scoped model capability projection and credit context. When an administrator requests substantive security analysis, Yablonsky Security sends a bounded security bundle to the same service. Contextual analysis launched from Events, Reconnaissance or Firewall is restricted to the selected security surface and removes source identity fields before transmission. Source fingerprints are removed from security-analysis data and secret-like fields are redacted before transmission. When an administrator explicitly requests malware remediation advice, YSec sends at most three bounded confirmed-finding metadata records (relative path, rule, classification and size); source-file contents are not transmitted. AI returns text-only advice (local quarantine, the official WordPress update/reinstall workflow, or manual investigation). YSec never downloads, stages, writes or runs AI-generated executable code, patches or replacement files. Forensic ZIP export, the local scanner, encrypted quarantine and restoration of the site's original quarantined copies remain available without AI.

Service information: https://yablonsky.io/
Privacy information: https://ai.yablonsky.io/policies/privacy
Terms: https://ai.yablonsky.io/policies/terms

The local protection engine executes bundled local code and keeps runtime authority inside the installed plugin package.

== Installation ==

1. Upload the plugin ZIP through Plugins > Add New > Upload Plugin.
2. Activate Yablonsky Security.
3. Open Yablonsky Security from the WordPress Plugins screen or admin menu.
4. Use Autopilot / Optimize Now for a guarded recommended configuration, or review Custom controls manually.
5. Configure trusted reverse proxies if the site is behind a non-Cloudflare proxy/CDN.
6. Create an integrity baseline after confirming the current filesystem is trusted.


== System requirements and scanner resource model ==

* WordPress 6.4 or newer.
* PHP 7.4 or newer.
* No external malware service is required: built-in deterministic heuristics run locally.
* Optional ClamAV integration requires a local clamd daemon reachable from PHP through a Unix-domain socket. YSec prefers clamd direct-path SCAN and automatically falls back to local INSTREAM transfer when virtual-host directory permissions prevent the daemon user from reading a site path directly.
* The resumable wp-content scanner processes bounded batches (250 filesystem entries per step) and persists progress between requests instead of holding the complete tree in memory.
* PHP heuristic inspection reads only supported executable/text files up to 2 MiB per file. ClamAV INSTREAM fallback transfers 16 KiB chunks and defaults to files up to 24 MiB unless `YSEC_CLAMD_STREAM_MAX_BYTES` is explicitly adjusted for the host's clamd configuration.
* Quarantine is administrator-triggered. Keep enough free disk space for the encrypted quarantine copy and normal site operations before quarantining large files.
* Large wp-content trees take proportionally longer to traverse. The scanner is designed to trade peak load for bounded, resumable progress rather than maximum scan speed.

== Frequently Asked Questions ==

= Does it require Apache or .htaccess? =

The core security engine is server-agnostic. Generated Nginx and Apache/LiteSpeed fast-path snippets provide an optional earlier enforcement layer.

= Is AI required? =

Core protection runs locally. AI adds optional administrator-invoked analysis and text-only remediation guidance; it cannot generate or apply executable repair files inside the plugin.

= Does Safe security headers enable CSP or HSTS? =

No. Safe security headers remains the compatibility-safe baseline preset for X-Content-Type-Options, Referrer-Policy, X-Frame-Options and a restrictive Permissions-Policy for geolocation, microphone and camera. CSP and HSTS are configured separately in Hardening > Security Headers so site-specific policy cannot be enabled accidentally.

= How does CSP discovery handle custom or self-hosted services? =

YSec does not require a service to exist in a built-in catalog. Known-service presets are convenience templates only. Runtime discovery and CSP Report-Only evidence normalize external origins by directive, and administrators can explicitly allow, block or ignore observations or add exact custom/self-hosted origins in the guided builder. Unknown origins are never auto-authorized merely because they were observed. An advanced raw CSP editor remains available for experienced administrators.

= Does CSP discovery send browsing data to an external service? =

No. The CSP report endpoint is a local WordPress REST route. YSec stores a bounded set of normalized directive/origin pairs and does not retain full blocked URLs, query strings, request bodies or cookies in CSP discovery evidence.

= Does Yablonsky Security control robots.txt or AI crawler permissions? =

When Yablonsky SEO is active, YSEO owns search/AI discovery policy while Yablonsky Security owns request safety. Crawler treatment follows request behavior and verified context, preserving public discovery while security enforcement remains authoritative.

= Does a suspicious 404 mean the site was compromised? =

A suspicious 404 records request evidence. Compromise assessment requires independent evidence about file existence, execution or impact.

= Are quarantine actions automatic? =

Quarantine begins with an explicit administrator action. Yablonsky Security encrypts the selected file, verifies the encrypted copy, then removes the original. Restore verifies SHA-256 before writing the file back and preserves an existing target for administrator review.

== Changelog ==

= 2.88.5 =
* Correct Firewall Proof to fail closed if the control HTTP request cannot complete.
* Require attributable, nonce-bound signed proof from the early MU runtime; reject spoofed headers, wrong rule family and responses caused by other enforcement layers.
* Preserve all protection policies, WordPress administrator-language translation catalogs, existing data/schema and malware workflows.

= 2.88.3 =
* Fix translation resolution for user-selected WordPress admin languages using bounded bundled MO lookup; no cross-plugin locale changes.
* Remove discouraged load_plugin_textdomain() call.

= 2.88.2 =
* Restore bundled admin translations in WPML/multi-plugin environments that intercept or reset text-domain loading, using a lazy fallback through the official WordPress MO parser and YSec-only gettext hooks.
* Keep the administrator's WordPress profile locale authoritative, without changing other plugins' translations or adding a YSec language selector.
* Preserve all 36 translated catalogs, firewall, malware and database contracts.

= 2.88.1 =
* Correct administrator-locale gettext loading for all bundled language catalogs. Register the standard WordPress text-domain path, explicitly load the user-selected profile locale, and replace stale/wrong-domain cached translations.
* Preserve native WordPress profile language selection. No plugin language selector is added. Security Doctor JSON includes read-only locale evidence.
* Preserve firewall, malware, database schema, admin layout and all 36 bundled translated locale catalogs.

= 2.88.0 =
* Adds complete Traditional Chinese (Taiwan) zh_TW gettext catalogs with Taiwanese security/UI terminology, independent from the existing Simplified Chinese zh_CN pack.
* Keeps the WordPress administrator profile as the sole UI-language selector; no new custom language chooser or ordering overrides.
* Audits and rebuilds all bundled translation catalogs; corrects two pre-existing pingback-label mistranslations. No security-enforcement, database, or API changes.


= 2.87.0 =
* Requires explicit administrator opt-in for scheduled official crawler IP lists. Disabling immediately revokes registry-based identity trust.
* Replaces external executable AI repair code with text-only malware remediation advice. Keeps local scanning, quarantine, forensic ZIP and trusted recovery methods.
* Scopes AI advice to the requesting administrator, fixes forensic guidance and refreshes all 35 translation catalogs.
* No automatic firewall bypass or change to the existing database schema.

= 2.86.0 =
* Adds scheduled and size-bounded official crawler IP verification for Google, Bing, Apple, OpenAI, Anthropic and Perplexity; unavailable proof never grants trusted status.
* Prevents claimed User-Agent, policy-only tokens or third-party hooks from asserting unproven crawler trust.
* Preserves application firewall enforcement and trusted proxy checks.
* Cryptographic Web Bot Auth verification and external CDN outcomes require separate evidence.


= 2.85.3 =
* Download forensic ZIP now packages a complete malware scan report (JSON, CSV, summary and manifest) even when zero malware review items exist; eligible evidence files remain optional.
* Clean scans no longer redirect on forensic export. No changes to scanning decisions, WordPress security enforcement or schema.

= 2.85.2 =
* Improves the three security monitor tables in one consolidated UI correction. Events now shows the full Path in Source / forensics rather than in a duplicated column; Firewall similarly presents Method and Path in forensics instead of a duplicated Request column.
* Widens the Events and Firewall forensic detail panels while retaining fixed, predictable column geometry and horizontal table scrolling on narrow screens.
* Clearly distinguishes Full block source containment from review, exact-request exceptions and evidence disposition, grouping secondary Firewall actions under Advanced. Preserves all existing response operations, filters, audit evidence and enforcement.
* Keeps Reconnaissance fields consistent with the other monitor surfaces and retains all 35 language catalogs without new untranslated labels.
* Versioning canon: YABLONSKY_PRODUCT_VERSIONING_CANON_v1.0.0_2026-09-21.md.

= 2.85.1 =
* Keeps Events, Reconnaissance and Firewall evidence-table column widths stable when source forensics are expanded, with horizontal scrolling when necessary.
* Uses the same Source / forensics heading on all three monitor surfaces. No changes to security enforcement, stored data, schema or localization catalog.
* Versioning canon: YABLONSKY_PRODUCT_VERSIONING_CANON_v1.0.0_2026-09-21.md.

= 2.85.0 =
* Repairs prioritized, time- and batch-bounded evidence ceiling cleanup; incomplete reduction is recorded explicitly rather than silently treated as ceiling compliance.
* Applies severity-based hot-evidence retention to L7 request signals in small batches; preserves configured days, firewall decisions and existing database schema.
* Prevents request-signal aggregation keys from crossing UTC day boundaries after a daily rollup has been finalized.
* Shows actual storage pressure above 100% and exact record count/limit in Events without adding untranslated UI labels.
* Preserves 35 language packs and 1,835 gettext source entries unchanged.

= 2.84.9 =
* Clarifies a translator placeholder comment at the gettext call site so WordPress i18n checks can recognize it.
* Documents eight pre-prepared, short-lived cached analytics SQL reads and two internally prepared retention-deletion helpers at their execution boundaries. No SQL execution flow or retention behavior changes.
* Shortens the WordPress.org readme changelog while preserving older release history in CHANGELOG.md.
* Preserves the 35 existing full localization packs, frozen 1,835-entry POT, DB schema, WAF enforcement and existing AI boundaries.

= 2.84.8 =
* Represents failed 24-hour and 7-day database reads as unavailable instead of zero, without caching failures.
* Propagates unavailable security analytics into Overview and posture rather than showing false reassuring counts.
* Retains all previous retention, storage-health, UI and forensic corrections.

= 2.84.7 =
* Correctly invalidates all related analytics caches after scheduled retention.
* Reports unavailable database totals explicitly instead of treating SQL failures as zero.

= 2.84.6 =
* Handles storage-health failures and interrupted retention with warnings and resumable safety.
* Prevents historical day-rollup starvation beyond 400 days.

= 2.84.3–2.84.5 =
* Improves the Overview SVG chart, five-per-page AI journal, empty forensic ZIP handling, maintenance checks and retention failure safety.

The complete version history is included in CHANGELOG.md.
