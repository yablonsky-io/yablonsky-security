=== Yablonsky Security ===
Contributors: yablonsky
Tags: security, firewall, malware, integrity, 2fa
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.88.6
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security, integrity, reconnaissance intelligence, login protection, auditing, and guarded response for WordPress.

== Description ==

Yablonsky Security provides a local-first, server-agnostic WordPress security control plane for observation, prevention, containment, verification and recovery. Core protection runs independently across supported web-server stacks, with optional server fast paths and optional AI assistance.

Core local protection is free. Optional external services are activated only by an administrator and are described below.

Features include:

* Configurable web application firewall (WAF), guarded response, reconnaissance monitoring, and incident reports.
* WordPress and WooCommerce login security: attempt limits, CAPTCHA, optional 2FA, session controls and account protection.
* Local malware scanning, file integrity baselines, encrypted quarantine and original-file recovery.
* Security headers, administrator-controlled hardening, policy rollback and guided Security Autopilot.
* Private WordPress login URL in Test/Enforce modes with documented emergency recovery.
* Local event evidence and optional, administrator-invoked Yablonsky AI analysis.
* Independent local protection with no required paid security service.

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


== System requirements ==

* WordPress 6.4+, PHP 7.4+; see this release for validated environments.
* Local malware scanning uses bounded, resumable batches; optional ClamAV needs a locally configured clamd socket.
* Quarantine and recovery are administrator-controlled and require sufficient available disk space.

== Frequently Asked Questions ==

= Does it require Apache or .htaccess? =

The core security engine is server-agnostic. Generated Nginx and Apache/LiteSpeed fast-path snippets provide an optional earlier enforcement layer.

= Is AI required? =

Core protection runs locally. AI adds optional administrator-invoked analysis and text-only remediation guidance; it cannot generate or apply executable repair files inside the plugin.

= Does Safe security headers enable CSP or HSTS? =

No. Safe security headers remains the compatibility-safe baseline preset for X-Content-Type-Options, Referrer-Policy, X-Frame-Options and a restrictive Permissions-Policy for geolocation, microphone and camera. CSP and HSTS are configured separately in Hardening > Security Headers so site-specific policy cannot be enabled accidentally.

= How are custom CSP sources handled? =

Known-service presets are optional. Administrators review observed origins and explicitly allow or block them; unknown sources are not auto-approved.

= Does CSP discovery send browsing data to an external service? =

No. The CSP report endpoint is a local WordPress REST route. YSec stores a bounded set of normalized directive/origin pairs and does not retain full blocked URLs, query strings, request bodies or cookies in CSP discovery evidence.

= Does Yablonsky Security control robots.txt or AI crawler permissions? =

When Yablonsky SEO is active, YSEO owns search/AI discovery policy while Yablonsky Security owns request safety. Crawler treatment follows request behavior and verified context, preserving public discovery while security enforcement remains authoritative.

= Does a suspicious 404 mean the site was compromised? =

A suspicious 404 records request evidence. Compromise assessment requires independent evidence about file existence, execution or impact.

= Are quarantine actions automatic? =

Quarantine begins with an explicit administrator action. Yablonsky Security encrypts the selected file, verifies the encrypted copy, then removes the original. Restore verifies SHA-256 before writing the file back and preserves an existing target for administrator review.

== Changelog ==

= 2.88.6 =
* Corrects local CAPTCHA asset loading on WordPress and WooCommerce forms.
* Aligns plugin homepage and GPL license packaging with WordPress.org guidance.
* Preserves existing firewall, login, security policy, data, and administrator settings.

= 2.88.5 =
* Improves request-input handling for the Firewall Proof workflow.

For earlier releases, see CHANGELOG.md in the GitHub repository.
