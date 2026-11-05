# Yablonsky Security

**Local-first security for WordPress — observation, prevention, response, verification, and recovery.**

Yablonsky Security is a self-contained WordPress security plugin. Core protection operates locally and does not require a remote AI provider. Optional external AI assistance and crawler-list downloads are administrator-controlled.

## Capabilities

- Application firewall with configurable rule profiles and guarded, reversible response.
- Reconnaissance and security-event observation, forensic evidence, and operational reporting.
- Login protection, rate limiting, CAPTCHA, TOTP-based two-factor authentication, and session tools.
- File integrity monitoring, malware scanning, local quarantine, and recovery controls.
- Hardening, security headers, account controls, and an administrator-invoked security Autopilot.
- Optional AI-assisted review without executing externally generated PHP code.
- Bundled interface translations for 36 locale variants. User-interface language follows the WordPress administrator profile.

## Requirements and tested environment

- Declared minimum: WordPress 6.4 and PHP 7.4.
- Verified deployments: WordPress 6.4.2, PHP 8.1.2, Nginx/PHP-FPM, including sites with WooCommerce and WPML.
- Production observations: both sites reported a green Plugin Check; prior Security Doctor reports showed 20/20 PASS.

Support claims for newer WordPress/PHP versions are subject to additional compatibility testing. The security and performance test program is ongoing; no comparative performance or penetration-testing certification is claimed here.

## Installation

Install the versioned WordPress plugin ZIP through **Plugins → Add New → Upload Plugin** and activate it. To browse the source, see the files in this repository. The release ZIP and repository source are different distribution surfaces: do not upload a GitHub source-upload batch as a WordPress plugin.

## Operation and trust boundaries

- WordPress users choose their own admin UI language in **Users → Profile → Language**. Yablonsky Security does not replace the WordPress language selector.
- Yablonsky SEO controls indexing and permitted content use; Yablonsky Security handles bot verification, spoofing, abuse, and enforcement; Yablonsky Performance handles caching and request efficiency. Each plugin works independently.
- Optional services require explicit administrator configuration and use conservative, auditable controls.
- False-positive prevention and administrative recovery remain priorities; protective rules should be tested against each site's integrations.

## Documentation

- [`readme.txt`](readme.txt) — WordPress plugin description and feature details.
- [`CHANGELOG.md`](CHANGELOG.md) — cumulative changes.
- [`docs/YABLONSKY_PRODUCT_VERSIONING_CANON_v1.0.0_2026-09-21.md`](docs/YABLONSKY_PRODUCT_VERSIONING_CANON_v1.0.0_2026-09-21.md) — product versioning.
- [`docs/YSEC_CRAWLER_ACCEPTANCE.md`](docs/YSEC_CRAWLER_ACCEPTANCE.md) — crawler-verification boundaries.

## Security and licensing

Security software reduces risk but cannot guarantee a site is free of vulnerabilities. Do not post credentials, private server logs, or exploit details in public issues.

**License:** GPL-2.0-or-later. See [`LICENSE`](LICENSE).

Developed by [Yablonsky.io](https://yablonsky.io/).
