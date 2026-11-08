## 2.88.6

- Fix client-side CAPTCHA bootstrap and login-style asset references when the plugin patch version changes; validate that referenced build files exist.
- Pin unchanged admin assets to their actual build filenames so corrective PHP updates do not request missing CSS or JavaScript.
- Set the canonical product Plugin URI to https://yablonsky.io/security/.
- Synchronize full GPLv2 license and shorten the WordPress.org readme while preserving external-service disclosures.
- Preserve stored settings, database schema, REST contracts, hooks, and security policy behavior.

## 2.88.5 — Early MU proof input compliance correction

- Unslash and sanitize synthetic Firewall Proof URI and token values before parsing them in the early MU-runtime response handler, addressing the four WordPress Plugin Check warnings found on both live test sites.
- Keep actual request-path classification unchanged: the early firewall still normalizes the original encoded request target and only the synthetic proof response consumes the sanitized copies.
- Preserve all 2.88.4 protection and proof behavior, localization catalogs, schema, options, UI and interoperability unchanged.

## 2.88.4 — Firewall Proof integrity correction

- Prevent unverified proof results on loopback unavailability, Minimal profile, or denial caused by a different enforcement rule.
- Authenticate early MU-runtime proof with a short-lived, one-request HMAC challenge bound to the verified rule family; normal visitor denies do not disclose the proof signature.
- Preserve all previous translations, firewall policies, database schema, login protection, malware scanner, WPML/WooCommerce and UI design.

## 2.88.3 — Bundled gettext runtime correction

- Resolve bundled MO files directly as a bounded read-only fallback when WordPress/WPML returns untranslated YSec text.
- Fix the `gettext` and `ngettext` paths for user profile locale, independent of other plugin language packs.
- Leave WordPress.org translation-pack precedence intact: no forced domain registration or unloading. Remove the discouraged registration call; leave protection logic and settings unchanged.

## 2.88.2 — WordPress gettext resilience for administration

- Add domain-specific, lazy POMO fallback for YSec when another extension leaves YSec strings untranslated even though user locale and compiled MO are available.
- Preserve user locale and all other text domains without global locale switching or reloading unrelated plugins.
- Cover singular, contextual and plural gettext hooks, leaving already translated/customized strings untouched.
- Add passive Doctor diagnostic flag for registration of YSec fallback.

## 2.88.1 — WordPress administrator-language gettext runtime correction

- Register the plugin's languages directory through WordPress text-domain APIs.
- Explicitly load the administrator's selected WordPress profile locale instead of treating any previously loaded text domain as proof of the correct locale.
- Retain the core's deliberate locale-switching behavior, WordPress language selector, all existing translations, and security functionality.
- Add read-only localization evidence to Security Doctor JSON exports, without adding controls or network requests.
- No schema, firewall, AI, locale files or security-policy changes.

## 2.88.0 — Traditional Chinese (Taiwan) locale and localization release gate

- Add independent zh_TW with Taiwanese terminology, retaining zh_CN and all 35 previously supplied locale catalogs.
- Verify gettext message ID parity, placeholder signatures, plural forms, HTML markers and PO/MO consistency for all 36 translation catalogs.
- Keep language selection native to each WordPress administrator profile. No internal locale selector and no reordering of WordPress core language lists.
- Fix two existing incorrect translations of the pingback-only option. Retain all 2.87.0 protection logic and database schema.

## 2.87.0 — Public distribution readiness

- Require explicit administrator consent for scheduled official crawler IP registry updates; withdrawing consent revokes cached verification.
- Replace generated PHP repair application with text-only AI malware advice; preserve scanning, forensic exports, quarantine and local recovery.
- Scope AI recommendations to the requesting administrator and update the forensic guidance.
- Keep firewall behavior, WordPress data schema, independent modules, and existing UI unchanged.
- Refresh localization and WordPress.org release metadata.

## 2.86.0 — Crawler authenticity, official evidence, safe interoperability (consolidated feature batch)

- Introduce scheduled-only official crawler CIDR registry for Google, Microsoft Bing, Applebot, OpenAI (Search, Ads, Training, User Fetch), Anthropic and Perplexity with distinct purposes and per-request identity evidence.
- Formalize `verified`, `spoofed` (fresh authoritative mismatch), `unverified`, and `verification_unavailable`; preserve purpose and behavior as independent fields. Explicitly exclude Google-Extended and Applebot-Extended as standalone HTTP User-Agent identities.
- Use SSRF-safe fixed HTTPS source URLs, TLS validation, no redirects, bounded response sizes and timeouts, limited background fetch budget, 48-hour evidence expiry and last-known-good retention.
- Reject untrusted forwarded-IP headers, malformed trusted proxy chains, provider spoofing and external filter attempts to promote verification. Read-only request contract fields remain immutable to consumers.
- Keep WAF enforcement, existing YSEO/YPerf hooks, WordPress/WooCommerce, AIOS coexistence, localization catalogs and accepted admin monitor layout unchanged.
- Retain cumulative forensic ZIP export fix from normalized historical 2.85.3 and earlier table / storage corrections. No schema migration.
- Explicit limits: DNS fallback is not yet implemented for provider IP feeds; Web Bot Auth signature verification and edge WAF reachability are not asserted by the WP runtime.
- Product versioning: MAJOR.MINOR.PATCH; MINOR 0–99, PATCH 0–9, rollover at 10 and at MINOR 100. Canon documented in docs.

## 2.85.3 — malware forensic report export contract correction

- Forensic ZIP now downloads for every available malware scan report, including clean scans with zero review findings; no redirect back to the Malware tab.
- Every forensic ZIP includes the complete same scan JSON metadata as the standalone JSON export, the same finding/trusted-artifact CSV, a brief summary, a manifest and explanatory README. Qualified suspicious files remain included when available, with existing 200 MB, digest and path safeguards.
- Malware toolbar keeps the ZIP control available whenever scan diagnostics exist; removes stale no-findings redirect notice. No scanner, quarantine, security enforcement or data schema changes.
- Baseline: Yablonsky Security 2.85.2; 35 language catalogs unchanged; product versioning canon YABLONSKY_PRODUCT_VERSIONING_CANON_v1.0.0_2026-09-21.md.

## 2.85.2 — consolidated security monitor UI corrections

- Remove the duplicated Path column from Events and Request column from Firewall while retaining full values in expandable Source / forensics.
- Widen forensic detail columns; retain invariant table geometry and scroll behaviour across viewport sizes.
- Clarify the Firewall containment action as primary, with reversible exception and evidence review actions under Advanced.
- Preserve event sorting/filtering, 35 language packs, security enforcement, WooCommerce interactions and schema.

# Yablonsky Security — Historical Changelog

The current correction release is in `readme.txt`. Archived package history follows.

= 2.84.9 =
* Repairs WordPress translator comment recognition and documents prepared SQL audit boundaries while retaining runtime behavior.

= 2.84.8 =
* Reports failed analytics reads as unavailable rather than zero, with invalidation and 24-hour metrics corrections.

= 2.84.7 =
* Displays unavailable Events storage totals as unknown instead of false zero after a database-read failure; successful measurements recover on the next request.
* Preserves evidence-report semantics under read failure: unavailable row counts, hit counts and compression factor are exported as null, with an explicit availability flag. Failure snapshots are not cached.
* Correctly clears the active analytics, operations, reconnaissance, firewall and evidence caches after successful or partially failed scheduled retention, keeping post-cleanup counters consistent.
* Preserves the cumulative 2.84.3–2.84.6 corrections, all 35 translations and the existing database schema, security controls and retention defaults.

= 2.84.6 =
* Records database write failures during tiered evidence cleanup, block expiration, rollup expiration, ceiling enforcement, and temporary export cleanup instead of claiming a successful retention cycle.
* Prevents orphaning temporary export fragments when removal of an expired job's parts fails.
* Preserves the previous successful maintenance receipt while showing a review warning after any partial failure. Automatic maintenance can retry on the next scheduled cycle.
* Processes unfinalized historical days without a 400-day starvation bug, and defers raw deletion when the daily rollup batch is incomplete.
* No schema, localization, WAF-enforcement, AI-authority, or retention-default changes.

= 2.84.4 =
* Corrects retention diagnostics by refreshing storage health before and after the cleanup cycle, reporting actual row-count changes.
* Preserves raw evidence if a closed-day rollup cannot be verified, rather than continuing irreversible tiered retention or row-ceiling deletion.
* Records a bounded maintenance warning without exposing database errors; the Events storage view and manual action now distinguish deferred maintenance from success.
* Carries forward the previous 2.84.3 interface and all existing language packs; no new translation strings or schema changes.


= 2.84.3 =
* Corrects the 7-day Overview pressure chart area geometry: both filled series now close at the baseline.
* Keeps the malware forensic ZIP restricted to real review findings; zero findings display an explanatory state, and stale links return to the Malware tab without a raw error page. Scan JSON/CSV diagnostics remain available.
* Displays the persisted per-user Events, Reconnaissance, and Firewall AI analysis journal in five collapsed entries per page, with stable ordering, navigable older pages, and selected-record deletion. Up to 60 journal entries are retained across those surfaces per user; the oldest are rotated out when this limit is reached.
* Adds explicit localized processing feedback and duplicate-submission safeguards for human-requested AI analysis, while preserving redaction and advisory-only execution.
* Normalizes spacing around monitor, export, malware, overview, and AI review surfaces without changing the export sequence or any stored-event schema.


= 2.84.2 =
* Corrective UX release for Events, Reconnaissance and Firewall: the evidence flow now reads roadmap/summary → filters → analytics/table → export workflow → Yablonsky AI review.
* Export CSV/JSON controls, background-job progress and final Download remain one uninterrupted visual/functional zone; AI history can no longer split export initiation from export progress.
* Adds monitor-surface spacing rules so rounded operational modules remain visually separated, while preserving the existing malware scanner toolbar/export grouping.
* No security-enforcement, malware traversal, AI authority, data schema, REST contract or gettext-surface changes; the frozen 1,835-message catalog and 36/36 language coverage remain intact.

= 2.84.1 =
* Corrective runtime release for the 2.84 contextual AI surface: parses provider streams down to the final structured analysis JSON instead of rendering echoed prompt/evidence payloads.
* Adds a bounded per-user contextual AI analysis journal with time, expandable full-width records, selection and deletion; only normalized analysis output is retained.
* Malware scanning no longer strands the complete wp-content traversal after one transient/path-specific ClamAV unavailable verdict; deterministic scanning continues and partial signature coverage remains explicit diagnostic evidence.
* Malware JSON/CSV diagnostics remain available for running, interrupted and failed resumable scan state; forensic ZIP remains available when findings exist.
* Preserves the frozen 1,835-message gettext catalog and all 36/36 product-language coverage.

= 2.84.0 =
* Adds explicit Yablonsky AI contextual analysis directly to Events, Reconnaissance and Firewall while preserving local enforcement authority and human-governed decisions.
* Contextual evidence is bounded to the selected surface and time window; source, source hashes, encrypted source identity and internal row IDs are removed before AI transmission, while secret-like fields continue through the existing redaction boundary.
* Events review uses recent bounded event evidence, Reconnaissance review uses grouped campaign evidence plus analytics, and Firewall review uses enforcement evidence plus source-redacted active-block context. AI output remains advisory and cannot change firewall state.
* Reuses the existing authenticated Yablonsky AI workspace/model route and explicit credit-consuming submit path; no AI request occurs on page load or automatic protection paths.
* Frozen localization authority remains 1,835 messages with all 35 non-English packs complete; no new gettext msgids were introduced, preserving 36/36 product-language coverage.

= 2.83.0 =
* Localization train completes cumulatively from the 2.82.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Vietnamese (`vi`) and Simplified Chinese (`zh_CN`) are complete across the exact frozen 1,835-message source catalog with locale-correct plural forms, fuzzy 0, exact printf placeholders, HTML-contract parity, rebuilt MO readback and semantic source-identical review.
* All 35 non-English locale packs are now complete on the same frozen catalog; with the English source surface, Yablonsky Security reaches 36/36 product-language coverage.
* Firewall, malware, AI authority, data schema, REST contract, Security Headers and Guarded Repair behavior remain unchanged.
= 2.82.0 =
* Localization train continues cumulatively from the 2.81.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Brazilian Portuguese (`pt_BR`) and Turkish (`tr_TR`) are complete across the exact frozen 1,835-message source catalog with locale-correct plural forms, fuzzy 0, exact printf placeholders, HTML-contract parity, rebuilt MO readback and semantic source-identical review.
* The previously completed 31 non-English locale packs remain complete on the same frozen catalog.
* Firewall, malware, AI authority, data schema, REST contract, Security Headers and Guarded Repair behavior remain unchanged.
= 2.81.0 =
* Localization train continues cumulatively from the 2.80.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Japanese (`ja`) and Korean (`ko_KR`) are complete across the exact frozen 1,835-message source catalog with locale-correct plural forms, fuzzy 0, exact printf placeholders, HTML-contract parity, rebuilt MO readback and semantic source-identical review.
* The previously completed 29 non-English locale packs remain complete on the same frozen catalog.
* Firewall, malware, AI authority, data schema, REST contract, Security Headers and Guarded Repair behavior remain unchanged.
= 2.80.0 =
* Localization train continues cumulatively from the 2.79.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Hindi (`hi_IN`) and Indonesian (`id_ID`) are complete across the exact frozen 1,835-message source catalog with locale-correct plural forms, fuzzy 0, exact printf placeholders, HTML-contract parity, rebuilt MO readback and semantic source-identical review.
* The previously completed 27 non-English locale packs remain complete on the same frozen catalog.
* Firewall, malware, AI authority, data schema, REST contract, Security Headers and Guarded Repair behavior remain unchanged.
= 2.79.0 =
* Localization train continues cumulatively from the 2.78.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Arabic (`ar`) and Persian (`fa_IR`) are complete across the exact frozen 1,835-message source catalog with locale-correct plural forms, fuzzy 0, exact printf placeholders, HTML-contract parity, rebuilt MO readback and RTL/bidi validation.
* The previously completed 25 non-English locale packs remain complete on the same frozen catalog.
* Firewall, malware, AI authority, data schema, REST contract, Security Headers and Guarded Repair behavior remain unchanged.
= 2.78.0 =
* Localization train continues cumulatively from the 2.77.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Irish (`ga`) and Maltese (`mt_MT`) are complete across the exact frozen 1,835-message source catalog with locale-correct plural forms, fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* The previously completed 23 non-English locale packs remain complete on the same frozen catalog.
* Firewall, malware, AI authority, data schema, REST contract, Security Headers and Guarded Repair behavior remain unchanged.
= 2.77.0 =
* Localization train continues cumulatively from the 2.76.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Greek (`el`) and Hungarian (`hu_HU`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`), German (`de_DE`), French (`fr_FR`), Spanish (`es_ES`), Italian (`it_IT`), European Portuguese (`pt_PT`), Dutch (`nl_NL`), Swedish (`sv_SE`), Danish (`da_DK`), Finnish (`fi`), Estonian (`et`), Latvian (`lv`), Czech (`cs_CZ`), Slovak (`sk_SK`), Slovenian (`sl_SI`), Romanian (`ro_RO`), Bulgarian (`bg_BG`) and Croatian (`hr`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.76.0 =
* Localization train continues cumulatively from the 2.75.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Bulgarian (`bg_BG`) and Croatian (`hr`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`), German (`de_DE`), French (`fr_FR`), Spanish (`es_ES`), Italian (`it_IT`), European Portuguese (`pt_PT`), Dutch (`nl_NL`), Swedish (`sv_SE`), Danish (`da_DK`), Finnish (`fi`), Estonian (`et`), Latvian (`lv`), Czech (`cs_CZ`), Slovak (`sk_SK`), Slovenian (`sl_SI`) and Romanian (`ro_RO`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.75.0 =
* Localization train continues cumulatively from the 2.74.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Slovenian (`sl_SI`) and Romanian (`ro_RO`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`), German (`de_DE`), French (`fr_FR`), Spanish (`es_ES`), Italian (`it_IT`), European Portuguese (`pt_PT`), Dutch (`nl_NL`), Swedish (`sv_SE`), Danish (`da_DK`), Finnish (`fi`), Estonian (`et`), Latvian (`lv`), Czech (`cs_CZ`) and Slovak (`sk_SK`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.74.0 =
* Localization train continues cumulatively from the 2.73.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Czech (`cs_CZ`) and Slovak (`sk_SK`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`), German (`de_DE`), French (`fr_FR`), Spanish (`es_ES`), Italian (`it_IT`), European Portuguese (`pt_PT`), Dutch (`nl_NL`), Swedish (`sv_SE`), Danish (`da_DK`), Finnish (`fi`), Estonian (`et`) and Latvian (`lv`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.73.0 =
* Localization train continues cumulatively from the 2.72.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Estonian (`et`) and Latvian (`lv`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`), German (`de_DE`), French (`fr_FR`), Spanish (`es_ES`), Italian (`it_IT`), European Portuguese (`pt_PT`), Dutch (`nl_NL`), Swedish (`sv_SE`), Danish (`da_DK`) and Finnish (`fi`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.72.0 =
* Localization train continues cumulatively from the 2.71.0 source candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Danish (`da_DK`) and Finnish (`fi`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`), German (`de_DE`), French (`fr_FR`), Spanish (`es_ES`), Italian (`it_IT`), European Portuguese (`pt_PT`), Dutch (`nl_NL`) and Swedish (`sv_SE`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.71.0 =
* Localization train continues cumulatively from the live-accepted 2.70.0 candidate and the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Dutch (`nl_NL`) and Swedish (`sv_SE`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`), German (`de_DE`), French (`fr_FR`), Spanish (`es_ES`), Italian (`it_IT`) and European Portuguese (`pt_PT`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.70.0 =
* Localization train continues cumulatively from the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Italian (`it_IT`) and European Portuguese (`pt_PT`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`), German (`de_DE`), French (`fr_FR`) and Spanish (`es_ES`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.69.0 =
* Localization train continues cumulatively from the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* French (`fr_FR`) and Spanish (`es_ES`) are complete across the exact frozen 1,835-message source catalog with fuzzy 0, exact printf placeholders, HTML-contract parity and rebuilt MO readback.
* Russian (`ru_RU`), Lithuanian (`lt_LT`), Ukrainian (`uk`), Polish (`pl_PL`) and German (`de_DE`) remain complete on the same frozen catalog.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.
= 2.68.0 =
* Localization train continues cumulatively from the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Ukrainian (`uk`) is complete across the exact current 1,835-message source catalog, with fuzzy 0, exact printf placeholders and rebuilt MO readback.
* Russian (`ru_RU`) and Lithuanian (`lt_LT`) remain complete; all 35 locale catalogs stay synchronized to the same frozen source set.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.

= 2.66.0 =
* Localization train continues cumulatively from the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Lithuanian (`lt_LT`) is complete across the exact current 1,835-message source catalog, with fuzzy 0, exact printf placeholders and rebuilt MO readback.
* Russian (`ru_RU`) remains complete and unchanged in translation content; all 35 locale catalogs stay synchronized to the same frozen source set.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.

= 2.65.0 =
* Localization train begins from the accepted 2.64.1 production code cutline; runtime security logic remains frozen.
* Russian (`ru_RU`) is complete across the exact current 1,835-message source catalog, with fuzzy 0, exact printf placeholders and rebuilt MO readback.
* Localization source is rebuilt from the current PHP gettext surface: 114 current messages absent from the previous POT were added, 45 stale messages were retired, and all 35 locale catalogs are synchronized to the same frozen source set before translation.
* No firewall, malware, AI authority, data schema, REST contract, Security Headers or Guarded Repair behavior changes.

= 2.64.1 =
* Corrective: completed Malware scan counters and preview now use the same current artifact-classification contract as Response Center, preventing stale review counts after a persisted finding is verified as a bounded runtime artifact.
* Corrective: scanner-verified runtime artifacts automatically resolve matching historical malware-finding evidence without deleting it; resolved records are archived as verified evidence so active Events and Reconnaissance no longer treat prior false positives as current threat pressure.
* Corrective: finalized daily rollups move reconciled false-positive malware evidence from its prior threat state into a verified state, preserving historical event volume while removing artificial reconnaissance pressure.
* No new user-facing strings, protection policy, AI authority or stored-data schema changes.

= 2.64.0 =
* Guarded Repair lifecycle: staged validation results now have an explicit Clear validation result action, retain the existing two-hour expiry, and make it clear when no replacement is waiting.
* Guarded Repair source context: staged candidates identify whether they came from an uploaded forensic ZIP or a Yablonsky AI draft.
* Yablonsky AI guarded repair: confirmed text-code malware can be sent only on an explicit administrator request to draft conservative replacement candidates; drafts are locally re-scanned, encrypted in staging and require a separate human Apply verified repairs action.
* AI repair safety: repair drafting is bounded to up to three confirmed text-code files per pass, preserves live SHA preconditions, never repairs review-only/verified artifacts, and keeps the existing encrypted-original rollback path.

= 2.63.0 =
* Threat analytics: chart scale now follows the currently visible series so low-volume Firewall/Recon signals remain readable; adding/removing comparison series rescales the plot without changing the underlying values.
* Malware classification: executable files under uploads are no longer treated as equivalent. Verified inert/plugin-runtime artifacts are excluded from findings, recognized WPML Twig cache files are downgraded to low-severity origin review, and the Response Center reports verified artifacts separately.
* Malware UX: findings, repair validation, and quarantine tables use bounded scroll surfaces with pagination so large result sets do not become endless admin pages.
* Guarded Repair wording: changed candidates are described as ready-to-apply only after verification instead of using the ambiguous Eligible label.

= 2.62.1 =
* Corrective: restores version-matched local admin, CAPTCHA and login assets for the 2.62.x release train.
* Prevents an unstyled Yablonsky Security admin surface when path-versioned assets are used.
* No security policy, malware classification, repair workflow or stored-data contract changes.

= 2.62.0 =
* Malware Response Center: adds guarded two-step repair ZIP import with site/path/SHA verification, encrypted staging, ClamAV + deterministic candidate checks, pre-repair encrypted quarantine, atomic-style replacement verification and automatic rollback on failed post-repair checks.
* Repair ZIP safety: unchanged candidates are recognized without touching live files; live files changed since forensic export are blocked from replacement.

= 2.61.1 =
* Corrective: persist the latest completed malware evidence durably so Redis/transient eviction cannot make Response Center exports disappear.
* Corrective: recover a valid completed full-scan result from the durable resumable scan state without forcing a rescan.
* Corrective: add required translator comments for malware summary placeholders.

= 2.61.0 =
* Malware Response Center: separates confirmed malware from review-only suspicious artifacts instead of treating every executable under uploads as confirmed malware.
* Malware findings use an internal scrollable review surface so the full retained finding set can be inspected without expanding the whole page.
* Adds a forensic review ZIP export with manifest, hashes, classification, preserved paths and selected file payloads for offline/AI/AV review.
* Keeps remediation human-governed: current files are never edited in place; quarantine remains reversible and future repaired candidates must use staged verification and atomic replacement.
* Restores explicit WordPress resource versions while retaining path-versioned assets, clearing Plugin Check MissingVersion warnings.


= 2.60.4 =
* Corrective: hardens cross-version admin control geometry and path-versions local browser assets so query-string stripping cannot leave stale UI code. Repairs the resumable malware walker by restoring missing file-inspection helpers/constants, making traversal errors fail closed, following symlinked content safely without duplicate loops, invalidating the earlier incomplete coverage contract, and refusing a green COMPLETE result when filesystem coverage is incomplete.
= 2.60.3 =
* WordPress 6.4 compatibility: replaces the list-array compatibility dependency with a YSec-prefixed PHP 7.4-safe helper, keeping the declared WordPress 6.4 floor valid under Plugin Check.
* Admin UI: standardizes ordinary text/search/password/email/URL/numeric/date-time controls, selects and buttons to the same canonical 40px control axis across supported WordPress admin versions.
* Keeps model pickers and searchable selectors aligned to the same control geometry without changing protection, database, AI-routing, firewall, malware or localization semantics.

= 2.60.2 =
* Compatibility gate: lowers the declared WordPress installation floor from 6.5 to 6.4 so the existing runtime/admin surface can be validated on WordPress 6.4.x.
* No protection semantics, database schema, Malware/ClamAV behavior, Firewall policy, Security Headers policy, REST contracts or localization strings changed.
* Adds the Monparle production-scale compatibility gate for WordPress 6.4.x before localization freeze.

= 2.60.1 =
* Makes active ClamAV signature coverage a completion invariant: when local clamd is connected, a file that cannot receive a definitive signature result pauses the resumable scan instead of allowing a green complete state.
* Preserves the exact directory/file checkpoint for retry, so Resume scan retries the same file after the local ClamAV access/stream condition is corrected rather than silently skipping it.
* Keeps deterministic local heuristics independent while preventing partial signature coverage from being reported as complete coverage.

= 2.60.0 =
* Runtime/Admin Optimization II: adds an archived+state+time evidence index for the high-frequency Events/Reconnaissance/Firewall filtering path.
* Analytics: merges finalized rollups and unfinalized hot evidence into one bounded daily aggregate query instead of two separate database round-trips.
* Evidence tables: sparse first-page results skip a redundant COUNT query; exact counts are still used whenever pagination needs them.
* Evidence rows: selects only the columns required by the current admin evidence/forensics surfaces instead of fetching unused event metadata.
* No security-policy, Firewall, Malware, CSP/HSTS, REST, stored-data or public compatibility contracts changed in this optimization train.

= 2.59.1 =
* Analytics polish: replaced full-span spline interpolation with local corner rounding so daily values remain visually sharp while hard angular joins are softened.
* Analytics clarity: correlation legends now show the selected-period total for every series, making true zero-value signals such as source containment explicit.
* Cross-product evidence: documented the YPerf Page Cache HIT header-replay interoperability gap observed during public Security Headers validation; YSec baseline headers are present on MISS but absent on HIT until the page-cache delivery layer preserves them.

= 2.59.0 =
* Optimization train: table/filter requests now cancel stale in-flight loads instead of blocking newer operator input.
* Consolidated post-action table refresh through the same request coordinator to avoid duplicate AJAX paths.
* Reduced admin job-status restoration from one identical request per data view to one request per loaded scope.
* No protection semantics, schema contracts, firewall behavior, malware behavior, CSP policy behavior, or stored-data contracts changed.

= 2.58.2 =
* Overview polish: aligned overview summary cards to the same grid rhythm as the 24-hour activity cards and grouped them in a shared bordered surface.
* Malware scanner UX: separated resumable stopped-state behavior from new scan behavior so interrupted scans can resume predictably without silently restarting from zero.
* Malware scanner copy: clarified stopped/resume/new-scan messaging for more predictable operator expectations.


= 2.58.1 =
* Corrective analytics UI patch: Family opens immediately from the server-rendered bounded catalog instead of waiting for a WordPress AJAX round trip.
* Family search filters the complete preloaded catalog locally when bounded; AJAX remains a fallback only when the catalog exceeds the preload ceiling.
* Stale remote selector requests are aborted and no longer blank the option list while typing.
* Replaced the font-glyph Family arrow with a geometrically centered SVG chevron so open/closed states stay optically centered.

= 2.58.0 =
* Refactors Events, Reconnaissance and Firewall onto one shared monitor-filter layout with the same search, family, severity, state/decision, record-status, date, timeframe and reset positions.
* Replaces the high-cardinality Family native selector on all three monitoring surfaces with a reusable local AJAX-search selector while keeping low-cardinality filters simple and predictable.
* Centers and normalizes 7-day, 30-day and 90-day timeframe controls so labels, padding, height and reset alignment stay consistent across the monitoring workspace.
* Uses canonical semantic chart series across all monitoring views: Security event hits, Reconnaissance hits, Request denies and Source containment keep the same line identity everywhere.
* Shows each tab’s native analytics series by default while keeping neighboring correlation series available as opt-in legend controls.
* Adds monotone curve smoothing that passes through the exact daily data points without changing stored values, and keeps native-series area fills bounded to their own baseline.
* Extends Reconnaissance evidence filtering and bulk-source scope to severity, state and record status so the standardized controls have real query semantics rather than decorative parity.

= 2.57.0 =
* Fixes threat-chart SVG area geometry so shaded regions follow each series to the baseline without diagonal cross-chart closures.
* Standardizes Events, Reconnaissance and Firewall analytics on the same 7-day default window while preserving custom calendar ranges.
* Adds one-click 7-day, 30-day and 90-day timeframe controls to all three operational analytics surfaces.
* Adds synchronized cross-surface correlation overlays so event pressure, reconnaissance pressure and firewall decisions can be compared on the same time axis and scale; legend controls can hide or restore individual series locally.

= 2.56.1 =
* Corrects six WordPress Plugin Check false positives in the Security Headers known-service CSP catalog. Cloudflare Turnstile and Google reCAPTCHA host strings are policy metadata only; YSec does not enqueue, fetch or offload plugin assets to those services through this catalog.
* Adds tightly scoped PHPCS suppressions only to the six CSP metadata lines reported by PluginCheck.CodeAnalysis.Offloading.OffloadedContent, preserving the 2.56.0 Security Headers runtime and UI behavior unchanged.

= 2.56.0 =
* Adds the Security Headers Control Plane in Hardening with a guided CSP workflow: discovery, policy proposal, Report-Only evidence, human-reviewed source decisions and guarded enforcement.
* Adds known-service presets for common video, analytics, CAPTCHA, payment and support integrations without treating detected services as automatically trusted.
* Adds first-class custom and self-hosted CSP origins plus an advanced raw-policy editor with directive/source validation and header-injection protection.
* Adds a bounded local CSP report endpoint and drift-evidence table that retain normalized directive/origin pairs instead of full blocked URLs, query strings, request bodies or cookies.
* Prevents a new CSP policy from jumping directly from Off to Enforce and keeps enforcement in Report-Only while unresolved source evidence remains.
* Adds separate HSTS controls with HTTPS-only emission and guarded includeSubDomains/preload prerequisites.
* Adds a downloadable Security Headers JSON evidence report while preserving the existing conservative baseline header toggle.
* Includes Security Headers policy in verified policy portability, encrypted local recovery checkpoints and posture-report evidence without exporting browser request bodies or credentials.

= 2.55.4 =
* Corrects Firewall Proof submission so the busy-state UI cannot remove the submit signal before WordPress processes the request.
* Routes Firewall Proof execution through a dedicated authenticated admin-post action, then returns to the proof panel with the durable receipt available for JSON download.
* Moves the existing Safe security headers control from Accounts to the Hardening settings panel, matching its actual runtime responsibility.

= 2.55.3 =
* Corrects the ClamAV Unix-socket/INSTREAM implementation for WordPress Plugin Check by documenting the four native stream primitives that have no WP_Filesystem equivalent, while keeping bounded-memory streaming intact.
* Fixes the live progress label so the percentage renders once, not as a duplicated %% token.
* Adds elapsed time and estimated remaining time to the resumable malware workbench and records completed scan duration in the JSON report.
* Remembers a clamd direct-path permission failure briefly across scan AJAX batches, avoiding repeated failed direct-SCAN probes before the known-good INSTREAM path.
* Compacts scan controls and JSON/CSV report downloads into one responsive toolbar so the workbench fits a dashboard viewport more efficiently.
* Makes Debian/Ubuntu ClamAV server setup discoverable directly above the scanner even when ClamAV is already connected.
* Keeps Firewall Proof execution and JSON receipt download in one visible toolbar and returns proof POSTs explicitly to the Firewall proof section.

= 2.55.2 =
* Corrects WordPress Plugin Check i18n translator-comment findings introduced in the 2.55.1 workbench strings.
* Prevents the deterministic web-shell marker rule from treating literal security-signature catalogs as malware, including YSec's own rule definitions.
* Adds ClamAV INSTREAM fallback over the existing local Unix socket when clamd can PING but cannot traverse a Virtualmin site's filesystem path directly, while keeping direct SCAN as the preferred zero-copy path.
* Adds ClamAV transport/error counters to scan state and reports for runtime proof.
* Persists the latest Firewall Proof receipt so PASS evidence and JSON download remain available beyond the short transient cache window.
* Documents supported WordPress/PHP versions and the bounded malware-scanner resource model.

= 2.55.1 =
* Corrective malware-scanner workbench: readable metric tiles, progress/activity stream, state-aware controls, explicit outcomes, finding review and downloadable run reports.
* Moves ClamAV and upload-receipt details behind a secondary setup surface and adds copy-ready Debian/Ubuntu local-daemon instructions.
* Clears stale section anchors during SPA tab navigation and preserves completed scan state across the update.

= 2.55.0 =
* Replaces the 8,000-file interactive malware cap with a resumable bounded-batch traversal of the complete wp-content scope.
* Adds explicit local ClamAV/clamd provider status, signature-scan counters and a latest file-ingress security receipt.
* Keeps deterministic high-confidence heuristics active independently of ClamAV.
* Returns Firewall Proof to its result panel after submission and shows an in-place busy state while the proof runs.

= 2.54.1 =
* Corrects ClamAV local-socket transport for WordPress Plugin Check compliance.
* Accepts verified Managed MU early-deny evidence in live Firewall Proof.
* Uses attention styling for reviewable proof outcomes.

= 2.54.0 =
* Explicit YSec MU security phase ordering before YPerf capacity admission.
* Real-time file-ingress gate for media/sideloads and extracted plugin/theme packages.
* Optional local ClamAV/clamd signature provider; deterministic heuristics remain the built-in baseline.
* YPerf capacity deferral stays outside attack counters and does not become a security verdict.

= 2.53.0 =
* Puts the live Firewall control plane first and moves origin-protection tooling below the primary monitor.
* Replaces repeated Events / Reconnaissance / Firewall cards with a compact Observe → Correlate → Respond flow rail.
* Combines Application DDoS and Managed MU controls into a compact two-tab Origin protection surface with clearer spacing and proof state.
* Makes malware-engine scope explicit: built-in deterministic high-confidence heuristics, with signature-provider coverage kept as a separate optional layer.
* Adds external emergency recovery for source containment through WP-CLI, a wp-config bypass switch and a filesystem fallback.
* Documents IPv4, IPv6 and CIDR support directly beside durable allow/block policy controls.
* Surfaces the detected server and wp-content/debug.log shielding path in the reviewed Server Fast Path workflow.
* Keeps Compatibility focused on the current security stack, responsibility boundaries and optional migration tools.

= 2.52.3 =
* Restores the Firewall and Accounts screens after the 2.52.2 UI-surface cleanup regression.
* Keeps Application DDoS Protection in Firewall and removes its accidental duplicate from Compatibility.
* Reorganizes Compatibility around overlap detection, responsibility boundaries, coexistence verification and human-approved cutover.
* Normalizes spacing between top-level security modules across the admin interface.

= 2.52.2 =
* Focuses the installed interface on security operations and site protection.
* Streamlines administrator screens and posture reporting around active security operations and site protection.
* Keeps Yablonsky AI scoped to administrator-invoked security analysis and security-mode assistance.
* Trims the public changelog to the supported WordPress.org parser size.

= 2.52.1 =
* Restores the security-only runtime boundary by retiring an experimental non-security workflow from the installed plugin.

= 2.42.2 =
* Restores canonical plugin identity and packaging after the source-package installation incident.
* Preserves Managed MU Early Guard ABI 1 and the accepted security runtime.

= 2.37.0 =
* Adds positive capability-first product language and clarifies application-layer DDoS protection.

= 2.35.1 =
* Corrects Managed MU lifecycle compliance and keeps early request handling fail-safe.

= 2.33.0 =
* Adds the unified Comment abuse security surface.

= 2.32.1 =
* Corrects Comment Guard output escaping while preserving normal comment flow and direct-post enforcement.

For detailed historical development provenance, use the release/handoff bundle distributed with each development train.
