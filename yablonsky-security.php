<?php
/**
 * Plugin Name: Yablonsky Security
 * Plugin URI: https://yablonsky.io/security/
 * Description: Security, integrity, reconnaissance intelligence, login protection, auditing, and guarded response for WordPress.
 * Version: 2.88.6
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * Author: Yablonsky.io
 * Author URI: https://yablonsky.io/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: yablonsky-security
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

/*
 * Canonical-plugin identity guard. If a second copy of Yablonsky Security is
 * accidentally installed under another directory while the canonical copy is
 * already active, stop this duplicate bootstrap before shared classes are
 * declared. This converts an accidental parallel install into a bounded no-op
 * instead of a PHP class/function redeclaration fatal.
 */
if ( defined( 'YSEC_VERSION' ) && defined( 'YSEC_FILE' ) && YSEC_FILE !== __FILE__ ) {
    return;
}

/*
 * PHP 7.4 compatibility boundary. WordPress 7.1 still supports PHP 7.4, while
 * these helpers became native in PHP 8.0/8.1. Define them only when absent so
 * modern runtimes continue to use the native implementations.
 */
if ( ! function_exists( 'str_contains' ) ) {
    function str_contains( $haystack, $needle ) { return '' === $needle || false !== strpos( $haystack, $needle ); }
}
if ( ! function_exists( 'str_starts_with' ) ) {
    function str_starts_with( $haystack, $needle ) { return '' === $needle || 0 === strncmp( $haystack, $needle, strlen( $needle ) ); }
}
if ( ! function_exists( 'str_ends_with' ) ) {
    function str_ends_with( $haystack, $needle ) {
        if ( '' === $needle ) return true;
        $length = strlen( $needle );
        return $length <= strlen( $haystack ) && 0 === substr_compare( $haystack, $needle, -$length );
    }
}

define( 'YSEC_VERSION', '2.88.6' );
define( 'YSEC_DB_VERSION', '1.9.4' );
define( 'YSEC_FILE', __FILE__ );
define( 'YSEC_DIR', plugin_dir_path( __FILE__ ) );
define( 'YSEC_URL', plugin_dir_url( __FILE__ ) );

require_once YSEC_DIR . 'includes/class-ysec-utils.php';
require_once YSEC_DIR . 'includes/class-ysec-db.php';
require_once YSEC_DIR . 'includes/class-ysec-environment.php';
require_once YSEC_DIR . 'includes/class-ysec-doctor.php';
require_once YSEC_DIR . 'includes/class-ysec-classifier.php';
require_once YSEC_DIR . 'includes/class-ysec-events.php';
require_once YSEC_DIR . 'includes/class-ysec-crawler-verification.php';
require_once YSEC_DIR . 'includes/class-ysec-discovery-interop.php';
require_once YSEC_DIR . 'includes/class-ysec-request-contract.php';
require_once YSEC_DIR . 'includes/class-ysec-l7-abuse.php';
require_once YSEC_DIR . 'includes/class-ysec-firewall.php';
require_once YSEC_DIR . 'includes/class-ysec-adaptive-response.php';
require_once YSEC_DIR . 'includes/class-ysec-rate-intelligence.php';
require_once YSEC_DIR . 'includes/class-ysec-firewall-policy.php';
require_once YSEC_DIR . 'includes/class-ysec-country-policy.php';
require_once YSEC_DIR . 'includes/class-ysec-conditional-rules.php';
require_once YSEC_DIR . 'includes/class-ysec-policy-portability.php';
require_once YSEC_DIR . 'includes/class-ysec-firewall-profiles.php';
require_once YSEC_DIR . 'includes/class-ysec-firewall-proof.php';
require_once YSEC_DIR . 'includes/class-ysec-fast-path.php';
require_once YSEC_DIR . 'includes/class-ysec-ddos-operations.php';
require_once YSEC_DIR . 'includes/class-ysec-managed-mu.php';
require_once YSEC_DIR . 'includes/class-ysec-jobs.php';
require_once YSEC_DIR . 'includes/class-ysec-login.php';
require_once YSEC_DIR . 'includes/class-ysec-private-login.php';
require_once YSEC_DIR . 'includes/class-ysec-accounts.php';
require_once YSEC_DIR . 'includes/class-ysec-captcha.php';
require_once YSEC_DIR . 'includes/class-ysec-comment-guard.php';
require_once YSEC_DIR . 'includes/class-ysec-integrity.php';
require_once YSEC_DIR . 'includes/class-ysec-permissions.php';
require_once YSEC_DIR . 'includes/class-ysec-malware.php';
require_once YSEC_DIR . 'includes/class-ysec-clamav.php';
require_once YSEC_DIR . 'includes/class-ysec-file-ingress.php';
require_once YSEC_DIR . 'includes/class-ysec-quarantine.php';
require_once YSEC_DIR . 'includes/class-ysec-repair-import.php';
require_once YSEC_DIR . 'includes/class-ysec-uploads.php';
require_once YSEC_DIR . 'includes/class-ysec-audit.php';
require_once YSEC_DIR . 'includes/class-ysec-alerts.php';
require_once YSEC_DIR . 'includes/class-ysec-hardening.php';
require_once YSEC_DIR . 'includes/class-ysec-security-headers.php';
require_once YSEC_DIR . 'includes/class-ysec-technology-exposure.php';
require_once YSEC_DIR . 'includes/class-ysec-exposure.php';
require_once YSEC_DIR . 'includes/class-ysec-database-safety.php';
require_once YSEC_DIR . 'includes/class-ysec-recovery.php';
require_once YSEC_DIR . 'includes/class-ysec-vulnerabilities.php';
require_once YSEC_DIR . 'includes/class-ysec-advisories.php';
require_once YSEC_DIR . 'includes/class-ysec-virtual-patches.php';
require_once YSEC_DIR . 'includes/class-ysec-posture.php';
require_once YSEC_DIR . 'includes/class-ysec-operations.php';
require_once YSEC_DIR . 'includes/class-ysec-security-report.php';
require_once YSEC_DIR . 'includes/class-ysec-autopilot.php';
require_once YSEC_DIR . 'includes/class-ysec-compatibility.php';
require_once YSEC_DIR . 'includes/class-ysec-migration.php';
require_once YSEC_DIR . 'includes/class-ysec-takeover.php';
require_once YSEC_DIR . 'includes/class-ysec-multisite.php';
require_once YSEC_DIR . 'includes/class-ysec-ai.php';
require_once YSEC_DIR . 'includes/class-ysec-rest.php';
require_once YSEC_DIR . 'includes/class-ysec-privacy.php';
require_once YSEC_DIR . 'includes/class-ysec-cli.php';
require_once YSEC_DIR . 'admin/class-ysec-admin-tables.php';
require_once YSEC_DIR . 'admin/class-ysec-admin.php';
require_once YSEC_DIR . 'includes/class-ysec-bundled-mo.php';
require_once YSEC_DIR . 'includes/class-ysec-plugin.php';

register_activation_hook( __FILE__, array( 'YSEC_DB', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'YSEC_DB', 'deactivate' ) );
register_deactivation_hook( __FILE__, array( 'YSEC_Managed_MU', 'deactivate' ) );

add_action( 'plugins_loaded', static function() {
    YSEC_Plugin::instance()->boot();
} );
