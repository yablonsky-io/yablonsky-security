<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) { exit; }

/*
 * Security evidence in YSec database tables is intentionally retained on uninstall.
 * Managed MU runtime files are execution artifacts, not evidence, and must never be
 * left orphaned after the owning plugin is removed.
 */
function ysec_uninstall_cleanup_managed_mu_runtime(): void {
    $ysec_mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
    $ysec_loader = rtrim( $ysec_mu_dir, '/\\' ) . '/yablonsky-security-runtime.php';
    if ( is_readable( $ysec_loader ) ) {
        $ysec_head = file_get_contents( $ysec_loader, false, null, 0, 4096 );
        if ( is_string( $ysec_head ) && false !== strpos( $ysec_head, 'YSEC_MANAGED_MU_RUNTIME_ABI=1' ) ) wp_delete_file( $ysec_loader );
    }

    $ysec_state_dir = WP_CONTENT_DIR . '/ysec-runtime';
    foreach ( array( 'policy.php', 'early-evidence.php', 'index.php' ) as $ysec_name ) {
        $ysec_path = $ysec_state_dir . '/' . $ysec_name;
        if ( is_file( $ysec_path ) ) wp_delete_file( $ysec_path );
    }

    if ( ! function_exists( 'WP_Filesystem' ) ) require_once ABSPATH . 'wp-admin/includes/file.php';
    global $wp_filesystem;
    if ( WP_Filesystem() && is_object( $wp_filesystem ) && $wp_filesystem->is_dir( $ysec_state_dir ) ) {
        $wp_filesystem->rmdir( $ysec_state_dir, false );
    }
}

ysec_uninstall_cleanup_managed_mu_runtime();
