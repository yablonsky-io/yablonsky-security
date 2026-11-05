<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class YSEC_Hardening {
    public static function boot(): void {
        add_action( 'template_redirect', array( __CLASS__, 'visitor_lockdown' ), -1000 );
        $xmlrpc = (string) YSEC_Utils::option( 'xmlrpc_mode', 'monitor' );
        if ( 'disable' === $xmlrpc ) add_filter( 'xmlrpc_enabled', '__return_false' );
        if ( 'pingbacks' === $xmlrpc ) add_filter( 'xmlrpc_methods', array( __CLASS__, 'remove_pingback_methods' ) );
        if ( YSEC_Utils::option( 'disable_file_editor', 0 ) ) add_filter( 'map_meta_cap', array( __CLASS__, 'block_file_editor_caps' ), 10, 4 );
        if ( YSEC_Utils::option( 'disable_application_passwords', 0 ) ) {
            add_filter( 'wp_is_application_passwords_available', '__return_false' );
            add_filter( 'wp_is_application_passwords_available_for_user', '__return_false' );
        }
    }
    public static function lockdown_active(): bool {
        $until = absint( get_option( 'ysec_visitor_lockdown_until', 0 ) );
        if ( ! $until ) return false;
        if ( $until <= time() ) {
            delete_option( 'ysec_visitor_lockdown_until' );
            return false;
        }
        return true;
    }
    public static function lockdown_until(): int { return absint( get_option( 'ysec_visitor_lockdown_until', 0 ) ); }
    public static function enable_lockdown( int $minutes ): int {
        $minutes = max( 5, min( 1440, $minutes ) );
        $until = time() + $minutes * MINUTE_IN_SECONDS;
        update_option( 'ysec_visitor_lockdown_until', $until, false );
        YSEC_Events::log( 'visitor_lockdown_enabled', array( 'severity'=>'medium', 'family'=>'hardening', 'state'=>'contained', 'details'=>array( 'until'=>$until, 'actor'=>get_current_user_id() ) ) );
        return $until;
    }
    public static function disable_lockdown(): void {
        delete_option( 'ysec_visitor_lockdown_until' );
        YSEC_Events::log( 'visitor_lockdown_disabled', array( 'severity'=>'info', 'family'=>'hardening', 'details'=>array( 'actor'=>get_current_user_id() ) ) );
    }
    public static function visitor_lockdown(): void {
        if ( ! self::lockdown_active() || is_user_logged_in() || is_admin() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) return;
        status_header( 503 );
        nocache_headers();
        header( 'Retry-After: 300' );
        header( 'Content-Type: text/html; charset=' . get_bloginfo( 'charset' ) );
        echo '<!doctype html><html><head><meta charset="' . esc_attr( get_bloginfo( 'charset' ) ) . '"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . esc_html__( 'Temporarily unavailable', 'yablonsky-security' ) . '</title></head><body><main style="max-width:720px;margin:12vh auto;padding:32px;font:16px/1.5 system-ui,sans-serif"><h1>' . esc_html__( 'This site is temporarily protected', 'yablonsky-security' ) . '</h1><p>' . esc_html__( 'An administrator enabled emergency visitor lockdown. Please try again later.', 'yablonsky-security' ) . '</p></main></body></html>';
        exit;
    }

    public static function headers(): void {
        if ( class_exists( 'YSEC_Security_Headers' ) ) YSEC_Security_Headers::send_baseline_headers();
    }
    public static function remove_pingback_methods( array $methods ): array {
        unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
        return $methods;
    }
    public static function block_file_editor_caps( array $caps, string $cap, int $user_id, array $args ): array {
        if ( in_array( $cap, array( 'edit_plugins', 'edit_themes' ), true ) ) return array( 'do_not_allow' );
        return $caps;
    }
    public static function findings(): array {
        $f = array();
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) $f[] = array( 'severity'=>'medium', 'message'=>__( 'WP_DEBUG is enabled.', 'yablonsky-security' ) );
        if ( ! is_ssl() ) $f[] = array( 'severity'=>'high', 'message'=>__( 'HTTPS is not detected.', 'yablonsky-security' ) );
        if ( ! YSEC_Utils::option( 'disable_file_editor', 0 ) && ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) ) $f[] = array( 'severity'=>'low', 'message'=>__( 'The built-in plugin/theme file editor is enabled.', 'yablonsky-security' ) );
        if ( get_option( 'users_can_register' ) ) $f[] = array( 'severity'=>'info', 'message'=>__( 'Public user registration is enabled.', 'yablonsky-security' ) );
        if ( 'monitor' === YSEC_Utils::option( 'xmlrpc_mode', 'monitor' ) ) $f[] = array( 'severity'=>'info', 'message'=>__( 'XML-RPC is available; choose pingback-only blocking or full disable if the site does not need it.', 'yablonsky-security' ) );
        if ( ! YSEC_Utils::option( 'disable_application_passwords', 0 ) ) $f[] = array( 'severity'=>'info', 'message'=>__( 'WordPress Application Passwords remain available for API integrations.', 'yablonsky-security' ) );
        return $f;
    }
}
