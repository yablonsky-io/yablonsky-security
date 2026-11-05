<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Bounded local email alerts and daily digest. No external alert service required. */
final class YSEC_Alerts {
    public static function boot(): void {
        add_action( 'wp_login', array( __CLASS__, 'admin_login' ), 20, 2 );
        add_action( 'activated_plugin', static fn( $plugin ) => self::admin_change( 'plugin_activated', array( 'plugin'=>sanitize_text_field( (string) $plugin ) ) ) );
        add_action( 'deactivated_plugin', static fn( $plugin ) => self::admin_change( 'plugin_deactivated', array( 'plugin'=>sanitize_text_field( (string) $plugin ) ) ) );
        add_action( 'deleted_plugin', static fn( $plugin, $deleted ) => $deleted ? self::admin_change( 'plugin_deleted', array( 'plugin'=>sanitize_text_field( (string) $plugin ) ) ) : null, 20, 2 );
        add_action( 'switch_theme', static fn( $name ) => self::admin_change( 'theme_switched', array( 'theme'=>sanitize_text_field( (string) $name ) ) ), 20, 1 );
        add_action( 'set_user_role', static fn( $user_id, $role ) => self::admin_change( 'user_role_changed', array( 'user_id'=>absint( $user_id ), 'role'=>sanitize_key( (string) $role ) ) ), 20, 2 );
        add_action( 'ysec_security_alert', array( __CLASS__, 'security_alert' ), 10, 2 );
        add_action( 'ysec_daily_maintenance', array( __CLASS__, 'daily_digest' ), 80 );
    }

    public static function admin_login( string $user_login, WP_User $user ): void {
        if ( ! YSEC_Utils::option( 'alerts_enabled', 0 ) || ! YSEC_Utils::option( 'alerts_admin_login', 1 ) ) return;
        if ( ! user_can( $user, 'manage_options' ) ) return;
        self::send_once(
            'admin_login_' . (int) $user->ID,
            __( 'Administrator login', 'yablonsky-security' ),
            array(
                __( 'An administrator account signed in.', 'yablonsky-security' ),
                sprintf( /* translators: %d: WordPress user ID. */ __( 'User ID: %d', 'yablonsky-security' ), (int) $user->ID ),
            ),
            15 * MINUTE_IN_SECONDS
        );
    }

    public static function admin_change( string $event, array $details ): void {
        if ( ! YSEC_Utils::option( 'alerts_enabled', 0 ) || ! YSEC_Utils::option( 'alerts_admin_changes', 1 ) ) return;
        $lines = array( sprintf( /* translators: %s: security event key. */ __( 'Security-relevant administration event: %s', 'yablonsky-security' ), sanitize_key( $event ) ) );
        foreach ( $details as $key => $value ) {
            if ( ! is_scalar( $value ) ) continue;
            $lines[] = sanitize_key( (string) $key ) . ': ' . sanitize_text_field( (string) $value );
        }
        self::send_once( 'admin_change_' . sanitize_key( $event ), __( 'Security administration change', 'yablonsky-security' ), $lines, 5 * MINUTE_IN_SECONDS );
    }

    public static function security_alert( string $event, array $details = array() ): void {
        if ( ! YSEC_Utils::option( 'alerts_enabled', 0 ) || ! YSEC_Utils::option( 'alerts_critical_events', 1 ) ) return;
        $lines = array( sprintf( /* translators: %s: security alert key. */ __( 'YSec detected a high-confidence security condition: %s', 'yablonsky-security' ), sanitize_key( $event ) ) );
        foreach ( array( 'family','reason','profile','country' ) as $key ) {
            if ( isset( $details[ $key ] ) && is_scalar( $details[ $key ] ) ) $lines[] = $key . ': ' . sanitize_text_field( (string) $details[ $key ] );
        }
        self::send_once( 'security_' . sanitize_key( $event ), __( 'High-confidence security alert', 'yablonsky-security' ), $lines, HOUR_IN_SECONDS );
    }

    public static function send_test(): bool {
        return self::send( __( 'Test security alert', 'yablonsky-security' ), array( __( 'This is a Yablonsky Security alert-delivery test.', 'yablonsky-security' ) ) );
    }

    public static function daily_digest(): void {
        if ( ! YSEC_Utils::option( 'alerts_enabled', 0 ) || ! YSEC_Utils::option( 'alerts_daily_digest', 1 ) ) return;
        global $wpdb;
        $table = $wpdb->prefix . 'ysec_events';
        $cut = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Read-only bounded digest from YSec-owned table; identifier and cutoff are prepared.
        $rows = $wpdb->get_results( $wpdb->prepare( 'SELECT severity,SUM(hit_count) hits FROM %i WHERE observed_at >= %s GROUP BY severity', $table, $cut ), ARRAY_A ) ?: array();
        $counts = array( 'info'=>0,'low'=>0,'medium'=>0,'high'=>0,'critical'=>0 );
        foreach ( $rows as $row ) {
            $sev = sanitize_key( (string) ( $row['severity'] ?? '' ) );
            if ( array_key_exists( $sev, $counts ) ) $counts[ $sev ] = absint( $row['hits'] ?? 0 );
        }
        $lines = array(
            __( 'YSec security evidence summary for the last 24 hours.', 'yablonsky-security' ),
            'critical: ' . $counts['critical'],
            'high: ' . $counts['high'],
            'medium: ' . $counts['medium'],
            'low: ' . $counts['low'],
            'info: ' . $counts['info'],
        );
        self::send( __( 'Daily security digest', 'yablonsky-security' ), $lines );
    }

    private static function send_once( string $key, string $subject, array $lines, int $ttl ): void {
        $transient = 'ysec_alert_' . substr( hash( 'sha256', $key ), 0, 24 );
        if ( get_transient( $transient ) ) return;
        if ( self::send( $subject, $lines ) ) set_transient( $transient, 1, max( MINUTE_IN_SECONDS, $ttl ) );
    }

    private static function send( string $subject, array $lines ): bool {
        $email = sanitize_email( (string) YSEC_Utils::option( 'alerts_email', '' ) );
        if ( '' === $email ) $email = sanitize_email( (string) get_option( 'admin_email', '' ) );
        if ( ! is_email( $email ) ) return false;
        $site = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
        $body = implode( "\n", array_map( static fn( $line ) => sanitize_text_field( (string) $line ), $lines ) );
        $body .= "\n\n" . home_url( '/' );
        return wp_mail( $email, '[' . $site . '] YSec — ' . $subject, $body );
    }
}
