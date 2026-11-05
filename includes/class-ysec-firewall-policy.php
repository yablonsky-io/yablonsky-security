<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Durable, human-governed firewall policy.
 *
 * This layer is intentionally independent from the temporary response-block table:
 * allowlist/permanent block policy survives response expiry and remains explicitly visible.
 */
final class YSEC_Firewall_Policy {
    public static function settings(): array {
        $defaults = array(
            'allowlist' => '',
            'blocklist' => '',
            'path_blocklist' => '',
            'request_allowlist' => '',
            'login_allowlist_enabled' => 0,
            'login_allowlist' => '',
            'login_honeypot' => 1,
            'registration_approval' => 0,
        );
        return wp_parse_args( get_option( 'ysec_firewall_policy', array() ), $defaults );
    }

    /**
     * Sanitize policy input. Returns a sanitized array or WP_Error when the policy would lock out the administrator.
     *
     * @return array|WP_Error
     */
    public static function sanitize( array $input ) {
        $current = self::settings();
        $out = $current;
        foreach ( array( 'allowlist', 'blocklist', 'login_allowlist' ) as $key ) {
            $out[$key] = self::sanitize_network_list( (string) ( $input[$key] ?? '' ) );
        }
        $out['path_blocklist'] = self::sanitize_path_list( (string) ( $input['path_blocklist'] ?? $current['path_blocklist'] ?? '' ) );
        $out['request_allowlist'] = self::sanitize_request_list( (string) ( $input['request_allowlist'] ?? $current['request_allowlist'] ?? '' ) );
        $out['login_allowlist_enabled'] = empty( $input['login_allowlist_enabled'] ) ? 0 : 1;
        $out['login_honeypot'] = empty( $input['login_honeypot'] ) ? 0 : 1;
        $out['registration_approval'] = empty( $input['registration_approval'] ) ? 0 : 1;

        $admin_ip = YSEC_Utils::client_ip();
        if ( '' !== $admin_ip && self::ip_in_text( $admin_ip, $out['blocklist'] ) ) {
            return new WP_Error( 'ysec_policy_self_block', __( 'The permanent block list contains your current administrator source. Remove it before saving.', 'yablonsky-security' ) );
        }
        if ( $out['login_allowlist_enabled'] ) {
            if ( '' === $admin_ip ) return new WP_Error( 'ysec_login_allowlist_unknown_source', __( 'Login allowlist cannot be enabled because the current administrator source IP could not be determined safely.', 'yablonsky-security' ) );
            if ( ! self::ip_in_text( $admin_ip, $out['login_allowlist'] ) ) return new WP_Error( 'ysec_login_allowlist_self_lockout', __( 'Login allowlist cannot be enabled until your current administrator source is included.', 'yablonsky-security' ) );
        }
        return $out;
    }

    private static function sanitize_network_list( string $raw ): string {
        $out = array();
        foreach ( preg_split( '/[\r\n,]+/', $raw ) ?: array() as $entry ) {
            $entry = trim( $entry );
            if ( '' === $entry ) continue;
            if ( self::valid_network_entry( $entry ) ) $out[] = $entry;
        }
        return implode( "\n", array_values( array_unique( $out ) ) );
    }

    private static function valid_network_entry( string $entry ): bool {
        if ( filter_var( $entry, FILTER_VALIDATE_IP ) ) return true;
        if ( false === strpos( $entry, '/' ) ) return false;
        list( $ip, $bits ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! ctype_digit( (string) $bits ) ) return false;
        $max = false !== strpos( $ip, ':' ) ? 128 : 32;
        return (int) $bits >= 0 && (int) $bits <= $max;
    }

    private static function sanitize_path_list( string $raw ): string {
        $out = array();
        foreach ( preg_split( '/[\r\n]+/', $raw ) ?: array() as $entry ) {
            $entry = trim( sanitize_text_field( $entry ) );
            if ( '' === $entry || '/' !== $entry[0] ) continue;
            if ( strlen( $entry ) > 256 || preg_match( '/[\x00-\x1F\x7F]/', $entry ) ) continue;
            $out[] = $entry;
            if ( count( $out ) >= 100 ) break;
        }
        return implode( "\n", array_values( array_unique( $out ) ) );
    }

    /**
     * Exact request exceptions are intentionally narrower than the source allowlist.
     * Each line is METHOD + normalized path (for example: GET /healthcheck).
     * They bypass only automatic profile matching; explicit source blocks, country
     * policy, adaptive/rate containment, virtual patches and manual deny rules still win.
     */
    private static function sanitize_request_list( string $raw ): string {
        $out = array();
        foreach ( preg_split( '/[\r\n]+/', $raw ) ?: array() as $entry ) {
            $entry = trim( sanitize_text_field( $entry ) );
            if ( '' === $entry ) continue;
            $parts = preg_split( '/\s+/', $entry, 2 );
            $method = strtoupper( sanitize_key( (string) ( $parts[0] ?? '' ) ) );
            $path = isset( $parts[1] ) ? YSEC_Utils::normalize_path( (string) $parts[1] ) : '';
            $key = self::request_exception_key( $method, $path );
            if ( '' === $key ) continue;
            $out[] = $key;
            if ( count( $out ) >= 100 ) break;
        }
        return implode( "\n", array_values( array_unique( $out ) ) );
    }

    public static function request_exception_active( string $method, string $path ): bool {
        $needle = self::request_exception_key( $method, $path );
        if ( '' === $needle ) return false;
        foreach ( preg_split( '/[\r\n]+/', (string) self::settings()['request_allowlist'] ) ?: array() as $entry ) {
            if ( hash_equals( trim( $entry ), $needle ) ) return true;
        }
        return false;
    }

    public static function add_request_exception( string $method, string $path ): bool {
        $key = self::request_exception_key( $method, $path );
        if ( '' === $key ) return false;
        $settings = self::settings();
        $existing = array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n]+/', (string) $settings['request_allowlist'] ) ?: array() ) ) );
        if ( in_array( $key, $existing, true ) ) return true;
        if ( count( $existing ) >= 100 ) return false;
        $existing[] = $key;
        $settings['request_allowlist'] = implode( "\n", $existing );
        $sanitized = self::sanitize( $settings );
        if ( is_wp_error( $sanitized ) ) return false;
        return update_option( 'ysec_firewall_policy', $sanitized, false );
    }

    public static function remove_request_exception( string $method, string $path ): bool {
        $key = self::request_exception_key( $method, $path );
        if ( '' === $key ) return false;
        $settings = self::settings();
        $existing = array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n]+/', (string) $settings['request_allowlist'] ) ?: array() ) ) );
        $filtered = array_values( array_filter( $existing, static function( $entry ) use ( $key ) { return ! hash_equals( (string) $entry, $key ); } ) );
        if ( count( $filtered ) === count( $existing ) ) return true;
        $settings['request_allowlist'] = implode( "\n", $filtered );
        $sanitized = self::sanitize( $settings );
        if ( is_wp_error( $sanitized ) ) return false;
        return update_option( 'ysec_firewall_policy', $sanitized, false );
    }

    public static function can_except_family( string $family ): bool {
        return in_array( sanitize_key( $family ), array(
            'credentials_secrets','path_traversal','framework_probe','database_admin','backup_dump',
            'reconnaissance','abusive_method','scanner_user_agent','exploit_query','suspicious_cookie_name'
        ), true );
    }

    public static function can_except_request( string $family, string $method, string $path ): bool {
        return self::can_except_family( $family ) && '' !== self::request_exception_key( $method, $path );
    }

    private static function request_exception_key( string $method, string $path ): string {
        $method = strtoupper( sanitize_key( $method ) );
        $path = YSEC_Utils::normalize_path( $path );
        if ( ! in_array( $method, array( 'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS' ), true ) ) return '';
        if ( '' === $path || '/' !== $path[0] || strlen( $path ) > 512 ) return '';
        // Never allow an administrator exception to invalidate YSec's own proof canaries.
        if ( false !== strpos( $path, '__ysec-profile-proof__' ) || '/.__ysec_fastpath_probe__' === $path ) return '';
        return $method . ' ' . $path;
    }

    public static function path_blocked( string $path ): bool {
        $path = YSEC_Utils::normalize_path( $path );
        foreach ( preg_split( '/[\r\n]+/', (string) self::settings()['path_blocklist'] ) ?: array() as $rule ) {
            $rule = trim( $rule );
            if ( '' === $rule ) continue;
            if ( str_ends_with( $rule, '*' ) ) {
                $prefix = substr( $rule, 0, -1 );
                if ( '' !== $prefix && str_starts_with( $path, $prefix ) ) return true;
            } elseif ( hash_equals( $rule, $path ) ) return true;
        }
        return false;
    }

    public static function add_allowlist_entry( string $entry ): bool {
        $entry = trim( $entry );
        if ( '' === $entry || ! self::valid_network_entry( $entry ) ) return false;
        $settings = self::settings();
        $existing = array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', (string) ( $settings['allowlist'] ?? '' ) ) ?: array() ) ) );
        if ( in_array( $entry, $existing, true ) ) return true;
        $existing[] = $entry;
        $settings['allowlist'] = implode( "\n", array_values( array_unique( $existing ) ) );
        $sanitized = self::sanitize( $settings );
        if ( is_wp_error( $sanitized ) ) return false;
        return update_option( 'ysec_firewall_policy', $sanitized, false );
    }

    public static function allowlisted( string $ip ): bool {
        return self::ip_in_text( $ip, (string) self::settings()['allowlist'] );
    }

    public static function permanently_blocked( string $ip ): bool {
        return self::ip_in_text( $ip, (string) self::settings()['blocklist'] );
    }

    public static function login_allowed( string $ip ): bool {
        $s = self::settings();
        if ( empty( $s['login_allowlist_enabled'] ) ) return true;
        return self::ip_in_text( $ip, (string) $s['login_allowlist'] );
    }

    public static function honeypot_enabled(): bool {
        return ! empty( self::settings()['login_honeypot'] );
    }

    public static function registration_approval_enabled(): bool {
        return ! empty( self::settings()['registration_approval'] );
    }

    public static function exportable(): array {
        $s = self::settings();
        return array(
            'allowlist'               => (string) $s['allowlist'],
            'blocklist'               => (string) $s['blocklist'],
            'path_blocklist'          => (string) $s['path_blocklist'],
            'request_allowlist'        => (string) $s['request_allowlist'],
            'login_allowlist_enabled' => (int) ! empty( $s['login_allowlist_enabled'] ),
            'login_allowlist'         => (string) $s['login_allowlist'],
            'login_honeypot'          => (int) ! empty( $s['login_honeypot'] ),
            'registration_approval'   => (int) ! empty( $s['registration_approval'] ),
        );
    }

    private static function ip_in_text( string $ip, string $text ): bool {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;
        foreach ( preg_split( '/[\r\n,]+/', $text ) ?: array() as $entry ) {
            $entry = trim( $entry );
            if ( '' === $entry ) continue;
            if ( $ip === $entry || ( false !== strpos( $entry, '/' ) && self::cidr_match( $ip, $entry ) ) ) return true;
        }
        return false;
    }

    private static function cidr_match( string $ip, string $cidr ): bool {
        list( $subnet, $mask ) = array_pad( explode( '/', $cidr, 2 ), 2, null );
        $ip_bin = @inet_pton( $ip );
        $subnet_bin = @inet_pton( (string) $subnet );
        if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) return false;
        $bits = (int) $mask;
        $max = 8 * strlen( $ip_bin );
        if ( $bits < 0 || $bits > $max ) return false;
        $bytes = intdiv( $bits, 8 );
        $rem = $bits % 8;
        if ( $bytes && substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) return false;
        if ( $rem ) {
            $m = ( 0xFF << ( 8 - $rem ) ) & 0xFF;
            if ( ( ord( $ip_bin[$bytes] ) & $m ) !== ( ord( $subnet_bin[$bytes] ) & $m ) ) return false;
        }
        return true;
    }
}
