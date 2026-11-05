<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Country_Policy {
    public static function countries(): array {
        $raw = (string) YSEC_Utils::option( 'country_blocklist', '' );
        $parts = preg_split( '/[\s,;]+/', strtoupper( $raw ) ) ?: array();
        $out = array();
        foreach ( $parts as $code ) {
            $code = trim( $code );
            if ( preg_match( '/^[A-Z]{2}$/', $code ) ) $out[] = $code;
        }
        return array_slice( array_values( array_unique( $out ) ), 0, 100 );
    }

    public static function sanitize_list( string $raw ): string {
        $parts = preg_split( '/[\s,;]+/', strtoupper( $raw ) ) ?: array();
        $out = array();
        foreach ( $parts as $code ) {
            $code = trim( $code );
            if ( preg_match( '/^[A-Z]{2}$/', $code ) ) $out[] = $code;
        }
        return implode( "\n", array_slice( array_values( array_unique( $out ) ), 0, 100 ) );
    }

    public static function scope(): string {
        $scope = sanitize_key( (string) YSEC_Utils::option( 'country_block_scope', 'public' ) );
        return in_array( $scope, array( 'auth','public','all' ), true ) ? $scope : 'public';
    }

    public static function recovery_surface( string $uri ): bool {
        $path = strtolower( YSEC_Utils::normalize_path( $uri ) );
        if ( str_starts_with( $path, '/wp-json' ) || str_starts_with( $path, '/wp-cron.php' ) ) return true;
        if ( str_starts_with( $path, '/wp-admin/admin-ajax.php' ) || str_starts_with( $path, '/wp-admin/admin-post.php' ) ) return true;
        if ( '/wp-login.php' === $path ) {
            $action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing classification.
            $key = isset( $_REQUEST['key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Core validates the recovery token.
            $rm_key = isset( $_REQUEST['rm_key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['rm_key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Core validates recovery-mode credentials.
            if ( in_array( $action, array( 'rp','resetpass','confirmaction' ), true ) && '' !== $key ) return true;
            if ( 'enter_recovery_mode' === $action && '' !== $rm_key ) return true;
        }
        return false;
    }

    public static function auth_surface( string $uri ): bool {
        $path = strtolower( YSEC_Utils::normalize_path( $uri ) );
        $login_slug = strtolower( trim( (string) YSEC_Utils::option( 'private_login_slug', '' ), '/' ) );
        $admin_slug = strtolower( trim( (string) YSEC_Utils::option( 'private_admin_slug', '' ), '/' ) );
        $trimmed = trim( $path, '/' );
        if ( '/wp-login.php' === $path || '/wp-admin' === $path || str_starts_with( $path, '/wp-admin/' ) ) return true;
        if ( '' !== $login_slug && $trimmed === $login_slug ) return true;
        if ( '' !== $admin_slug && $trimmed === $admin_slug ) return true;
        if ( isset( $_POST['woocommerce-login-nonce'] ) || isset( $_POST['woocommerce-register-nonce'] ) || isset( $_POST['wc_reset_password'] ) ) return true; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Presence only; WooCommerce validates its own nonce.
        if ( function_exists( 'wc_get_page_permalink' ) ) {
            $my = wc_get_page_permalink( 'myaccount' );
            $my_path = is_string( $my ) ? strtolower( (string) wp_parse_url( $my, PHP_URL_PATH ) ) : '';
            if ( '' !== $my_path && ( $path === untrailingslashit( $my_path ) || str_starts_with( $path, trailingslashit( $my_path ) ) ) ) return true;
        }
        return false;
    }

    public static function match( string $uri ): string {
        if ( ! YSEC_Utils::option( 'country_block_enabled', 0 ) || self::recovery_surface( $uri ) ) return '';
        $country = YSEC_Utils::country_signal();
        if ( '' === $country || ! in_array( $country, self::countries(), true ) ) return '';
        $auth = self::auth_surface( $uri );
        $scope = self::scope();
        if ( 'auth' === $scope && ! $auth ) return '';
        if ( 'public' === $scope && $auth ) return '';
        return $country;
    }

    public static function status(): array {
        $countries = self::countries();
        return array(
            'enabled'   => (bool) YSEC_Utils::option( 'country_block_enabled', 0 ),
            'countries' => $countries,
            'count'     => count( $countries ),
            'scope'     => self::scope(),
            'source'    => 'cloudflare_trusted_peer',
        );
    }
}
