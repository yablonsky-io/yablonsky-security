<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class YSEC_Captcha {
    private static array $verified = array();
    public static function boot(): void {
        add_action( 'login_form', array( __CLASS__, 'render_wp_login' ) );
        add_action( 'register_form', array( __CLASS__, 'render_wp_register' ) );
        add_action( 'lostpassword_form', array( __CLASS__, 'render_wp_recovery' ) );
        add_action( 'login_enqueue_scripts', array( __CLASS__, 'enqueue_login_style' ) );
        add_filter( 'authenticate', array( __CLASS__, 'validate_wp_login' ), 4, 3 );
        add_filter( 'registration_errors', array( __CLASS__, 'validate_wp_register' ), 10, 3 );
        add_action( 'lostpassword_post', array( __CLASS__, 'validate_wp_recovery' ), 10, 2 );
        add_action( 'woocommerce_login_form', array( __CLASS__, 'render_woo_login' ) );
        add_action( 'woocommerce_register_form', array( __CLASS__, 'render_woo_register' ) );
        add_action( 'woocommerce_lostpassword_form', array( __CLASS__, 'render_woo_recovery' ) );
        add_filter( 'woocommerce_process_login_errors', array( __CLASS__, 'validate_woo_login' ), 10, 3 );
        add_filter( 'woocommerce_registration_errors', array( __CLASS__, 'validate_woo_register' ), 10, 3 );
    }
    public static function configured(): bool {
        $provider = (string) YSEC_Utils::option( 'captcha_provider', 'none' );
        return in_array( $provider, array( 'turnstile', 'recaptcha' ), true ) && '' !== trim( (string) YSEC_Utils::option( 'captcha_site_key', '' ) ) && '' !== YSEC_Utils::decrypt( (string) YSEC_Utils::option( 'captcha_secret_key', '' ) );
    }
    private static function enabled( string $surface ): bool {
        return self::configured() && (bool) YSEC_Utils::option( 'captcha_' . $surface, 1 );
    }
    public static function render_wp_login(): void { self::render( 'wp_login' ); }
    public static function render_wp_register(): void { self::render( 'wp_register' ); }
    public static function render_wp_recovery(): void { self::render( 'wp_recovery' ); }
    public static function render_woo_login(): void { self::render( 'woo_login' ); }
    public static function render_woo_register(): void { self::render( 'woo_register' ); }
    public static function render_woo_recovery(): void { self::render( 'woo_recovery' ); }
    private static function render( string $surface ): void {
        if ( ! self::enabled( $surface ) ) return;
        $provider = (string) YSEC_Utils::option( 'captcha_provider', 'none' );
        $site_key = (string) YSEC_Utils::option( 'captcha_site_key', '' );
        if ( ! in_array( $provider, array( 'turnstile', 'recaptcha' ), true ) ) return;
        // Load only our local bootstrap through WordPress. The local bootstrap then loads the
        // administrator-selected provider runtime in the browser. This keeps plugin assets local
        // while preserving the provider-required challenge runtime and explicit external-service boundary.
        $asset_version = str_replace( '.', '-', YSEC_VERSION );
        wp_enqueue_script( 'ysec-captcha-loader', YSEC_URL . 'assets/captcha-loader-' . $asset_version . '.js', array(), YSEC_VERSION, true );
        $class = 'turnstile' === $provider ? 'cf-turnstile' : 'g-recaptcha';
        $surface_class = str_starts_with( $surface, 'wp_' ) ? 'ysec-captcha--wp' : 'ysec-captcha--commerce';
        // Cloudflare's flexible widget is useful inside WordPress' narrow native
        // login box, but it becomes visually oversized inside wide WooCommerce
        // account columns. Use Turnstile's normal 300px widget on commerce forms.
        $size = '';
        if ( 'turnstile' === $provider ) {
            $size = str_starts_with( $surface, 'wp_' ) ? ' data-size="flexible"' : ' data-size="normal"';
        }
        echo '<div class="' . esc_attr( $class ) . ' ysec-captcha ' . esc_attr( $surface_class ) . '" data-ysec-captcha-provider="' . esc_attr( $provider ) . '" data-sitekey="' . esc_attr( $site_key ) . '"' . $size . '></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $size is a fixed internal attribute fragment.
    }

    public static function enqueue_login_style(): void {
        if ( ! self::configured() ) return;
        $asset_version = str_replace( '.', '-', YSEC_VERSION );
        wp_enqueue_style( 'ysec-login-security', YSEC_URL . 'assets/login-security-' . $asset_version . '.css', array(), YSEC_VERSION );
    }
    public static function validate_wp_login( $user, $username, $password ) {
        if ( ! self::is_wp_login_request() || ! self::should_validate_post( 'wp_login' ) ) return $user;
        return self::verify( 'wp_login' ) ? $user : new WP_Error( 'ysec_captcha', __( 'Human verification failed. Please try again.', 'yablonsky-security' ) );
    }
    public static function validate_wp_register( WP_Error $errors, string $sanitized_user_login, string $user_email ): WP_Error {
        if ( self::should_validate_post( 'wp_register' ) && ! self::verify( 'wp_register' ) ) $errors->add( 'ysec_captcha', __( 'Human verification failed. Please try again.', 'yablonsky-security' ) );
        return $errors;
    }
    public static function validate_wp_recovery( WP_Error $errors, $user_data ): void {
        $surface = self::is_woo_request() ? 'woo_recovery' : 'wp_recovery';
        if ( self::should_validate_post( $surface ) && ! self::verify( $surface ) ) $errors->add( 'ysec_captcha', __( 'Human verification failed. Please try again.', 'yablonsky-security' ) );
    }
    public static function validate_woo_login( WP_Error $errors, string $username, string $password ): WP_Error {
        if ( self::should_validate_post( 'woo_login' ) && ! self::verify( 'woo_login' ) ) $errors->add( 'ysec_captcha', __( 'Human verification failed. Please try again.', 'yablonsky-security' ) );
        return $errors;
    }
    public static function validate_woo_register( WP_Error $errors, string $username, string $email ): WP_Error {
        if ( self::should_validate_post( 'woo_register' ) && ! self::verify( 'woo_register' ) ) $errors->add( 'ysec_captcha', __( 'Human verification failed. Please try again.', 'yablonsky-security' ) );
        return $errors;
    }
    private static function is_wp_login_request(): bool {
        global $pagenow;
        return 'wp-login.php' === (string) $pagenow;
    }
    private static function is_woo_request(): bool {
        if ( function_exists( 'is_account_page' ) && is_account_page() ) return true;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing -- Read-only routing hint only; WooCommerce validates its own form nonces before account actions.
        return isset( $_POST['woocommerce-login-nonce'] ) || isset( $_POST['woocommerce-register-nonce'] ) || isset( $_POST['wc_reset_password'] );
    }

    private static function should_validate_post( string $surface ): bool {
        if ( ! self::enabled( $surface ) || 'POST' !== strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) ) return false;
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) return false;
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) return false;
        if ( defined( 'WP_CLI' ) && WP_CLI ) return false;
        return true;
    }
    private static function verify( string $surface ): bool {
        if ( isset( self::$verified[$surface] ) ) return self::$verified[$surface];
        $provider = (string) YSEC_Utils::option( 'captcha_provider', 'none' );
        $field = 'turnstile' === $provider ? 'cf-turnstile-response' : 'g-recaptcha-response';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Provider token is validated remotely inside the authentication/registration/recovery submission flow.
        $token = isset( $_POST[$field] ) ? sanitize_text_field( wp_unslash( $_POST[$field] ) ) : '';
        if ( '' === $token ) return self::failure( $surface, 'missing_token' );
        $secret = YSEC_Utils::decrypt( (string) YSEC_Utils::option( 'captcha_secret_key', '' ) );
        // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- CAPTCHA verification is the documented substance of the explicitly configured third-party service.
        $endpoint = 'turnstile' === $provider ? 'https://challenges.cloudflare.com/turnstile/v0/siteverify' : 'https://www.google.com/recaptcha/api/siteverify';
        $body = array( 'secret' => $secret, 'response' => $token );
        $ip = YSEC_Utils::client_ip();
        if ( '' !== $ip ) $body['remoteip'] = $ip;
        $response = wp_safe_remote_post( $endpoint, array( 'timeout' => 8, 'redirection' => 0, 'body' => $body ) );
        if ( is_wp_error( $response ) ) return self::failure( $surface, 'provider_unavailable' );
        $decoded = json_decode( wp_remote_retrieve_body( $response ), true );
        $ok = is_array( $decoded ) && ! empty( $decoded['success'] );
        if ( ! $ok ) return self::failure( $surface, 'provider_rejected' );
        self::$verified[$surface] = true;
        YSEC_Events::log( 'captcha_verified', array( 'severity' => 'info', 'confidence' => 'high', 'state' => 'observed', 'family' => 'authentication', 'details' => array( 'surface' => $surface, 'provider' => $provider ) ) );
        return true;
    }
    private static function failure( string $surface, string $reason ): bool {
        self::$verified[$surface] = false;
        YSEC_Events::log( 'captcha_failed', array( 'severity' => 'medium', 'confidence' => 'high', 'state' => 'suspicious', 'family' => 'credential_attack', 'details' => array( 'surface' => $surface, 'provider' => (string) YSEC_Utils::option( 'captcha_provider', 'none' ), 'reason' => $reason ) ) );
        return false;
    }
}
