<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Private WordPress core-login entry.
 *
 * The private alias serves WordPress' native login handler under the alias itself.
 * Core files are not renamed and authenticated /wp-admin/ remains native. A TEST
 * mode exists so administrators can prove the alias before hiding the standard
 * unauthenticated wp-login.php/wp-admin entry surfaces.
 */
final class YSEC_Private_Login {
    private static bool $defer_not_found = false;

    public static function boot(): void {
        add_action( 'init', array( __CLASS__, 'intercept' ), -900 );
        add_action( 'init', array( __CLASS__, 'render_deferred_not_found' ), PHP_INT_MAX );
        add_filter( 'login_url', array( __CLASS__, 'filter_login_url' ), 20, 3 );
        add_filter( 'site_url', array( __CLASS__, 'filter_site_url' ), 20, 4 );
        add_filter( 'network_site_url', array( __CLASS__, 'filter_network_site_url' ), 20, 3 );
    }

    public static function mode(): string {
        $mode = sanitize_key( (string) YSEC_Utils::option( 'private_login_mode', '' ) );
        if ( in_array( $mode, array( 'off', 'test', 'enforce' ), true ) ) return $mode;
        // Safe migration from 2.18 and older: an existing enabled private entry
        // upgrades to TEST first, never directly to lockout-capable enforcement.
        return YSEC_Utils::option( 'private_login_enabled', 0 ) ? 'test' : 'off';
    }

    public static function configured(): bool {
        return 'off' !== self::mode();
    }

    public static function aliases_active(): bool {
        if ( ! self::configured() ) return false;
        if ( defined( 'YSEC_PRIVATE_LOGIN_DISABLE' ) && YSEC_PRIVATE_LOGIN_DISABLE ) return false;
        if ( ! self::pretty_permalinks() ) return false;
        return ! self::external_path_owner_active();
    }

    public static function enforcing(): bool {
        return self::aliases_active() && 'enforce' === self::mode();
    }

    public static function testing(): bool {
        return self::aliases_active() && 'test' === self::mode();
    }

    public static function pretty_permalinks(): bool {
        return '' !== (string) get_option( 'permalink_structure', '' );
    }

    public static function external_path_owner_active(): bool {
        $target = 'hide-my-wp/index.php';
        $active = get_option( 'active_plugins', array() );
        if ( is_array( $active ) && in_array( $target, $active, true ) ) return true;
        if ( is_multisite() ) {
            $network = get_site_option( 'active_sitewide_plugins', array() );
            if ( is_array( $network ) && isset( $network[ $target ] ) ) return true;
        }
        return false;
    }

    public static function status(): array {
        $configured = self::configured();
        $owner = self::external_path_owner_active();
        $disabled = defined( 'YSEC_PRIVATE_LOGIN_DISABLE' ) && YSEC_PRIVATE_LOGIN_DISABLE;
        if ( ! $configured ) {
            $state = 'off';
        } elseif ( $disabled ) {
            $state = 'recovery_disabled';
        } elseif ( ! self::pretty_permalinks() ) {
            $state = 'permalink_required';
        } elseif ( $owner ) {
            $state = 'standby';
        } else {
            $state = 'enforce' === self::mode() ? 'active' : 'test';
        }
        return array(
            'configured' => $configured,
            'enforcing'  => self::enforcing(),
            'testing'    => self::testing(),
            'mode'       => self::mode(),
            'state'      => $state,
            'login_url'  => self::private_login_url(),
            'admin_url'  => self::private_admin_url(),
        );
    }

    public static function sanitize_slug( string $value, string $kind = 'login' ): string {
        $value = strtolower( sanitize_title_with_dashes( trim( $value, " \t\n\r\0\x0B/" ) ) );
        if ( '' === $value && 'admin' === $kind ) return '';
        $reserved = array( 'wp-admin','wp-login','wp-login.php','login','login.php','admin','administrator','dashboard','wp-json','wp-content','wp-includes','xmlrpc.php' );
        if ( strlen( $value ) < 8 || strlen( $value ) > 64 || in_array( $value, $reserved, true ) ) return '';
        if ( str_starts_with( $value, 'wp-' ) ) return '';
        return $value;
    }

    public static function generate_slug( string $kind = 'login' ): string {
        $prefix = 'admin' === $kind ? 'office-' : 'gate-';
        return $prefix . strtolower( wp_generate_password( 22, false, false ) );
    }

    public static function private_login_url( string $redirect = '', bool $force_reauth = false ): string {
        $slug = (string) YSEC_Utils::option( 'private_login_slug', '' );
        if ( '' === $slug ) return self::core_login_url();
        $url = trailingslashit( site_url( '/' . rawurlencode( $slug ), 'login' ) );
        if ( '' !== $redirect ) $url = add_query_arg( 'redirect_to', $redirect, $url );
        if ( $force_reauth ) $url = add_query_arg( 'reauth', '1', $url );
        return $url;
    }

    public static function private_admin_url(): string {
        $slug = (string) YSEC_Utils::option( 'private_admin_slug', '' );
        if ( '' === $slug ) return '';
        return trailingslashit( site_url( '/' . rawurlencode( $slug ), 'admin' ) );
    }

    public static function filter_login_url( string $login_url, string $redirect, bool $force_reauth ): string {
        // TEST must not silently rewrite WordPress-generated standard login URLs.
        // It exists to prove the secret alias while the ordinary core login remains observable.
        if ( ! self::enforcing() ) return $login_url;
        return self::private_login_url( $redirect, $force_reauth );
    }

    public static function filter_site_url( string $url, string $path, ?string $scheme, ?int $blog_id ): string {
        if ( ! self::enforcing() ) return $url;
        return self::rewrite_core_login_path( $url, $path );
    }

    public static function filter_network_site_url( string $url, string $path, ?string $scheme ): string {
        if ( ! self::enforcing() ) return $url;
        return self::rewrite_core_login_path( $url, $path );
    }

    private static function rewrite_core_login_path( string $url, string $path ): string {
        $path = ltrim( $path, '/' );
        if ( ! str_starts_with( $path, 'wp-login.php' ) ) return $url;
        $query = wp_parse_url( $url, PHP_URL_QUERY );
        $target = self::private_login_url();
        if ( is_string( $query ) && '' !== $query ) {
            $args = array();
            wp_parse_str( $query, $args );
            if ( is_array( $args ) ) $target = add_query_arg( map_deep( $args, 'sanitize_text_field' ), $target );
        }
        return $target;
    }

    public static function intercept(): void {
        if ( ! self::aliases_active() && ! self::enforcing() ) return;
        $relative = self::relative_request_path();
        if ( '' === $relative ) return;

        $login_slug = trim( (string) YSEC_Utils::option( 'private_login_slug', '' ), '/' );
        $admin_slug = trim( (string) YSEC_Utils::option( 'private_admin_slug', '' ), '/' );

        if ( '' !== $login_slug && self::same_path( $relative, $login_slug ) ) {
            self::serve_core_login( self::safe_query_args() );
        }

        if ( '' !== $admin_slug && self::same_path( $relative, $admin_slug ) ) {
            if ( is_user_logged_in() ) {
                wp_safe_redirect( admin_url(), 302, 'Yablonsky Security' );
                exit;
            }
            $args = self::safe_query_args();
            $args['redirect_to'] = admin_url();
            self::serve_core_login( $args );
        }

        // A direct unauthenticated wp-admin request must never reveal the private
        // alias. In both TEST and ENFORCE it returns a real 404. Prepare a public
        // screen context now, but render only at the end of init so other normal
        // front-end/theme setup callbacks can finish before the native 404 loads.
        if ( ! is_user_logged_in() && self::is_private_admin_request( $relative ) ) {
            self::prepare_public_404_context();
            self::$defer_not_found = true;
            return;
        }

        // TEST proves that the aliases work while standard wp-login.php remains
        // available. ENFORCE additionally closes the unauthenticated core login.
        if ( ! self::enforcing() ) return;

        if ( self::is_core_login_request( $relative ) ) {
            // Existing password-reset/recovery links remain usable as a lockout-safe
            // exception; normal GET/POST login attempts receive a neutral 404.
            if ( self::is_tokenized_recovery_request() || self::is_safe_core_login_action() ) return;
            self::$defer_not_found = true;
            return;
        }

        if ( in_array( strtolower( trim( $relative, '/' ) ), array( 'login', 'login.php' ), true ) ) {
            self::$defer_not_found = true;
            return;
        }
    }

    private static function serve_core_login( array $query ): void {
        foreach ( $query as $key => $value ) {
            if ( ! is_scalar( $value ) ) continue;
            $safe_key = sanitize_key( (string) $key );
            if ( '' === $safe_key ) continue;
            $safe_value = sanitize_text_field( (string) $value );
            $_GET[ $safe_key ] = $safe_value;
            $_REQUEST[ $safe_key ] = $safe_value;
        }
        global $pagenow;
        $pagenow = 'wp-login.php';

        /*
         * wp-login.php normally executes as a top-level entry script. Serving it
         * from this method means included variables live in this method scope.
         * Core references $error on some login paths without assigning it first,
         * so initialize the same local variable explicitly before the include.
         */
        $error = '';
        require ABSPATH . 'wp-login.php';
        exit;
    }

    private static function is_core_login_request( string $relative ): bool {
        return 'wp-login.php' === strtolower( trim( $relative, '/' ) );
    }

    private static function is_private_admin_request( string $relative ): bool {
        $relative = strtolower( trim( $relative, '/' ) );
        if ( 'wp-admin' === $relative || 'wp-admin/index.php' === $relative ) return true;
        if ( ! str_starts_with( $relative, 'wp-admin/' ) ) return false;
        $file = basename( $relative );
        return ! in_array( $file, array( 'admin-ajax.php','admin-post.php','load-scripts.php','load-styles.php','async-upload.php','authorize-application.php' ), true );
    }

    private static function is_safe_core_login_action(): bool {
        $action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing classification before core validates the action.
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        if ( 'POST' === $method && 'postpass' === $action ) return true;
        if ( is_user_logged_in() && in_array( $action, array( 'logout','confirm_admin_email' ), true ) ) return true;
        return false;
    }

    private static function is_tokenized_recovery_request(): bool {
        $action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing classification before core login handler validates its own recovery tokens.
        if ( in_array( $action, array( 'rp','resetpass' ), true ) ) {
            $key = isset( $_REQUEST['key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Core validates the reset key after routing.
            return '' !== $key;
        }
        if ( 'enter_recovery_mode' === $action ) {
            $key = isset( $_REQUEST['rm_key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['rm_key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Core validates recovery mode credentials.
            return '' !== $key;
        }
        if ( 'confirmaction' === $action ) {
            $key = isset( $_REQUEST['key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Core validates the confirmation token.
            return '' !== $key;
        }
        return false;
    }

    private static function relative_request_path(): string {
        $request = isset( $_SERVER['REQUEST_URI'] ) ? YSEC_Utils::normalize_path( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) ) : '/';
        $site_path = wp_parse_url( site_url( '/' ), PHP_URL_PATH );
        $site_path = is_string( $site_path ) ? '/' . trim( $site_path, '/' ) : '';
        if ( '/' === $site_path ) $site_path = '';
        if ( '' !== $site_path && str_starts_with( $request, $site_path . '/' ) ) $request = substr( $request, strlen( $site_path ) );
        return trim( $request, '/' );
    }

    private static function same_path( string $relative, string $slug ): bool {
        return strtolower( trim( $relative, '/' ) ) === strtolower( trim( $slug, '/' ) );
    }

    private static function safe_query_args(): array {
        $args = array();
        foreach ( array( 'action','redirect_to','reauth','interim-login','checkemail','key','login','wp_lang','loggedout','request_id','rm_token','rm_key' ) as $key ) {
            if ( ! isset( $_GET[ $key ] ) || ! is_scalar( $_GET[ $key ] ) ) continue; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only route forwarding; core login validates action-specific values.
            $args[ $key ] = sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- See above.
        }
        return $args;
    }

    private static function core_login_url(): string {
        $base = trailingslashit( (string) get_option( 'siteurl', '' ) ) . 'wp-login.php';
        return set_url_scheme( $base, 'login' );
    }

    public static function render_deferred_not_found(): void {
        if ( ! self::$defer_not_found ) return;
        self::not_found();
    }

    private static function prepare_public_404_context(): void {
        global $pagenow;

        /*
         * /wp-admin/ enters WordPress through the administrative bootstrap.
         * The active theme's 404 still needs front-end semantics, otherwise
         * front-end CSS/hooks can be skipped and accessibility helpers such as
         * the skip link can become visibly unstyled. Current screen is the
         * canonical WordPress mechanism used by is_admin(); WP_ADMIN itself is
         * intentionally not redefined.
         */
        if ( is_admin() ) {
            if ( ! class_exists( 'WP_Screen' ) ) {
                $screen_file = ABSPATH . 'wp-admin/includes/class-wp-screen.php';
                if ( is_readable( $screen_file ) ) require_once $screen_file;
            }
            if ( class_exists( 'WP_Screen' ) ) $GLOBALS['current_screen'] = WP_Screen::get( 'front' );
            $pagenow = 'index.php';
        }
        if ( function_exists( 'show_admin_bar' ) ) show_admin_bar( false );
    }

    private static function not_found(): void {
        global $wp_query, $wp_the_query;

        self::prepare_public_404_context();

        if ( ! ( $wp_query instanceof WP_Query ) ) {
            $wp_query = new WP_Query();
        }
        $wp_query->set_404();
        $wp_the_query = $wp_query;

        status_header( 404 );
        nocache_headers();
        header( 'X-Robots-Tag: noindex, nofollow, noarchive', true );

        $template = get_404_template();
        if ( ! $template ) {
            $template = get_index_template();
        }
        if ( $template ) {
            load_template( $template );
            exit;
        }

        // Defensive fallback for a broken/incomplete theme only.
        wp_die(
            esc_html__( 'Page not found.', 'yablonsky-security' ),
            esc_html__( 'Page Not Found', 'yablonsky-security' ),
            array( 'response' => 404 )
        );
    }}
