<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Security Headers Control Plane.
 *
 * Baseline headers remain conservative. CSP is opt-in and moves through
 * discovery/report-only before human-approved enforcement. Unknown origins are
 * never auto-authorized merely because they were observed.
 */
final class YSEC_Security_Headers {
    private const POLICY_OPTION = 'ysec_security_headers_policy';
    private const DISCOVERY_OPTION = 'ysec_csp_discovery';
    private const DECISIONS_OPTION = 'ysec_csp_discovery_decisions';
    private const MAX_DISCOVERY = 250;
    private const MAX_BODY_BYTES = 32768;
    private const MAX_CSP_HEADER_BYTES = 7000;
    private const MAX_APPROVED_SOURCES = 100;

    public static function boot(): void {
        add_action( 'send_headers', array( __CLASS__, 'send_headers' ), 100 );
        add_action( 'rest_api_init', array( __CLASS__, 'register_rest' ) );
        add_action( 'wp_footer', array( __CLASS__, 'capture_runtime_sources' ), PHP_INT_MAX );
    }

    public static function defaults(): array {
        return array(
            'csp_mode'                 => 'off',
            'csp_known_services'       => array(),
            'csp_custom_sources'       => '',
            'csp_approved_sources'     => array(),
            'csp_allow_inline_styles'  => 1,
            'csp_allow_inline_scripts' => 0,
            'csp_allow_eval'           => 0,
            'csp_upgrade_insecure'     => 0,
            'csp_use_raw'              => 0,
            'csp_raw_policy'           => '',
            'hsts_enabled'             => 0,
            'hsts_max_age'             => 15552000,
            'hsts_include_subdomains'  => 0,
            'hsts_preload'             => 0,
        );
    }

    public static function policy(): array {
        $stored = get_option( self::POLICY_OPTION, array() );
        return wp_parse_args( is_array( $stored ) ? $stored : array(), self::defaults() );
    }

    public static function known_services(): array {
        return array(
            'youtube' => array(
                'label' => 'YouTube',
                'patterns' => array( 'youtube.com', 'www.youtube.com', 'youtube-nocookie.com', 'www.youtube-nocookie.com', 'i.ytimg.com' ),
                'directives' => array(
                    'frame-src' => array( 'https://www.youtube.com', 'https://www.youtube-nocookie.com' ),
                    'img-src'   => array( 'https://i.ytimg.com' ),
                ),
            ),
            'vimeo' => array(
                'label' => 'Vimeo',
                'patterns' => array( 'player.vimeo.com', 'i.vimeocdn.com' ),
                'directives' => array(
                    'frame-src' => array( 'https://player.vimeo.com' ),
                    'img-src'   => array( 'https://i.vimeocdn.com' ),
                ),
            ),
            'google_fonts' => array(
                'label' => 'Google Fonts',
                'patterns' => array( 'fonts.googleapis.com', 'fonts.gstatic.com' ),
                'directives' => array(
                    'style-src' => array( 'https://fonts.googleapis.com' ),
                    'font-src'  => array( 'https://fonts.gstatic.com' ),
                ),
            ),
            'google_measurement' => array(
                'label' => 'Google Tag Manager / Analytics',
                'patterns' => array( 'www.googletagmanager.com', 'www.google-analytics.com', 'region1.google-analytics.com' ),
                'directives' => array(
                    'script-src'  => array( 'https://www.googletagmanager.com' ),
                    'connect-src' => array( 'https://www.googletagmanager.com', 'https://www.google-analytics.com', 'https://region1.google-analytics.com' ),
                    'img-src'     => array( 'https://www.google-analytics.com' ),
                ),
            ),
            'turnstile' => array(
                'label' => 'Cloudflare Turnstile',
                'patterns' => array( 'challenges.cloudflare.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- CSP allowlist metadata only; YSec does not load this remote resource.
                'directives' => array(
                    'script-src'  => array( 'https://challenges.cloudflare.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- CSP allowlist metadata only; YSec does not load this remote resource.
                    'frame-src'   => array( 'https://challenges.cloudflare.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- CSP allowlist metadata only; YSec does not load this remote resource.
                    'connect-src' => array( 'https://challenges.cloudflare.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- CSP allowlist metadata only; YSec does not load this remote resource.
                ),
            ),
            'recaptcha' => array(
                'label' => 'Google reCAPTCHA',
                'patterns' => array( 'www.google.com', 'www.gstatic.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- CSP allowlist metadata only; YSec does not load this remote resource.
                'directives' => array(
                    'script-src'  => array( 'https://www.google.com', 'https://www.gstatic.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- CSP allowlist metadata only; YSec does not load this remote resource.
                    'frame-src'   => array( 'https://www.google.com' ),
                    'connect-src' => array( 'https://www.google.com' ),
                ),
            ),
            'stripe' => array(
                'label' => 'Stripe',
                'patterns' => array( 'js.stripe.com', 'api.stripe.com', 'm.stripe.com', 'hooks.stripe.com' ),
                'directives' => array(
                    'script-src'  => array( 'https://js.stripe.com' ),
                    'frame-src'   => array( 'https://js.stripe.com', 'https://hooks.stripe.com' ),
                    'connect-src' => array( 'https://api.stripe.com', 'https://m.stripe.com' ),
                ),
            ),
            'paypal' => array(
                'label' => 'PayPal',
                'patterns' => array( 'www.paypal.com', 'www.paypalobjects.com' ),
                'directives' => array(
                    'script-src'  => array( 'https://www.paypal.com', 'https://www.paypalobjects.com' ),
                    'frame-src'   => array( 'https://www.paypal.com' ),
                    'connect-src' => array( 'https://www.paypal.com' ),
                    'img-src'     => array( 'https://www.paypalobjects.com' ),
                ),
            ),
            'meta_widgets' => array(
                'label' => 'Facebook / Instagram widgets',
                'patterns' => array( 'www.facebook.com', 'connect.facebook.net', 'www.instagram.com' ),
                'directives' => array(
                    'script-src' => array( 'https://connect.facebook.net', 'https://www.instagram.com' ),
                    'frame-src'  => array( 'https://www.facebook.com', 'https://www.instagram.com' ),
                    'img-src'    => array( 'https://www.facebook.com', 'https://www.instagram.com' ),
                ),
            ),
            'tawk' => array(
                'label' => 'Tawk.to',
                'patterns' => array( 'embed.tawk.to', '*.tawk.to' ),
                'directives' => array(
                    'script-src'  => array( 'https://embed.tawk.to' ),
                    'style-src'   => array( 'https://embed.tawk.to', 'https://*.tawk.to' ),
                    'font-src'    => array( 'https://*.tawk.to' ),
                    'img-src'     => array( 'https://*.tawk.to' ),
                    'frame-src'   => array( 'https://*.tawk.to' ),
                    'connect-src' => array( 'https://*.tawk.to', 'wss://*.tawk.to' ),
                ),
            ),
        );
    }

    public static function sanitize_policy( array $input ) {
        $out = self::policy();
        $mode = sanitize_key( (string) ( $input['csp_mode'] ?? 'off' ) );
        $out['csp_mode'] = in_array( $mode, array( 'off', 'report_only', 'enforce' ), true ) ? $mode : 'off';

        $catalog = self::known_services();
        $selected = array();
        $raw_services = isset( $input['csp_known_services'] ) && is_array( $input['csp_known_services'] ) ? $input['csp_known_services'] : array();
        foreach ( $raw_services as $service ) {
            $service = sanitize_key( (string) $service );
            if ( isset( $catalog[ $service ] ) ) $selected[] = $service;
        }
        $out['csp_known_services'] = array_values( array_unique( $selected ) );

        $out['csp_custom_sources'] = self::sanitize_custom_sources_text( (string) ( $input['csp_custom_sources'] ?? '' ) );
        $approved = array();
        $approved_input = isset( $input['csp_approved_sources'] ) && is_array( $input['csp_approved_sources'] ) ? $input['csp_approved_sources'] : (array) ( $out['csp_approved_sources'] ?? array() );
        foreach ( $approved_input as $hash => $entry ) {
            if ( ! is_array( $entry ) ) continue;
            $directive = sanitize_key( (string) ( $entry['directive'] ?? '' ) );
            $source = (string) ( $entry['source'] ?? '' );
            $origin = (string) ( $entry['origin'] ?? '' );
            if ( ! preg_match( '/^[a-f0-9]{64}$/', (string) $hash ) || ! isset( self::allowed_directives()[ $directive ] ) || ! self::valid_source_expression( $directive, $source ) ) continue;
            $approved[ (string) $hash ] = array( 'directive'=>$directive, 'source'=>$source, 'origin'=>$origin );
        }
        $out['csp_approved_sources'] = $approved;
        $out['csp_allow_inline_styles'] = empty( $input['csp_allow_inline_styles'] ) ? 0 : 1;
        $out['csp_allow_inline_scripts'] = empty( $input['csp_allow_inline_scripts'] ) ? 0 : 1;
        $out['csp_allow_eval'] = empty( $input['csp_allow_eval'] ) ? 0 : 1;
        $out['csp_upgrade_insecure'] = empty( $input['csp_upgrade_insecure'] ) ? 0 : 1;
        $out['csp_use_raw'] = empty( $input['csp_use_raw'] ) ? 0 : 1;
        $raw_policy = trim( (string) ( $input['csp_raw_policy'] ?? '' ) );
        if ( strlen( $raw_policy ) > 12000 ) return new WP_Error( 'ysec_csp_policy_too_large', __( 'The advanced CSP policy is too large.', 'yablonsky-security' ) );
        if ( '' !== $raw_policy ) {
            $validated = self::validate_raw_policy( $raw_policy );
            if ( is_wp_error( $validated ) ) return $validated;
            $raw_policy = $validated;
        }
        $out['csp_raw_policy'] = $raw_policy;

        $out['hsts_enabled'] = empty( $input['hsts_enabled'] ) ? 0 : 1;
        $out['hsts_max_age'] = max( 300, min( 63072000, absint( $input['hsts_max_age'] ?? 15552000 ) ) );
        $out['hsts_include_subdomains'] = empty( $input['hsts_include_subdomains'] ) ? 0 : 1;
        $out['hsts_preload'] = empty( $input['hsts_preload'] ) ? 0 : 1;
        if ( $out['hsts_preload'] ) {
            $out['hsts_include_subdomains'] = 1;
            $out['hsts_max_age'] = max( 31536000, $out['hsts_max_age'] );
        }
        if ( strlen( self::build_policy( $out ) ) > self::MAX_CSP_HEADER_BYTES ) return new WP_Error( 'ysec_csp_header_too_large', __( 'The generated CSP header is too large. Reduce custom or approved sources before saving.', 'yablonsky-security' ) );
        return $out;
    }

    public static function validate_raw_policy( string $policy ) {
        if ( preg_match( '/[\r\n]/', $policy ) ) return new WP_Error( 'ysec_csp_header_injection', __( 'The CSP policy must not contain line breaks.', 'yablonsky-security' ) );
        $allowed = self::allowed_directives();
        $parts = array_filter( array_map( 'trim', explode( ';', $policy ) ) );
        $clean = array();
        foreach ( $parts as $part ) {
            $tokens = preg_split( '/\s+/', trim( $part ) );
            if ( ! is_array( $tokens ) || empty( $tokens ) ) continue;
            $directive = strtolower( array_shift( $tokens ) );
            if ( ! isset( $allowed[ $directive ] ) ) {
                /* translators: %s: CSP directive name. */
                return new WP_Error( 'ysec_csp_unknown_directive', sprintf( __( 'Unsupported CSP directive: %s', 'yablonsky-security' ), $directive ) );
            }
            $values = array();
            foreach ( $tokens as $token ) {
                if ( ! self::valid_source_expression( $directive, $token ) ) {
                    /* translators: 1: invalid CSP source expression, 2: CSP directive. */
                    return new WP_Error( 'ysec_csp_invalid_source', sprintf( __( 'Invalid CSP source expression “%1$s” in %2$s.', 'yablonsky-security' ), $token, $directive ) );
                }
                $values[] = $token;
            }
            if ( ! empty( $values ) ) $clean[] = $directive . ' ' . implode( ' ', array_values( array_unique( $values ) ) );
            else $clean[] = $directive;
        }
        return implode( '; ', $clean );
    }

    public static function build_policy( ?array $policy = null ): string {
        $policy = is_array( $policy ) ? wp_parse_args( $policy, self::defaults() ) : self::policy();
        if ( ! empty( $policy['csp_use_raw'] ) && '' !== trim( (string) $policy['csp_raw_policy'] ) ) {
            $raw = self::validate_raw_policy( (string) $policy['csp_raw_policy'] );
            if ( ! is_wp_error( $raw ) ) return self::ensure_reporting_directive( $raw );
        }
        $directives = self::guided_directives( $policy );
        $chunks = array();
        foreach ( $directives as $directive => $sources ) {
            if ( is_int( $directive ) ) continue;
            if ( true === $sources ) {
                $chunks[] = $directive;
                continue;
            }
            $sources = array_values( array_unique( array_filter( array_map( 'strval', (array) $sources ) ) ) );
            if ( empty( $sources ) ) continue;
            $chunks[] = $directive . ' ' . implode( ' ', $sources );
        }
        return self::ensure_reporting_directive( implode( '; ', $chunks ) );
    }

    public static function summary(): array {
        $policy = self::policy();
        $readiness = self::readiness( $policy );
        return array(
            'baseline_enabled' => (bool) YSEC_Utils::option( 'security_headers', 1 ),
            'mode'             => (string) $policy['csp_mode'],
            'policy'           => self::build_policy( $policy ),
            'hsts_enabled'     => ! empty( $policy['hsts_enabled'] ),
            'readiness'        => $readiness,
            'report_only_since'=> (string) get_option( 'ysec_csp_report_only_since', '' ),
        );
    }

    public static function readiness( ?array $policy = null ): array {
        $policy = is_array( $policy ) ? wp_parse_args( $policy, self::defaults() ) : self::policy();
        $items = self::discovery();
        $decisions = self::decisions();
        $unresolved = 0;
        $approved = 0;
        $blocked = 0;
        $ignored = 0;
        $known = 0;
        $reports = 0;
        foreach ( $items as $hash => $item ) {
            $reports += absint( $item['count'] ?? 0 );
            if ( '' !== self::classify_service( (string) ( $item['origin'] ?? '' ) ) ) $known++;
            $decision = sanitize_key( (string) ( $decisions[ $hash ] ?? '' ) );
            if ( 'block' === $decision ) { $blocked++; continue; }
            if ( 'ignore' === $decision ) { $ignored++; continue; }
            if ( self::policy_allows_item( $policy, $item ) ) { $approved++; continue; }
            $unresolved++;
        }
        return array(
            'observed'   => count( $items ),
            'reports'    => $reports,
            'known'      => $known,
            'approved'   => $approved,
            'blocked'    => $blocked,
            'ignored'    => $ignored,
            'unresolved' => $unresolved,
            'ready'      => 0 === $unresolved,
        );
    }

    public static function discovery(): array {
        $stored = get_option( self::DISCOVERY_OPTION, array() );
        if ( ! is_array( $stored ) ) return array();
        uasort( $stored, static function ( array $a, array $b ): int {
            return strcmp( (string) ( $b['last_seen'] ?? '' ), (string) ( $a['last_seen'] ?? '' ) );
        } );
        return $stored;
    }

    public static function decisions(): array {
        $stored = get_option( self::DECISIONS_OPTION, array() );
        return is_array( $stored ) ? $stored : array();
    }

    public static function set_decision( string $hash, string $decision ): bool {
        $items = self::discovery();
        if ( ! isset( $items[ $hash ] ) ) return false;
        $decision = sanitize_key( $decision );
        $decisions = self::decisions();
        $policy = self::policy();
        $approved = is_array( $policy['csp_approved_sources'] ?? null ) ? $policy['csp_approved_sources'] : array();
        if ( 'allow' === $decision ) {
            $directive = sanitize_key( (string) ( $items[ $hash ]['directive'] ?? '' ) );
            $origin = (string) ( $items[ $hash ]['origin'] ?? '' );
            $source = self::observed_origin_to_source( $directive, $origin );
            if ( '' === $source ) return false;
            if ( ! isset( $approved[ $hash ] ) && count( $approved ) >= self::MAX_APPROVED_SOURCES ) return false;
            $approved[ $hash ] = array( 'directive'=>$directive, 'source'=>$source, 'origin'=>$origin );
            $policy['csp_approved_sources'] = $approved;
            if ( strlen( self::build_policy( $policy ) ) > self::MAX_CSP_HEADER_BYTES ) return false;
            $decisions[ $hash ] = 'allow';
        } elseif ( in_array( $decision, array( 'block', 'ignore' ), true ) ) {
            unset( $approved[ $hash ] );
            $decisions[ $hash ] = $decision;
        } else {
            unset( $approved[ $hash ], $decisions[ $hash ] );
        }
        $policy['csp_approved_sources'] = $approved;
        update_option( self::POLICY_OPTION, $policy, false );
        update_option( self::DECISIONS_OPTION, $decisions, false );
        return true;
    }

    public static function remove_approved_source( string $hash ): bool {
        $policy = self::policy();
        $approved = is_array( $policy['csp_approved_sources'] ?? null ) ? $policy['csp_approved_sources'] : array();
        if ( ! isset( $approved[ $hash ] ) ) return false;
        unset( $approved[ $hash ] );
        $policy['csp_approved_sources'] = $approved;
        update_option( self::POLICY_OPTION, $policy, false );
        $decisions = self::decisions();
        unset( $decisions[ $hash ] );
        update_option( self::DECISIONS_OPTION, $decisions, false );
        return true;
    }

    public static function clear_discovery(): void {
        delete_option( self::DISCOVERY_OPTION );
        delete_option( self::DECISIONS_OPTION );
    }

    public static function export_bundle(): array {
        return array(
            'schema'       => 'yablonsky.security.headers-report.v1',
            'generated_at' => gmdate( 'c' ),
            'plugin'       => 'Yablonsky Security',
            'version'      => YSEC_VERSION,
            'baseline'     => array(
                'enabled' => (bool) YSEC_Utils::option( 'security_headers', 1 ),
                'headers' => self::baseline_header_map(),
            ),
            'policy'       => self::policy(),
            'summary'      => self::summary(),
            'discovery'    => self::discovery(),
            'decisions'    => self::decisions(),
        );
    }

    public static function send_headers(): void {
        if ( headers_sent() ) return;
        if ( YSEC_Utils::option( 'security_headers', 1 ) ) self::send_baseline_headers();

        $policy = self::policy();
        if ( ! empty( $policy['hsts_enabled'] ) && is_ssl() ) {
            $value = 'max-age=' . absint( $policy['hsts_max_age'] );
            if ( ! empty( $policy['hsts_include_subdomains'] ) ) $value .= '; includeSubDomains';
            if ( ! empty( $policy['hsts_preload'] ) ) $value .= '; preload';
            header( 'Strict-Transport-Security: ' . $value, true );
        }

        if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) return;
        $mode = (string) ( $policy['csp_mode'] ?? 'off' );
        if ( ! in_array( $mode, array( 'report_only', 'enforce' ), true ) ) return;
        $value = self::build_policy( $policy );
        if ( '' === $value ) return;
        $name = 'enforce' === $mode ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
        header( $name . ': ' . $value, true );
    }

    public static function send_baseline_headers(): void {
        foreach ( self::baseline_header_map() as $name => $value ) header( $name . ': ' . $value, true );
    }

    public static function baseline_header_map(): array {
        return array(
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy'        => 'strict-origin-when-cross-origin',
            'X-Frame-Options'        => 'SAMEORIGIN',
            'Permissions-Policy'     => 'geolocation=(), microphone=(), camera=()',
        );
    }

    public static function register_rest(): void {
        register_rest_route(
            'yablonsky-security/v1',
            '/csp-report',
            array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array( __CLASS__, 'receive_report' ),
                'permission_callback' => '__return_true',
            )
        );
    }

    public static function receive_report( WP_REST_Request $request ) {
        $policy = self::policy();
        if ( 'off' === (string) ( $policy['csp_mode'] ?? 'off' ) ) return new WP_REST_Response( null, 204 );
        $body = (string) $request->get_body();
        if ( strlen( $body ) > self::MAX_BODY_BYTES ) return new WP_Error( 'ysec_csp_report_too_large', __( 'CSP report payload is too large.', 'yablonsky-security' ), array( 'status'=>413 ) );
        if ( ! self::report_rate_allowed() ) return new WP_Error( 'ysec_csp_report_rate_limited', __( 'CSP report rate limit reached.', 'yablonsky-security' ), array( 'status'=>429 ) );
        $decoded = json_decode( $body, true );
        if ( ! is_array( $decoded ) ) return new WP_REST_Response( null, 204 );

        $reports = YSEC_Utils::is_list_array( $decoded ) ? $decoded : array( $decoded );
        foreach ( array_slice( $reports, 0, 20 ) as $report ) {
            if ( ! is_array( $report ) ) continue;
            $r = self::normalize_report( $report );
            if ( empty( $r['local_document'] ) || empty( $r['origin'] ) || empty( $r['directive'] ) ) continue;
            self::observe( $r['directive'], $r['origin'], 'browser_report', $r['disposition'] );
        }
        return new WP_REST_Response( null, 204 );
    }

    public static function capture_runtime_sources(): void {
        if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) return;
        $scripts = wp_scripts();
        if ( $scripts instanceof WP_Scripts ) {
            foreach ( (array) $scripts->queue as $handle ) {
                if ( empty( $scripts->registered[ $handle ] ) ) continue;
                $src = (string) $scripts->registered[ $handle ]->src;
                $origin = self::origin_from_url( $src );
                if ( '' !== $origin && "'self'" !== $origin ) self::observe( 'script-src', $origin, 'wordpress_enqueue', 'runtime' );
            }
        }
        $styles = wp_styles();
        if ( $styles instanceof WP_Styles ) {
            foreach ( (array) $styles->queue as $handle ) {
                if ( empty( $styles->registered[ $handle ] ) ) continue;
                $src = (string) $styles->registered[ $handle ]->src;
                $origin = self::origin_from_url( $src );
                if ( '' !== $origin && "'self'" !== $origin ) self::observe( 'style-src', $origin, 'wordpress_enqueue', 'runtime' );
            }
        }
    }

    public static function classify_service( string $origin ): string {
        $host = wp_parse_url( $origin, PHP_URL_HOST );
        $host = strtolower( (string) $host );
        if ( '' === $host ) return '';
        foreach ( self::known_services() as $key => $service ) {
            foreach ( (array) $service['patterns'] as $pattern ) {
                $pattern = strtolower( (string) $pattern );
                if ( str_starts_with( $pattern, '*.' ) ) {
                    $suffix = substr( $pattern, 1 );
                    if ( str_ends_with( $host, $suffix ) ) return $key;
                } elseif ( $host === $pattern || str_ends_with( $host, '.' . $pattern ) ) {
                    return $key;
                }
            }
        }
        return '';
    }

    private static function guided_directives( array $policy ): array {
        $d = array(
            'default-src'     => array( "'self'" ),
            'base-uri'        => array( "'self'" ),
            'object-src'      => array( "'none'" ),
            'frame-ancestors' => array( "'self'" ),
            'form-action'     => array( "'self'" ),
            'script-src'      => array( "'self'" ),
            'style-src'       => array( "'self'" ),
            'img-src'         => array( "'self'", 'data:', 'blob:' ),
            'font-src'        => array( "'self'", 'data:' ),
            'connect-src'     => array( "'self'" ),
            'frame-src'       => array( "'self'" ),
            'media-src'       => array( "'self'", 'blob:' ),
            'worker-src'      => array( "'self'", 'blob:' ),
            'manifest-src'    => array( "'self'" ),
        );
        if ( ! empty( $policy['csp_allow_inline_styles'] ) ) $d['style-src'][] = "'unsafe-inline'";
        if ( ! empty( $policy['csp_allow_inline_scripts'] ) ) $d['script-src'][] = "'unsafe-inline'";
        if ( ! empty( $policy['csp_allow_eval'] ) ) $d['script-src'][] = "'unsafe-eval'";

        $catalog = self::known_services();
        foreach ( (array) ( $policy['csp_known_services'] ?? array() ) as $key ) {
            if ( empty( $catalog[ $key ]['directives'] ) ) continue;
            foreach ( (array) $catalog[ $key ]['directives'] as $directive => $sources ) {
                if ( ! isset( $d[ $directive ] ) ) $d[ $directive ] = array();
                $d[ $directive ] = array_merge( $d[ $directive ], (array) $sources );
            }
        }

        foreach ( self::parse_custom_sources( (string) ( $policy['csp_custom_sources'] ?? '' ) ) as $directive => $sources ) {
            if ( ! isset( $d[ $directive ] ) ) $d[ $directive ] = array();
            $d[ $directive ] = array_merge( $d[ $directive ], $sources );
        }

        foreach ( (array) ( $policy['csp_approved_sources'] ?? array() ) as $entry ) {
            if ( ! is_array( $entry ) ) continue;
            $directive = sanitize_key( (string) ( $entry['directive'] ?? '' ) );
            $source = (string) ( $entry['source'] ?? '' );
            if ( ! isset( self::allowed_directives()[ $directive ] ) || ! self::valid_source_expression( $directive, $source ) ) continue;
            if ( ! isset( $d[ $directive ] ) ) $d[ $directive ] = array();
            $d[ $directive ][] = $source;
        }
        if ( ! empty( $policy['csp_upgrade_insecure'] ) ) $d['upgrade-insecure-requests'] = true;
        foreach ( $d as $directive => $sources ) {
            if ( true === $sources ) continue;
            $sources = array_values( array_unique( $sources ) );
            if ( in_array( "'none'", $sources, true ) && count( $sources ) > 1 ) $sources = array_values( array_diff( $sources, array( "'none'" ) ) );
            $d[ $directive ] = $sources;
        }
        return $d;
    }

    private static function ensure_reporting_directive( string $policy ): string {
        $policy = trim( $policy, " ;\t\n\r\0\x0B" );
        if ( preg_match( '/(?:^|;)\s*report-uri\s/i', $policy ) ) return $policy;
        $endpoint = rest_url( 'yablonsky-security/v1/csp-report' );
        return $policy . ( '' !== $policy ? '; ' : '' ) . 'report-uri ' . $endpoint;
    }

    private static function allowed_directives(): array {
        $names = array(
            'default-src','script-src','script-src-elem','script-src-attr','style-src','style-src-elem','style-src-attr','img-src','font-src','connect-src','media-src','object-src','frame-src','child-src','worker-src','manifest-src','form-action','frame-ancestors','base-uri','sandbox','upgrade-insecure-requests','block-all-mixed-content','report-uri','report-to','navigate-to','prefetch-src',
        );
        return array_fill_keys( $names, true );
    }

    private static function valid_source_expression( string $directive, string $token ): bool {
        $token = trim( $token );
        if ( '' === $token || preg_match( '/[\r\n;,]/', $token ) ) return false;
        if ( in_array( $directive, array( 'upgrade-insecure-requests', 'block-all-mixed-content' ), true ) ) return false;
        if ( 'sandbox' === $directive ) return (bool) preg_match( '/^allow-[a-z-]+$/', $token );
        if ( in_array( $token, array( "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'report-sample'", 'data:', 'blob:', 'https:', 'http:', 'wss:', 'ws:' ), true ) ) return true;
        if ( preg_match( "/^'(?:nonce-[A-Za-z0-9+\/_-]+=*|sha(?:256|384|512)-[A-Za-z0-9+\/_-]+=*)'$/", $token ) ) return true;
        if ( preg_match( '#^(?:https?|wss?)://(?:\*\.)?[A-Za-z0-9.-]+(?::\d{1,5})?$#', $token ) ) return true;
        if ( 'report-uri' === $directive && preg_match( '#^https?://#', $token ) ) return true;
        if ( 'report-to' === $directive && preg_match( '/^[A-Za-z0-9._-]+$/', $token ) ) return true;
        return false;
    }

    private static function sanitize_custom_sources_text( string $text ): string {
        $out = array();
        $text = substr( $text, 0, 12000 );
        $lines = array_slice( preg_split( '/\r\n|\r|\n/', $text ), 0, 100 );
        foreach ( $lines as $line ) {
            $line = trim( (string) $line );
            if ( '' === $line || str_starts_with( $line, '#' ) ) continue;
            $line = preg_replace( '/^([A-Za-z][A-Za-z0-9-]*)\s*:\s*/', '$1 ', $line, 1 );
            $tokens = preg_split( '/\s+/', $line );
            if ( ! is_array( $tokens ) || count( $tokens ) < 2 ) continue;
            $directive = sanitize_key( array_shift( $tokens ) );
            if ( ! isset( self::allowed_directives()[ $directive ] ) ) continue;
            $valid = array();
            foreach ( $tokens as $token ) if ( self::valid_source_expression( $directive, $token ) ) $valid[] = $token;
            if ( ! empty( $valid ) ) $out[] = $directive . ' ' . implode( ' ', array_values( array_unique( $valid ) ) );
        }
        return implode( "\n", array_values( array_unique( $out ) ) );
    }

    private static function parse_custom_sources( string $text ): array {
        $out = array();
        $clean = self::sanitize_custom_sources_text( $text );
        foreach ( preg_split( '/\r\n|\r|\n/', $clean ) as $line ) {
            $tokens = preg_split( '/\s+/', trim( (string) $line ) );
            if ( ! is_array( $tokens ) || count( $tokens ) < 2 ) continue;
            $directive = array_shift( $tokens );
            if ( ! isset( $out[ $directive ] ) ) $out[ $directive ] = array();
            $out[ $directive ] = array_merge( $out[ $directive ], $tokens );
        }
        return $out;
    }

    private static function normalize_report( array $report ): array {
        $outer_document = (string) ( $report['url'] ?? $report['documentURL'] ?? $report['document_url'] ?? '' );
        if ( isset( $report['csp-report'] ) && is_array( $report['csp-report'] ) ) $report = $report['csp-report'];
        if ( isset( $report['body'] ) && is_array( $report['body'] ) ) $report = $report['body'];
        $blocked = (string) ( $report['blocked-uri'] ?? $report['blockedURL'] ?? $report['blocked_url'] ?? '' );
        $document = (string) ( $report['document-uri'] ?? $report['documentURL'] ?? $report['document_url'] ?? $outer_document );
        $directive = (string) ( $report['effective-directive'] ?? $report['effectiveDirective'] ?? $report['violated-directive'] ?? $report['violatedDirective'] ?? '' );
        $directive = strtolower( trim( explode( ' ', $directive )[0] ?? '' ) );
        if ( ! isset( self::allowed_directives()[ $directive ] ) ) $directive = 'default-src';
        return array(
            'origin'         => self::origin_from_report_value( $blocked ),
            'directive'      => $directive,
            'disposition'    => sanitize_key( (string) ( $report['disposition'] ?? 'report' ) ),
            'local_document' => self::document_is_local( $document ),
        );
    }

    private static function document_is_local( string $url ): bool {
        $host = strtolower( (string) wp_parse_url( trim( $url ), PHP_URL_HOST ) );
        $home_host = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
        return '' !== $host && '' !== $home_host && $host === $home_host;
    }

    private static function origin_from_report_value( string $value ): string {
        $value = trim( $value );
        if ( '' === $value ) return '';
        $lower = strtolower( $value );
        if ( in_array( $lower, array( 'inline', 'eval', 'data', 'blob' ), true ) ) return $lower;
        return self::origin_from_url( $value );
    }

    private static function origin_from_url( string $url ): string {
        $url = trim( html_entity_decode( $url, ENT_QUOTES, 'UTF-8' ) );
        if ( '' === $url ) return '';
        if ( str_starts_with( $url, '//' ) ) $url = ( is_ssl() ? 'https:' : 'http:' ) . $url;
        if ( str_starts_with( $url, '/' ) || ! preg_match( '#^[a-z][a-z0-9+.-]*:#i', $url ) ) return "'self'";
        $scheme = strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) );
        if ( in_array( $scheme, array( 'data', 'blob' ), true ) ) return $scheme . ':';
        if ( ! in_array( $scheme, array( 'http', 'https', 'ws', 'wss' ), true ) ) return '';
        $host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
        if ( '' === $host ) return '';
        $port = absint( wp_parse_url( $url, PHP_URL_PORT ) );
        $origin = $scheme . '://' . $host;
        if ( $port && ! ( 80 === $port && 'http' === $scheme ) && ! ( 443 === $port && 'https' === $scheme ) && ! ( 443 === $port && 'wss' === $scheme ) ) $origin .= ':' . $port;
        $home_host = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
        if ( $host === $home_host ) return "'self'";
        return $origin;
    }

    private static function observe( string $directive, string $origin, string $source, string $disposition ): void {
        $directive = sanitize_key( $directive );
        $origin = trim( $origin );
        if ( '' === $directive || '' === $origin || "'self'" === $origin ) return;
        if ( ! self::valid_observed_origin( $origin ) ) return;
        $hash = hash( 'sha256', $directive . '|' . $origin );
        $items = get_option( self::DISCOVERY_OPTION, array() );
        if ( ! is_array( $items ) ) $items = array();
        $now = gmdate( 'c' );
        $item = isset( $items[ $hash ] ) && is_array( $items[ $hash ] ) ? $items[ $hash ] : array(
            'directive'  => $directive,
            'origin'     => $origin,
            'first_seen' => $now,
            'last_seen'  => $now,
            'count'      => 0,
            'sources'    => array(),
            'dispositions'=> array(),
        );
        $item['last_seen'] = $now;
        $item['count'] = absint( $item['count'] ?? 0 ) + 1;
        $item['sources'] = array_values( array_unique( array_merge( (array) ( $item['sources'] ?? array() ), array( sanitize_key( $source ) ) ) ) );
        $item['dispositions'] = array_values( array_unique( array_merge( (array) ( $item['dispositions'] ?? array() ), array( sanitize_key( $disposition ) ) ) ) );
        $items[ $hash ] = $item;
        if ( count( $items ) > self::MAX_DISCOVERY ) {
            uasort( $items, static function ( array $a, array $b ): int { return strcmp( (string) ( $b['last_seen'] ?? '' ), (string) ( $a['last_seen'] ?? '' ) ); } );
            $items = array_slice( $items, 0, self::MAX_DISCOVERY, true );
        }
        update_option( self::DISCOVERY_OPTION, $items, false );
    }

    private static function observed_origin_to_source( string $directive, string $origin ): string {
        if ( 'inline' === $origin ) {
            return in_array( $directive, array( 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr' ), true ) ? "'unsafe-inline'" : '';
        }
        if ( 'eval' === $origin ) return 'script-src' === $directive ? "'unsafe-eval'" : '';
        if ( 'data' === $origin ) return 'data:';
        if ( 'blob' === $origin ) return 'blob:';
        return self::valid_source_expression( $directive, $origin ) ? $origin : '';
    }

    private static function valid_observed_origin( string $origin ): bool {
        if ( in_array( $origin, array( 'inline', 'eval', 'data', 'blob' ), true ) ) return true;
        return (bool) preg_match( '#^(?:https?|wss?)://[A-Za-z0-9.*:-]+$#', $origin );
    }

    private static function policy_allows_item( array $policy, array $item ): bool {
        $directive = sanitize_key( (string) ( $item['directive'] ?? '' ) );
        $origin = (string) ( $item['origin'] ?? '' );
        if ( '' === $directive || '' === $origin ) return false;
        if ( ! empty( $policy['csp_use_raw'] ) && '' !== trim( (string) $policy['csp_raw_policy'] ) ) {
            return self::raw_policy_allows( (string) $policy['csp_raw_policy'], $directive, $origin );
        }
        $directives = self::guided_directives( $policy );
        $sources = self::directive_sources( $directives, $directive );
        return self::source_list_allows( $sources, $origin );
    }

    private static function raw_policy_allows( string $raw, string $directive, string $origin ): bool {
        $map = array();
        foreach ( array_filter( array_map( 'trim', explode( ';', $raw ) ) ) as $chunk ) {
            $tokens = preg_split( '/\s+/', $chunk );
            if ( ! is_array( $tokens ) || empty( $tokens ) ) continue;
            $name = sanitize_key( array_shift( $tokens ) );
            $map[ $name ] = $tokens;
        }
        $sources = self::directive_sources( $map, $directive );
        return self::source_list_allows( $sources, $origin );
    }

    private static function directive_sources( array $map, string $directive ): array {
        $chains = array(
            'script-src-elem' => array( 'script-src-elem', 'script-src', 'default-src' ),
            'script-src-attr' => array( 'script-src-attr', 'script-src', 'default-src' ),
            'style-src-elem'  => array( 'style-src-elem', 'style-src', 'default-src' ),
            'style-src-attr'  => array( 'style-src-attr', 'style-src', 'default-src' ),
            'worker-src'      => array( 'worker-src', 'child-src', 'script-src', 'default-src' ),
            'frame-src'       => array( 'frame-src', 'child-src', 'default-src' ),
            'child-src'       => array( 'child-src', 'default-src' ),
        );
        $chain = $chains[ $directive ] ?? array( $directive, 'default-src' );
        foreach ( $chain as $candidate ) {
            if ( isset( $map[ $candidate ] ) && true !== $map[ $candidate ] ) return (array) $map[ $candidate ];
        }
        return array();
    }

    private static function source_list_allows( array $sources, string $origin ): bool {
        if ( 'inline' === $origin ) return in_array( "'unsafe-inline'", $sources, true );
        if ( 'eval' === $origin ) return in_array( "'unsafe-eval'", $sources, true );
        if ( 'data' === $origin ) return in_array( 'data:', $sources, true );
        if ( 'blob' === $origin ) return in_array( 'blob:', $sources, true );
        $scheme = (string) wp_parse_url( $origin, PHP_URL_SCHEME );
        $host = strtolower( (string) wp_parse_url( $origin, PHP_URL_HOST ) );
        foreach ( $sources as $source ) {
            if ( $source === $origin ) return true;
            if ( ( 'https:' === $source && 'https' === $scheme ) || ( 'http:' === $source && 'http' === $scheme ) || ( 'wss:' === $source && 'wss' === $scheme ) || ( 'ws:' === $source && 'ws' === $scheme ) ) return true;
            if ( preg_match( '#^(https?|wss?)://\*\.([A-Za-z0-9.-]+)(?::\d{1,5})?$#', (string) $source, $m ) ) {
                if ( $scheme === $m[1] && ( $host === strtolower( $m[2] ) || str_ends_with( $host, '.' . strtolower( $m[2] ) ) ) ) return true;
            }
        }
        return false;
    }

    private static function report_rate_allowed(): bool {
        $ip = YSEC_Utils::client_ip();
        if ( '' === $ip ) return true;
        $key = 'ysec_csp_rl_' . substr( hash( 'sha256', $ip ), 0, 24 );
        $count = absint( get_transient( $key ) );
        if ( $count >= 60 ) return false;
        set_transient( $key, $count + 1, MINUTE_IN_SECONDS );
        return true;
    }
}
