<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Passive technology exposure reduction.
 *
 * This deliberately avoids path rewriting/output-buffer URL mutation. Those
 * mechanisms can collide with cache/CDN/performance layers and must be proven
 * separately before becoming part of the default security surface.
 */
final class YSEC_Technology_Exposure {
    public static function boot(): void {
        if ( 'off' === self::mode() ) return;
        add_action( 'init', array( __CLASS__, 'apply_metadata_reduction' ), 99 );
        add_action( 'send_headers', array( __CLASS__, 'reduce_headers' ), 999 );
        if ( 'extended' === self::mode() ) {
            add_filter( 'script_loader_src', array( __CLASS__, 'strip_local_version_arg' ), 999 );
            add_filter( 'style_loader_src', array( __CLASS__, 'strip_local_version_arg' ), 999 );
        }
    }

    public static function mode(): string {
        $mode = sanitize_key( (string) YSEC_Utils::option( 'technology_exposure_mode', 'safe' ) );
        return in_array( $mode, array( 'off', 'safe', 'extended' ), true ) ? $mode : 'safe';
    }

    public static function apply_metadata_reduction(): void {
        remove_action( 'wp_head', 'wp_generator' );
        add_filter( 'the_generator', '__return_empty_string', PHP_INT_MAX );
        remove_action( 'wp_head', 'rsd_link' );
        remove_action( 'wp_head', 'wlwmanifest_link' );
        remove_action( 'wp_head', 'wp_shortlink_wp_head', 10 );
        remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
        remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
        remove_action( 'template_redirect', 'rest_output_link_header', 11 );
        remove_filter( 'get_the_generator_html', 'wc_generator_tag', 10 );
        remove_filter( 'get_the_generator_xhtml', 'wc_generator_tag', 10 );
        if ( 'extended' === self::mode() ) {
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );
        }
    }

    public static function reduce_headers(): void {
        if ( headers_sent() ) return;
        header_remove( 'X-Powered-By' );
        header_remove( 'X-Pingback' );
    }

    public static function strip_local_version_arg( string $src ): string {
        if ( '' === $src ) return $src;
        $host = wp_parse_url( $src, PHP_URL_HOST );
        $site_host = wp_parse_url( site_url( '/' ), PHP_URL_HOST );
        if ( is_string( $host ) && '' !== $host && is_string( $site_host ) && strtolower( $host ) !== strtolower( $site_host ) ) return $src;
        return remove_query_arg( 'ver', $src );
    }

    public static function status(): array {
        $mode = self::mode();
        return array(
            'mode' => $mode,
            'enabled' => 'off' !== $mode,
            'extended' => 'extended' === $mode,
            'metadata_hints' => 'off' === $mode ? 'visible' : 'reduced',
            'version_hints' => 'extended' === $mode ? 'reduced' : 'preserved',
            'path_rewriting' => false,
            'note' => __( 'Passive fingerprint reduction lowers obvious WordPress/WooCommerce metadata exposure but does not guarantee that a scanner cannot infer the CMS, plugins, JavaScript libraries or backend stack from public behavior and asset paths.', 'yablonsky-security' ),
        );
    }
}
