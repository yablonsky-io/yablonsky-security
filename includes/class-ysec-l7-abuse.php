<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Bounded L7 request-intent intelligence derived from production incident evidence.
 *
 * This layer classifies expensive/stateful public GET surfaces before the main query/template
 * runs. It deliberately avoids writing one database event per request: high-rate counters use
 * the persistent object cache when available and only bounded samples are persisted.
 */
final class YSEC_L7_Abuse {
    public const CONTRACT_VERSION = '1.0.0';
    private const CACHE_GROUP = 'ysec_l7_abuse';
    private const SAMPLE_BUDGET = 20;

    public static function inspect_current(): array {
        if ( ! YSEC_Utils::option( 'l7_abuse_observe', 1 ) || is_admin() || wp_doing_cron() ) return array();

        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        if ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) ) return array();

        $path = YSEC_Discovery_Interop::request_context()['path'] ?? '/';
        $keys = self::query_keys();
        $intent = self::classify( $keys, (string) $path, $method );
        if ( empty( $intent['matched'] ) ) return array();

        $ip = YSEC_Utils::client_ip();
        $source = '' !== $ip ? YSEC_Utils::source_identity( $ip ) : '';
        $window = max( 30, min( 300, absint( YSEC_Utils::option( 'l7_abuse_window_seconds', 60 ) ) ) );
        $threshold = max( 20, min( 1000, absint( YSEC_Utils::option( 'l7_state_action_threshold', 60 ) ) ) );
        $persistent = function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache();
        $count = $persistent && '' !== $source ? self::counter( $source, (string) $intent['family'], $window ) : 0;

        $request_context = YSEC_Discovery_Interop::request_context();
        $crawler = YSEC_Discovery_Interop::identity( '', $request_context );
        $enforce = 'state_action_get' === $intent['family']
            && ! empty( YSEC_Utils::option( 'l7_state_action_enforce', 1 ) )
            && $persistent
            && '' !== $source
            && ! is_user_logged_in()
            && $count >= $threshold;

        $result = array(
            'matched'          => true,
            'family'           => (string) $intent['family'],
            'action'           => (string) ( $intent['action'] ?? '' ),
            'method'           => $method,
            'path'             => YSEC_Utils::log_string( (string) $path, 1024 ),
            'query_keys'       => $keys,
            'source_rate'      => $count,
            'window_seconds'   => $window,
            'threshold'        => $threshold,
            'persistent_cache' => $persistent,
            'enforce'          => $enforce,
            'crawler_claimed'  => ! empty( $crawler['claimed'] ),
            'crawler_verified' => ! empty( $crawler['verified'] ),
            'crawler_agent'    => sanitize_text_field( (string) ( $crawler['agent'] ?? '' ) ),
            'request_id'       => YSEC_Utils::request_id(),
        );

        self::publish_signal( $result );
        if ( self::should_sample( $result ) ) self::record_sample( $result );
        return $result;
    }

    public static function classify( array $keys, string $path, string $method = 'GET' ): array {
        if ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) ) return array( 'matched'=>false );
        $key_map = array_fill_keys( $keys, true );

        if ( isset( $key_map['add-to-cart'] ) || isset( $key_map['add_to_cart'] ) ) {
            return array( 'matched'=>true, 'family'=>'state_action_get', 'action'=>'add_to_cart' );
        }
        if ( isset( $key_map['add_to_wishlist'] ) || isset( $key_map['add-to-wishlist'] ) ) {
            return array( 'matched'=>true, 'family'=>'state_action_get', 'action'=>'wishlist' );
        }
        if ( isset( $key_map['action'] ) && self::query_value_is( 'action', 'yith-woocompare-add-product' ) ) {
            return array( 'matched'=>true, 'family'=>'state_action_get', 'action'=>'compare' );
        }

        $facet = false;
        foreach ( $keys as $key ) {
            if ( str_starts_with( $key, 'filter_' ) || str_starts_with( $key, 'query_type_' ) || in_array( $key, array( 'min_price','max_price','rating_filter' ), true ) ) {
                $facet = true;
                break;
            }
        }
        if ( $facet ) return array( 'matched'=>true, 'family'=>'expensive_faceted_crawl', 'action'=>'facet' );

        if ( preg_match( '~/(?:page|strona|pagina)/\d+/?$~i', $path ) && ( isset( $key_map['view'] ) || isset( $key_map['orderby'] ) ) ) {
            return array( 'matched'=>true, 'family'=>'expensive_faceted_crawl', 'action'=>'deep_variant' );
        }
        return array( 'matched'=>false );
    }

    public static function admin_state(): array {
        $persistent = function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache();
        $configured = (bool) YSEC_Utils::option( 'l7_state_action_enforce', 1 );
        return array(
            'observe'                 => (bool) YSEC_Utils::option( 'l7_abuse_observe', 1 ),
            'state_enforce'           => $configured,
            'effective_state_enforce' => $configured && $persistent,
            'threshold'               => max( 20, min( 1000, absint( YSEC_Utils::option( 'l7_state_action_threshold', 60 ) ) ) ),
            'window_seconds'          => max( 30, min( 300, absint( YSEC_Utils::option( 'l7_abuse_window_seconds', 60 ) ) ) ),
            'persistent_cache'        => $persistent,
            'contract'                => self::CONTRACT_VERSION,
        );
    }

    private static function query_keys(): array {
        $keys = array();
        foreach ( array_keys( self::query_map() ) as $key ) {
            $clean = sanitize_key( (string) $key );
            if ( '' !== $clean && ! in_array( $clean, array( 'password','pass','token','key','nonce','_wpnonce','authorization' ), true ) ) $keys[] = substr( $clean, 0, 64 );
        }
        sort( $keys, SORT_STRING );
        return array_values( array_unique( array_slice( $keys, 0, 32 ) ) );
    }

    private static function query_value_is( string $key, string $expected ): bool {
        $query = self::query_map();
        if ( ! isset( $query[ $key ] ) || ! is_scalar( $query[ $key ] ) ) return false;
        $value = sanitize_key( (string) $query[ $key ] );
        return hash_equals( sanitize_key( $expected ), $value );
    }

    private static function query_map(): array {
        $raw = isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '';
        if ( '' === $raw ) return array();
        $query = array();
        wp_parse_str( $raw, $query );
        return is_array( $query ) ? map_deep( $query, 'sanitize_text_field' ) : array();
    }

    private static function counter( string $source, string $family, int $window ): int {
        $bucket = (int) floor( time() / $window );
        $key = 'rate_' . hash( 'sha256', $source . '|' . $family . '|' . $bucket );
        if ( false === wp_cache_get( $key, self::CACHE_GROUP ) ) wp_cache_add( $key, 0, self::CACHE_GROUP, $window + 15 );
        $count = wp_cache_incr( $key, 1, self::CACHE_GROUP );
        return false === $count ? 1 : (int) $count;
    }

    private static function should_sample( array $result ): bool {
        if ( ! empty( $result['persistent_cache'] ) ) {
            $count = (int) ( $result['source_rate'] ?? 0 );
            $threshold = (int) ( $result['threshold'] ?? 60 );
            if ( ! in_array( $count, array( 1, $threshold, $threshold * 2, $threshold * 4 ), true ) ) return false;
            $bucket = (int) floor( time() / 60 );
            $budget_key = 'sample_budget_' . $bucket;
            if ( false === wp_cache_get( $budget_key, self::CACHE_GROUP ) ) wp_cache_add( $budget_key, 0, self::CACHE_GROUP, 75 );
            $used = wp_cache_incr( $budget_key, 1, self::CACHE_GROUP );
            return false !== $used && (int) $used <= self::SAMPLE_BUDGET;
        }
        return 0 === ( crc32( (string) ( $result['request_id'] ?? '' ) . '|' . (string) ( $result['family'] ?? '' ) ) % 128 );
    }

    private static function record_sample( array $result ): void {
        YSEC_Events::log( 'l7_abuse_signal', array(
            'severity'         => ! empty( $result['enforce'] ) ? 'high' : 'medium',
            'confidence'       => 'high',
            'state'            => ! empty( $result['enforce'] ) ? 'request_denied' : 'observed',
            'family'           => (string) $result['family'],
            'path'             => (string) $result['path'],
            'method'           => (string) $result['method'],
            'aggregate'        => true,
            'aggregate_window' => 900,
            'aggregate_seed'   => (string) $result['action'],
            'request_id'       => (string) $result['request_id'],
            'query_redacted'   => implode( '&', (array) $result['query_keys'] ),
            'details'          => array(
                'intent'              => (string) $result['family'],
                'action'              => (string) $result['action'],
                'query_keys'          => (array) $result['query_keys'],
                'source_rate'         => (int) $result['source_rate'],
                'window_seconds'      => (int) $result['window_seconds'],
                'threshold'           => (int) $result['threshold'],
                'persistent_cache'    => (bool) $result['persistent_cache'],
                'crawler_claimed'     => (bool) $result['crawler_claimed'],
                'crawler_verified'    => (bool) $result['crawler_verified'],
                'crawler_agent'       => (string) $result['crawler_agent'],
                'origin_stage'        => 'pre_main_query',
                'evidence_is_sampled' => true,
            ),
        ) );
    }

    private static function publish_signal( array $result ): void {
        $payload = array(
            'contract_version' => self::CONTRACT_VERSION,
            'intent'           => sanitize_key( (string) $result['family'] ),
            'action'           => sanitize_key( (string) $result['action'] ),
            'method'           => substr( sanitize_key( (string) $result['method'] ), 0, 12 ),
            'path'             => YSEC_Utils::log_string( (string) $result['path'], 1024 ),
            'query_keys'       => array_values( array_map( 'sanitize_key', (array) $result['query_keys'] ) ),
            'request_id'       => sanitize_text_field( (string) $result['request_id'] ),
            'source_rate'      => (int) $result['source_rate'],
            'window_seconds'   => (int) $result['window_seconds'],
            'enforced'         => (bool) $result['enforce'],
            'origin_stage'     => 'pre_main_query',
        );
        /**
         * Publish a bounded L7 intent signal for YPerf/origin-cost correlation.
         * No raw IP, query values, cookies, credentials, request body or secret headers are included.
         *
         * @param array $payload Sanitized request-intent evidence.
         */
        do_action( 'ysec_request_intent_signal', $payload );
    }
}
