<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Shared bounded request contract for YSec ↔ YPerf ↔ YSEO interoperability. */
final class YSEC_Request_Contract {
    public const VERSION = '1.1.0';
    private static array $last = array();

    public static function publish( string $verdict, array $context = array() ): array {
        $verdict = strtoupper( sanitize_key( $verdict ) );
        if ( ! in_array( $verdict, array( 'ALLOW','DENY','CHALLENGE','OBSERVE' ), true ) ) $verdict = 'OBSERVE';
        $request = YSEC_Discovery_Interop::request_context();
        $identity = YSEC_Discovery_Interop::identity( '', $request );
        $payload = array(
            'contract_version'   => self::VERSION,
            'security_authority' => 'ysec',
            'performance_owner'  => 'yperf',
            'publication_owner'  => YSEC_Discovery_Interop::yseo_active() ? 'yseo' : 'site_policy',
            'verdict'            => $verdict,
            'family'             => sanitize_key( (string) ( $context['family'] ?? 'request_safety' ) ),
            'stage'              => sanitize_key( (string) ( $context['stage'] ?? 'wordpress_runtime' ) ),
            'phase'              => absint( $context['phase'] ?? 10 ),
            'capacity_semantics' => 'separate_authority',
            'method'             => substr( sanitize_key( (string) ( $request['method'] ?? 'GET' ) ), 0, 12 ),
            'path'               => YSEC_Utils::log_string( (string) ( $request['path'] ?? '/' ), 1024 ),
            'request_id'         => YSEC_Utils::request_id(),
            'http_status'        => absint( $context['http_status'] ?? 0 ),
            'crawler'            => array(
                'claimed'  => ! empty( $identity['claimed'] ),
                'verified' => ! empty( $identity['verified'] ),
                'provider' => sanitize_key( (string) ( $identity['provider'] ?? '' ) ),
                'agent'    => sanitize_text_field( (string) ( $identity['agent'] ?? '' ) ),
                'surface'  => sanitize_key( (string) ( $identity['surface'] ?? 'unknown' ) ),
                'status' => sanitize_key( (string) ( $identity['status'] ?? 'unknown' ) ),
                'method' => sanitize_key( (string) ( $identity['method'] ?? 'none' ) ),
                'checked_at' => sanitize_text_field( (string) ( $identity['checked_at'] ?? '' ) ),
                'purpose' => array_values( array_map( 'sanitize_key', (array) ( $identity['purpose'] ?? array() ) ) ),
            ),
        );
        // Compatibility observers may append auxiliary context but cannot override YSec's
        // authoritative security verdict, crawler identity or the request provenance.
        $filtered = apply_filters( 'ysec_request_contract_v1', $payload );
        if ( is_array( $filtered ) ) {
            foreach ( array( 'consumer_note' ) as $key ) {
                if ( isset( $filtered[ $key ] ) && is_string( $filtered[ $key ] ) ) {
                    $payload[ $key ] = substr( sanitize_text_field( $filtered[ $key ] ), 0, 128 );
                }
            }
        }
        self::$last = $payload;
        do_action( 'ysec_security_verdict_v1', $payload );
        return $payload;
    }

    public static function last(): array { return self::$last; }

    public static function admin_summary(): array {
        return array(
            'version'             => self::VERSION,
            'security_authority'  => 'Yablonsky Security',
            'performance_owner'   => 'Yablonsky Performance',
            'publication_owner'   => YSEC_Discovery_Interop::yseo_active() ? 'Yablonsky SEO' : __( 'Site publication policy', 'yablonsky-security' ),
            'listeners'           => (int) has_action( 'ysec_security_verdict_v1' ),
        );
    }
}
