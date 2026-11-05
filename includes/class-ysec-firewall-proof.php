<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Firewall_Proof {
    private const TRANSIENT = 'ysec_firewall_proof_result_v1';
    private const OPTION = 'ysec_firewall_proof_last_v1';
    private const TOKEN_TRANSIENT = 'ysec_firewall_proof_token_v1';

    public static function run(): array {
        $profile = YSEC_Firewall_Profiles::current();
        $profiles = YSEC_Firewall_Profiles::profiles();
        $level = (int) ( $profiles[ $profile ]['level'] ?? 0 );
        $vector = self::vector_for_level( $level );
        $engine = self::engine_check( $profile, $vector );
        $live = self::live_check( $profile, $vector, (string) ( $engine['family'] ?? '' ) );
        $result = array(
            'profile'    => $profile,
            'label'      => (string) ( $profiles[ $profile ]['label'] ?? $profile ),
            'engine'     => $engine,
            'live'       => $live,
            'checked_at' => current_time( 'mysql' ),
            'ok'         => ! empty( $vector['testable'] ) && ! empty( $engine['ok'] ) && ! empty( $live['ok'] ),
        );
        set_transient( self::TRANSIENT, $result, 30 * MINUTE_IN_SECONDS );
        if ( false === get_option( self::OPTION, false ) ) {
            add_option( self::OPTION, $result, '', false );
        } else {
            update_option( self::OPTION, $result, false );
        }
        YSEC_Events::log( 'firewall_proof_run', array(
            'severity' => ! empty( $result['ok'] ) ? 'info' : 'medium',
            'family'   => 'firewall_proof',
            'state'    => ! empty( $result['ok'] ) ? 'verified' : 'review',
            'details'  => array(
                'profile'   => $profile,
                'engine_ok' => ! empty( $engine['ok'] ),
                'live_ok'   => ! empty( $live['ok'] ),
                'live_unavailable' => ! empty( $live['unavailable'] ),
            ),
        ) );
        return $result;
    }

    public static function last(): array {
        $value = get_transient( self::TRANSIENT );
        if ( is_array( $value ) && $value ) return $value;
        $value = get_option( self::OPTION, array() );
        return is_array( $value ) ? $value : array();
    }

    public static function receipt(): array {
        $last = self::last();
        $engine = is_array( $last['engine'] ?? null ) ? $last['engine'] : array();
        $live = is_array( $last['live'] ?? null ) ? $last['live'] : array();
        return array(
            'schema'      => 'yablonsky.security.firewall-proof.v1',
            'plugin'      => 'Yablonsky Security',
            'version'     => YSEC_VERSION,
            'profile'     => sanitize_key( (string) ( $last['profile'] ?? '' ) ),
            'label'       => sanitize_text_field( (string) ( $last['label'] ?? '' ) ),
            'checked_at'  => sanitize_text_field( (string) ( $last['checked_at'] ?? '' ) ),
            'proved'      => ! empty( $last['ok'] ),
            'rule_engine' => array(
                'pass'    => ! empty( $engine['ok'] ),
                'family'  => sanitize_key( (string) ( $engine['family'] ?? '' ) ),
                'message' => sanitize_text_field( (string) ( $engine['message'] ?? '' ) ),
            ),
            'live_enforcement' => array(
                'pass'            => ! empty( $live['ok'] ),
                'unavailable'     => ! empty( $live['unavailable'] ),
                'http_code'       => absint( $live['code'] ?? 0 ),
                'expected_status' => 403,
                'proof_marker'    => ! empty( $live['marker_verified'] ),
                'early_runtime'   => ! empty( $live['early_verified'] ),
                'proof_layer'     => sanitize_key( (string) ( $live['proof_layer'] ?? '' ) ),
                'family'          => sanitize_key( (string) ( $live['early_family'] ?? '' ) ),
                'message'         => sanitize_text_field( (string) ( $live['message'] ?? '' ) ),
            ),
        );
    }

    public static function proof_response_token(): string {
        $incoming = isset( $_SERVER['HTTP_X_YSEC_PROOF_TOKEN'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_YSEC_PROOF_TOKEN'] ) ) : '';
        if ( '' === $incoming ) return '';
        $expected = get_transient( self::TOKEN_TRANSIENT );
        if ( ! is_string( $expected ) || '' === $expected || ! hash_equals( $expected, $incoming ) ) return '';
        return $incoming;
    }

    private static function engine_check( string $profile, array $vector ): array {
        if ( empty( $vector['testable'] ) ) {
            return array( 'ok'=>true, 'state'=>'not_applicable', 'message'=>__( 'Minimal profile has no profile-specific deny tier to prove.', 'yablonsky-security' ) );
        }
        $signal = YSEC_Firewall_Profiles::evaluate_values(
            $profile,
            (string) $vector['path'],
            (string) ( $vector['query'] ?? '' ),
            (string) ( $vector['ua'] ?? 'YSEC-Proof' ),
            (string) ( $vector['method'] ?? 'GET' ),
            (array) ( $vector['cookies'] ?? array() )
        );
        $ok = ! empty( $signal ) && (string) ( $signal['rule'] ?? '' ) === 'profile_' . sanitize_key( $profile );
        return array(
            'ok'      => $ok,
            'state'   => $ok ? 'pass' : 'fail',
            'family'  => (string) ( $signal['family'] ?? '' ),
            'surface' => (string) ( $signal['details']['surface'] ?? '' ),
            'message' => $ok ? __( 'The selected profile matched its deterministic high-confidence canary.', 'yablonsky-security' ) : __( 'The selected profile did not match its deterministic canary.', 'yablonsky-security' ),
        );
    }

    private static function live_check( string $profile, array $vector, string $expected_family = '' ): array {
        if ( empty( $vector['testable'] ) ) {
            return array( 'ok'=>false, 'unavailable'=>false, 'state'=>'not_applicable', 'message'=>__( 'The Minimal profile has no dedicated deny canary and cannot receive a live-proof PASS.', 'yablonsky-security' ) );
        }
        $token = wp_generate_password( 32, false, false );
        set_transient( self::TOKEN_TRANSIENT, $token, 2 * MINUTE_IN_SECONDS );
        $url = home_url( (string) $vector['path'] );
        if ( ! empty( $vector['query'] ) ) $url = add_query_arg( 'ysec_proof_q', (string) $vector['query'], $url );
        $response = wp_remote_request( $url, array(
            'method'      => (string) ( $vector['method'] ?? 'GET' ),
            'timeout'     => 8,
            'redirection' => 0,
            'headers'     => array(
                'X-YSEC-Proof-Token' => $token,
                'Cache-Control'       => 'no-cache, no-store, max-age=0',
                'User-Agent'          => (string) ( $vector['ua'] ?? 'YSEC-Proof/1.0' ),
            ),
        ) );
        delete_transient( self::TOKEN_TRANSIENT );
        if ( is_wp_error( $response ) ) {
            return array( 'ok'=>false, 'unavailable'=>true, 'state'=>'unavailable', 'code'=>0, 'message'=>sanitize_text_field( $response->get_error_message() ) );
        }
        $code = (int) wp_remote_retrieve_response_code( $response );
        $marker = (string) wp_remote_retrieve_header( $response, 'x-yablonsky-security-proof' );
        $early = trim( (string) wp_remote_retrieve_header( $response, 'x-yablonsky-security-early' ) );
        $early_family = sanitize_key( (string) wp_remote_retrieve_header( $response, 'x-yablonsky-security-family' ) );
        $wordpress_ok = 403 === $code && '' !== $marker && hash_equals( $token, $marker );
        $signature = (string) wp_remote_retrieve_header( $response, 'x-yablonsky-security-signature' );
        $expected_signature = YSEC_Managed_MU::proof_signature( $token, $early_family );
        $mu_ok = 403 === $code
            && '1' === $early
            && '' !== $expected_family
            && hash_equals( sanitize_key( $expected_family ), $early_family )
            && '' !== $signature
            && hash_equals( $expected_signature, $signature );
        $ok = $wordpress_ok || $mu_ok;
        $message = $ok
            ? __( 'A real same-site HTTP request reached YSec and was denied by the application firewall.', 'yablonsky-security' )
            : __( 'The loopback request did not return the YSec proof marker. Another layer may have intercepted it, or live enforcement needs review.', 'yablonsky-security' );
        return array(
            'ok'=>$ok,
            'unavailable'=>false,
            'state'=>$ok?'pass':'review',
            'code'=>$code,
            'marker'=>$wordpress_ok,
            'marker_verified'=>$wordpress_ok,
            'early_verified'=>$mu_ok,
            'proof_layer'=>$wordpress_ok?'wordpress_firewall':($mu_ok?'managed_mu_early':''),
            'early_family'=>$early_family,
            'message'=>$message,
        );
    }

    private static function vector_for_level( int $level ): array {
        if ( $level >= 4 ) return array( 'testable'=>true, 'path'=>'/__ysec-profile-proof__', 'method'=>'TRACE', 'ua'=>'YSEC-Proof/1.0' );
        if ( $level >= 3 ) return array( 'testable'=>true, 'path'=>'/manager/__ysec-profile-proof__', 'method'=>'GET', 'ua'=>'YSEC-Proof/1.0' );
        if ( $level >= 2 ) return array( 'testable'=>true, 'path'=>'/phpmyadmin/__ysec-profile-proof__', 'method'=>'GET', 'ua'=>'YSEC-Proof/1.0' );
        if ( $level >= 1 ) return array( 'testable'=>true, 'path'=>'/.env.__ysec-profile-proof__', 'method'=>'GET', 'ua'=>'YSEC-Proof/1.0' );
        return array( 'testable'=>false, 'path'=>'/__ysec-profile-proof__', 'method'=>'GET', 'ua'=>'YSEC-Proof/1.0' );
    }
}
