<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Context-aware response engine.
 *
 * The primary decision unit is the request, not the IP address. Harmful requests are
 * denied immediately by the WAF, while broader source containment is scoped and
 * temporary so legitimate public discovery can continue when it is safe to do so.
 */
final class YSEC_Adaptive_Response {
    private const BUCKET_PREFIX      = 'ysec_response_bucket_';
    private const CONTAINMENT_PREFIX = 'ysec_response_scope_';

    private static function source_key( string $ip ): string {
        return substr( YSEC_Utils::source_identity( $ip ), 0, 40 );
    }

    private static function bucket_key( string $ip ): string {
        return self::BUCKET_PREFIX . self::source_key( $ip );
    }

    private static function containment_key( string $ip ): string {
        return self::CONTAINMENT_PREFIX . self::source_key( $ip );
    }

    public static function request_context(): array {
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        $uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
        $path = strtolower( YSEC_Utils::normalize_path( (string) $uri ) );
        $read_only = in_array( $method, array( 'GET', 'HEAD' ), true );

        $privileged = false;
        foreach ( array( '/wp-login.php', '/wp-admin', '/xmlrpc.php' ) as $prefix ) {
            if ( str_starts_with( $path, $prefix ) ) { $privileged = true; break; }
        }
        if ( ! $privileged && str_starts_with( $path, '/wp-json/' ) && ! $read_only ) $privileged = true;
        if ( ! $privileged && preg_match( '#/(?:checkout|cart|my-account)(?:/|$)#i', $path ) && ! $read_only ) $privileged = true;

        $base = array(
            'method'           => $method,
            'path'             => $path,
            'read_only'        => $read_only,
            'privileged'       => $privileged,
            'public_discovery' => $read_only && ! $privileged,
        );
        $identity = YSEC_Discovery_Interop::identity( '', $base );
        $policy = YSEC_Discovery_Interop::policy_context( $base );
        $base['crawler_claimed'] = ! empty( $identity['claimed'] );
        $base['crawler_agent'] = sanitize_text_field( (string) ( $identity['agent'] ?? '' ) );
        $base['crawler_verified'] = ! empty( $identity['verified'] );
        $base['discovery_policy_owner'] = sanitize_key( (string) ( $policy['owner'] ?? '' ) );
        return $base;
    }

    public static function preflight( string $ip ): array {
        if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return array( 'active'=>false, 'deny'=>false );
        $state = get_transient( self::containment_key( $ip ) );
        if ( ! is_array( $state ) ) return array( 'active'=>false, 'deny'=>false );
        $until = absint( $state['until'] ?? 0 );
        if ( $until && $until <= time() ) {
            delete_transient( self::containment_key( $ip ) );
            return array( 'active'=>false, 'deny'=>false );
        }

        $context = self::request_context();
        $preserve_public = (bool) YSEC_Utils::option( 'preserve_public_discovery', 1 );
        $deny = ! ( $preserve_public && ! empty( $context['public_discovery'] ) );
        return array(
            'active'   => true,
            'deny'     => $deny,
            'context'  => $context,
            'until'    => $until,
            'reason'   => $deny ? 'scoped_source_containment' : 'public_discovery_preserved',
            'pressure' => absint( $state['pressure'] ?? 0 ),
            'families' => array_values( array_filter( array_map( 'sanitize_key', (array) ( $state['families'] ?? array() ) ) ) ),
        );
    }

    public static function record_benign( string $ip ): void {
        if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return;
        $context = self::request_context();
        if ( empty( $context['public_discovery'] ) ) return;
        $bucket = self::bucket( $ip );
        $bucket['public_hits'] = absint( $bucket['public_hits'] ?? 0 ) + 1;
        $bucket['last_public'] = time();
        self::store_bucket( $ip, $bucket );
    }

    public static function record_harmful( string $ip, array $signals, string $reason = 'waf' ): array {
        if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! $signals ) return array( 'contained'=>false );
        $bucket = self::bucket( $ip );
        $score = 0;
        $attack_hits = 0;
        foreach ( $signals as $signal ) {
            $severity = sanitize_key( (string) ( $signal['severity'] ?? 'medium' ) );
            $confidence = sanitize_key( (string) ( $signal['confidence'] ?? 'medium' ) );
            $class = sanitize_key( (string) ( $signal['class'] ?? 'probe' ) );
            if ( 'high' !== $confidence && 'critical' !== $severity ) continue;
            $family = sanitize_key( (string) ( $signal['family'] ?? 'security' ) );
            if ( '' !== $family ) $bucket['families'][ $family ] = 1;
            $weight = array( 'critical'=>6, 'high'=>3, 'medium'=>1, 'low'=>1, 'info'=>0 )[ $severity ] ?? 1;
            if ( 'attack' === $class ) { $weight += 2; $attack_hits++; }
            $score += $weight;
        }
        if ( $score <= 0 ) $score = 1;
        $bucket['harmful_hits'] = absint( $bucket['harmful_hits'] ?? 0 ) + 1;
        $bucket['attack_hits'] = absint( $bucket['attack_hits'] ?? 0 ) + $attack_hits;
        $bucket['pressure'] = absint( $bucket['pressure'] ?? 0 ) + $score;
        $bucket['last_harmful'] = time();
        $bucket['last_reason'] = sanitize_key( $reason );
        self::store_bucket( $ip, $bucket );

        $result = self::maybe_contain( $ip, $bucket, $reason );
        return array_merge( array( 'bucket'=>$bucket ), $result );
    }

    public static function activate_scoped_containment( string $ip, string $reason, array $families = array(), int $pressure = 0 ): bool {
        if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! YSEC_Utils::option( 'auto_block', 0 ) ) return false;

        // Keep containment idempotent. Repeated probes inside an already-active window are
        // still denied at request level, but they must not endlessly extend the TTL or
        // generate one containment event per request.
        $existing = get_transient( self::containment_key( $ip ) );
        if ( is_array( $existing ) && absint( $existing['until'] ?? 0 ) > time() ) return false;

        if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
            $admin_ip = YSEC_Utils::client_ip();
            if ( $admin_ip && hash_equals( YSEC_Utils::source_identity( $admin_ip ), YSEC_Utils::source_identity( $ip ) ) ) return false;
        }
        $minutes = max( 5, min( 1440, absint( YSEC_Utils::option( 'block_minutes', 60 ) ) ) );
        $state = array(
            'started'  => time(),
            'until'    => time() + $minutes * MINUTE_IN_SECONDS,
            'reason'   => sanitize_key( $reason ),
            'pressure' => max( 0, $pressure ),
            'families' => array_values( array_unique( array_filter( array_map( 'sanitize_key', $families ) ) ) ),
        );
        set_transient( self::containment_key( $ip ), $state, $minutes * MINUTE_IN_SECONDS );
        YSEC_Events::log( 'response_scoped_containment', array(
            'severity'=>'high',
            'confidence'=>'high',
            'state'=>'campaign_contained',
            'family'=>'adaptive_response',
            'details'=>array(
                'reason'=>$state['reason'],
                'minutes'=>$minutes,
                'pressure'=>$state['pressure'],
                'families'=>$state['families'],
                'public_discovery_preserved'=>(bool) YSEC_Utils::option( 'preserve_public_discovery', 1 ),
                'crawler_claim'=>YSEC_Discovery_Interop::evidence_context()['crawler_claim'] ?? array(),
                'discovery_policy_owner'=>YSEC_Discovery_Interop::yseo_active() ? 'yseo' : 'external_or_unset',
            ),
        ) );
        return true;
    }

    public static function clear_scoped_containment( string $ip ): bool {
        if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;
        delete_transient( self::containment_key( $ip ) );
        return true;
    }

    private static function maybe_contain( string $ip, array $bucket, string $reason ): array {
        if ( ! YSEC_Utils::option( 'auto_block', 0 ) ) return array( 'contained'=>false );
        $pressure_threshold = max( 8, min( 500, absint( YSEC_Utils::option( 'smart_containment_score', 24 ) ) ) );
        $family_threshold = max( 1, min( 12, absint( YSEC_Utils::option( 'smart_containment_families', 3 ) ) ) );
        $attack_threshold = max( 2, min( 100, absint( YSEC_Utils::option( 'smart_containment_attack_hits', 8 ) ) ) );
        $families = array_keys( (array) ( $bucket['families'] ?? array() ) );
        $pressure = absint( $bucket['pressure'] ?? 0 );
        $attack_hits = absint( $bucket['attack_hits'] ?? 0 );
        $qualifies = ( $pressure >= $pressure_threshold && count( $families ) >= $family_threshold ) || $attack_hits >= $attack_threshold;
        if ( ! $qualifies ) return array( 'contained'=>false, 'pressure'=>$pressure, 'families'=>$families );
        $contained = self::activate_scoped_containment( $ip, $reason, $families, $pressure );
        return array( 'contained'=>$contained, 'pressure'=>$pressure, 'families'=>$families );
    }

    private static function bucket( string $ip ): array {
        $window = max( 1, min( 60, absint( YSEC_Utils::option( 'smart_response_window', 10 ) ) ) );
        $bucket = get_transient( self::bucket_key( $ip ) );
        $now = time();
        if ( ! is_array( $bucket ) || empty( $bucket['started'] ) || $now - absint( $bucket['started'] ) >= $window * MINUTE_IN_SECONDS ) {
            $bucket = array(
                'started'=>$now,
                'harmful_hits'=>0,
                'attack_hits'=>0,
                'public_hits'=>0,
                'pressure'=>0,
                'families'=>array(),
            );
        }
        return $bucket;
    }

    private static function store_bucket( string $ip, array $bucket ): void {
        $window = max( 1, min( 60, absint( YSEC_Utils::option( 'smart_response_window', 10 ) ) ) );
        $remaining = max( 1, $window * MINUTE_IN_SECONDS - ( time() - absint( $bucket['started'] ?? time() ) ) );
        set_transient( self::bucket_key( $ip ), $bucket, $remaining );
    }
}
