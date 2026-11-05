<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Rate_Intelligence {
    public static function observe( string $ip, array $signals ): array {
        if ( '' === $ip || empty( $signals ) ) return array( 'threshold'=>false, 'enforce'=>false, 'count'=>0 );
        $high_conf = array_filter( $signals, static fn( $s ) => 'high' === ( $s['confidence'] ?? '' ) && in_array( ( $s['class'] ?? '' ), array( 'probe','attack' ), true ) );
        if ( ! $high_conf ) return array( 'threshold'=>false, 'enforce'=>false, 'count'=>0 );
        $window = max( 1, min( 60, absint( YSEC_Utils::option( 'suspicious_rate_window', 10 ) ) ) );
        $threshold = max( 20, min( 1000, absint( YSEC_Utils::option( 'suspicious_rate_threshold', 120 ) ) ) );
        $key = 'ysec_rate_' . substr( YSEC_Utils::source_identity( $ip ), 0, 40 );
        $bucket = get_transient( $key );
        $now = time();
        if ( ! is_array( $bucket ) || empty( $bucket['started'] ) || $now - (int) $bucket['started'] >= $window * MINUTE_IN_SECONDS ) {
            $bucket = array( 'started'=>$now, 'count'=>0, 'reported'=>0 );
        }
        $bucket['count'] = (int) ( $bucket['count'] ?? 0 ) + 1;
        $remaining = max( 1, $window * MINUTE_IN_SECONDS - ( $now - (int) $bucket['started'] ) );
        $hit = $bucket['count'] >= $threshold;
        if ( $hit && empty( $bucket['reported'] ) ) {
            $bucket['reported'] = 1;
            YSEC_Events::log( 'suspicious_rate_threshold', array(
                'severity'=>'high','confidence'=>'high','family'=>'automated_scanner','state'=>'observed',
                'details'=>array( 'count'=>$bucket['count'], 'threshold'=>$threshold, 'window_minutes'=>$window ),
            ) );
        }
        set_transient( $key, $bucket, $remaining );
        return array( 'threshold'=>$hit, 'enforce'=>$hit && (bool) YSEC_Utils::option( 'suspicious_rate_enforce', 0 ), 'count'=>$bucket['count'], 'window'=>$window, 'limit'=>$threshold );
    }
}
