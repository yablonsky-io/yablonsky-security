<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Local operational-response evidence. Describes observed decisions; never claims compromise prevention. */
final class YSEC_Operations {
    public static function snapshot( int $hours = 24 ): array {
        $hours = max( 1, min( 168, $hours ) );
        $cache_key = 'ysec_operations_v1_' . $hours;
        $cached = get_transient( $cache_key );
        if ( is_array( $cached ) ) return $cached;

        global $wpdb;
        $since = gmdate( 'Y-m-d H:i:s', time() - $hours * HOUR_IN_SECONDS );
        $table = YSEC_DB::table( 'events' );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded local operational summary over plugin-owned request-decision evidence.
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT state,SUM(hit_count) hits FROM %i WHERE type='request_decision' AND observed_at >= %s GROUP BY state", $table, $since ), ARRAY_A ) ?: array();
        $states = array();
        $decisions = 0;
        foreach ( $rows as $row ) {
            $state = sanitize_key( (string) ( $row['state'] ?? '' ) );
            $hits = max( 0, (int) ( $row['hits'] ?? 0 ) );
            if ( '' === $state ) continue;
            $states[ $state ] = $hits;
            $decisions += $hits;
        }
        $request_denies = (int) ( $states['request_denied'] ?? 0 ) + (int) ( $states['blocked'] ?? 0 );
        $source_containments = (int) ( $states['source_blocked'] ?? 0 ) + (int) ( $states['campaign_contained'] ?? 0 );
        $handled = $request_denies + $source_containments;
        $recon = YSEC_Events::recon_summary( $hours );
        $storage = YSEC_Events::storage_summary();
        $storage_valid = ! empty( $storage['valid'] );
        $active_blocks = YSEC_Firewall::active_blocks();
        $conditional_rules = YSEC_Conditional_Rules::all();
        $virtual = YSEC_Virtual_Patches::status();
        $enabled_conditional = 0;
        foreach ( $conditional_rules as $rule ) if ( ! empty( $rule['enabled'] ) ) $enabled_conditional++;

        $out = array(
            'hours'                => $hours,
            'request_decisions'    => $decisions,
            'request_denies'       => $request_denies,
            'source_containments'  => $source_containments,
            'handled_decisions'    => $handled,
            'handled_ratio'        => $decisions > 0 ? round( 100 * $handled / $decisions, 1 ) : 0.0,
            'recon_campaigns'      => (int) ( $recon['campaigns'] ?? 0 ),
            'recon_sources'        => (int) ( $recon['sources'] ?? 0 ),
            'active_source_blocks' => is_array( $active_blocks ) ? count( $active_blocks ) : 0,
            'conditional_rules'    => $enabled_conditional,
            'virtual_patches'      => (int) ( $virtual['enabled'] ?? 0 ),
            'evidence_available'   => $storage_valid,
            'evidence_rows'        => $storage_valid ? (int) $storage['total'] : null,
            'evidence_hits'        => $storage_valid ? (int) $storage['hits'] : null,
            'aggregation_factor'   => $storage_valid ? ( ! empty( $storage['total'] ) ? round( (int) $storage['hits'] / max( 1, (int) $storage['total'] ), 2 ) : 0.0 ) : null,
            'states'               => $states,
        );
        // An unknown evidence state should not be stored as a successful snapshot.
        if ( $storage_valid ) set_transient( $cache_key, $out, 20 );
        return $out;
    }
}
