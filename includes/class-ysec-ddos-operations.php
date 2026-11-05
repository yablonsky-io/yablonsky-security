<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Application-layer DDoS readiness across YSec-owned WordPress/origin controls. */
final class YSEC_DDoS_Operations {
    public static function summary(): array {
        $mu = YSEC_Managed_MU::status();
        $mu_proof = get_transient( 'ysec_mu_verify_result' );
        $l7 = YSEC_L7_Abuse::admin_state();
        $profile = YSEC_Firewall_Profiles::current();
        $profiles = YSEC_Firewall_Profiles::profiles();
        $fast = YSEC_Fast_Path::last();
        $layers = array(
            array( 'id'=>'mu_early', 'group'=>'core', 'label'=>__( 'Managed MU early guard', 'yablonsky-security' ), 'state'=>( ! empty( $mu['owned'] ) && ! empty( $mu['policy_valid'] ) ) ? 'ready' : 'available', 'detail'=>__( 'Rejects high-confidence hostile request shapes before normal plugins load.', 'yablonsky-security' ), 'next'=>__( 'Keep the managed runtime owned and policy-valid.', 'yablonsky-security' ) ),
            array( 'id'=>'mu_proof', 'group'=>'core', 'label'=>__( 'Early live proof', 'yablonsky-security' ), 'state'=>is_array( $mu_proof ) && ! empty( $mu_proof['ok'] ) ? 'verified' : 'ready_to_verify', 'detail'=>__( 'Same-site HTTP canary proves the Managed MU response path.', 'yablonsky-security' ), 'next'=>__( 'Run Verify early runtime after installation or a runtime change.', 'yablonsky-security' ) ),
            array( 'id'=>'burst', 'group'=>'extended', 'label'=>__( 'Sensitive-surface burst shield', 'yablonsky-security' ), 'state'=>! empty( $mu['persistent_object_cache'] ) ? 'ready' : 'available', 'detail'=>! empty( $mu['persistent_object_cache'] ) ? __( 'Persistent object-cache counters provide constant-cost burst enforcement.', 'yablonsky-security' ) : __( 'Persistent object cache activates constant-cost burst counters for login, XML-RPC, comments and REST writes.', 'yablonsky-security' ), 'next'=>__( 'Connect a persistent object cache through the performance/server stack to activate constant-cost counters.', 'yablonsky-security' ) ),
            array( 'id'=>'origin', 'group'=>'core', 'label'=>__( 'Origin abuse intelligence', 'yablonsky-security' ), 'state'=>! empty( $l7['observe'] ) ? 'observing' : 'available', 'detail'=>__( 'Classifies expensive state-action and faceted-crawl patterns before the main query.', 'yablonsky-security' ), 'next'=>__( 'Keep bounded origin-abuse observation active for cost-aware response evidence.', 'yablonsky-security' ) ),
            array( 'id'=>'fast_path', 'group'=>'extended', 'label'=>__( 'Server fast path', 'yablonsky-security' ), 'state'=>! empty( $fast['ok'] ) ? 'verified' : 'available', 'detail'=>__( 'Optional Nginx or Apache/LiteSpeed rules can reject selected probes before PHP.', 'yablonsky-security' ), 'next'=>__( 'Review and verify the generated server fast path when origin-level pre-PHP filtering is desired.', 'yablonsky-security' ) ),
        );
        $ready_states = array( 'ready','verified','observing' );
        $core_layers = array_values( array_filter( $layers, static fn( array $row ): bool => 'core' === (string) ( $row['group'] ?? '' ) ) );
        $extended_layers = array_values( array_filter( $layers, static fn( array $row ): bool => 'extended' === (string) ( $row['group'] ?? '' ) ) );
        $ready_count = static fn( array $rows ): int => count( array_filter( $rows, static fn( array $row ): bool => in_array( (string) $row['state'], $ready_states, true ) ) );
        return array(
            'profile'         => $profile,
            'profile_label'   => (string) ( $profiles[ $profile ]['label'] ?? $profile ),
            'layers'          => $layers,
            'ready_layers'    => $ready_count( $layers ),
            'total_layers'    => count( $layers ),
            'core_ready'      => $ready_count( $core_layers ),
            'core_total'      => count( $core_layers ),
            'extended_ready'  => $ready_count( $extended_layers ),
            'extended_total'  => count( $extended_layers ),
            'crawler_mode'    => 'discovery_friendly',
        );
    }
}
