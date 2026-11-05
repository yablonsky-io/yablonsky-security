<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Migration completion evidence for security-tool ownership handoff.
 *
 * This layer is deliberately diagnostic and proof-oriented. It never changes
 * another plugin's activation state and it never edits wp-config.php.
 */
final class YSEC_Takeover {
    private const OPTION = 'ysec_takeover_closeout_v1';

    public static function status(): array {
        $sources = array();
        $proofs = YSEC_Migration::cutover_proofs();
        $all_inactive = true;
        $all_proved = true;

        foreach ( YSEC_Compatibility::report() as $item ) {
            $file = (string) ( $item['file'] ?? '' );
            $proof = isset( $proofs[ $file ] ) && is_array( $proofs[ $file ] ) ? $proofs[ $file ] : array();
            $active = ! empty( $item['active'] );
            $proved = ! $active && ! empty( $proof['ok'] );
            if ( $active ) $all_inactive = false;
            if ( ! $proved ) $all_proved = false;
            $sources[] = array(
                'file'         => $file,
                'name'         => (string) ( $item['name'] ?? $file ),
                'active'       => $active,
                'proved'       => $proved,
                'proved_at'    => sanitize_text_field( (string) ( $proof['generated_at'] ?? '' ) ),
                'proof_version'=> sanitize_text_field( (string) ( $proof['version'] ?? '' ) ),
            );
        }

        if ( ! $sources ) {
            $all_inactive = true;
            $all_proved = true;
        }

        $doctor = YSEC_Doctor::report();
        $doctor_ok = ! empty( $doctor['ok'] ) || ( isset( $doctor['passed'], $doctor['total'] ) && (int) $doctor['passed'] === (int) $doctor['total'] );
        $firewall = YSEC_Firewall_Proof::receipt();
        $firewall_ok = ! empty( $firewall['proved'] ) && ! empty( $firewall['rule_engine']['pass'] ) && ! empty( $firewall['live_enforcement']['pass'] );
        $migration = YSEC_Migration::readiness();
        $migration_ok = isset( $migration['passed'], $migration['total'] ) && (int) $migration['passed'] === (int) $migration['total'];
        $exposure = YSEC_Exposure::audit();
        $debug_clear = true;
        foreach ( (array) ( $exposure['checks'] ?? array() ) as $check ) {
            if ( 'wp-content/debug.log' !== (string) ( $check['key'] ?? '' ) ) continue;
            $debug_clear = 'clear' === (string) ( $check['state'] ?? '' );
            break;
        }

        $gates = array(
            array(
                'id'     => 'legacy_sources_inactive',
                'label'  => __( 'Prior security products inactive', 'yablonsky-security' ),
                'pass'   => $all_inactive,
                'detail' => $sources ? __( 'Detected source security products are ready for YSec ownership proof when their overlapping enforcement is inactive.', 'yablonsky-security' ) : __( 'The current stack has no supported prior security product to migrate.', 'yablonsky-security' ),
            ),
            array(
                'id'     => 'per_source_proofs',
                'label'  => __( 'Per-source migration proofs', 'yablonsky-security' ),
                'pass'   => $all_proved,
                'detail' => $sources ? __( 'Each detected prior security product can be verified with its own successful migration receipt.', 'yablonsky-security' ) : __( 'A clean install already has a direct YSec ownership path.', 'yablonsky-security' ),
            ),
            array(
                'id'     => 'doctor',
                'label'  => __( 'Security Doctor', 'yablonsky-security' ),
                'pass'   => $doctor_ok,
                'detail' => sprintf( /* translators: 1: passed checks, 2: total checks. */ __( '%1$d/%2$d local runtime checks passed.', 'yablonsky-security' ), (int) ( $doctor['passed'] ?? 0 ), (int) ( $doctor['total'] ?? 0 ) ),
            ),
            array(
                'id'     => 'firewall_live_proof',
                'label'  => __( 'Live Firewall Proof', 'yablonsky-security' ),
                'pass'   => $firewall_ok,
                'detail' => $firewall_ok ? __( 'The current firewall profile has a live same-site deny proof.', 'yablonsky-security' ) : __( 'Run Firewall Proof to add a current live-enforcement PASS.', 'yablonsky-security' ),
            ),
            array(
                'id'     => 'migration_readiness',
                'label'  => __( 'Migration checks', 'yablonsky-security' ),
                'pass'   => $migration_ok,
                'detail' => sprintf( /* translators: 1: passed migration gates, 2: total migration gates. */ __( '%1$d/%2$d migration checks passed.', 'yablonsky-security' ), (int) ( $migration['passed'] ?? 0 ), (int) ( $migration['total'] ?? 0 ) ),
            ),
            array(
                'id'     => 'public_debug_artifact',
                'label'  => __( 'Public debug artifact', 'yablonsky-security' ),
                'pass'   => $debug_clear,
                'detail' => $debug_clear ? __( 'The public document tree is clear of wp-content/debug.log.', 'yablonsky-security' ) : __( 'wp-content/debug.log is present in the public document tree. Move or retire it to keep diagnostic output outside public delivery.', 'yablonsky-security' ),
            ),
        );

        $passed = count( array_filter( $gates, static fn( $gate ) => ! empty( $gate['pass'] ) ) );
        return array(
            'schema'       => 'yablonsky.security.takeover-closeout-status.v1',
            'version'      => YSEC_VERSION,
            'checked_at'   => gmdate( 'c' ),
            'ready'        => $passed === count( $gates ),
            'passed'       => $passed,
            'total'        => count( $gates ),
            'sources'      => $sources,
            'gates'        => $gates,
            'debug_clear'  => $debug_clear,
            'doctor'       => array( 'passed'=>(int) ( $doctor['passed'] ?? 0 ), 'total'=>(int) ( $doctor['total'] ?? 0 ), 'ok'=>$doctor_ok ),
            'firewall_proof'=> $firewall,
            'migration'    => array( 'passed'=>(int) ( $migration['passed'] ?? 0 ), 'total'=>(int) ( $migration['total'] ?? 0 ), 'ok'=>$migration_ok ),
        );
    }

    public static function run(): array {
        $results = array();
        foreach ( YSEC_Compatibility::report() as $item ) {
            $file = (string) ( $item['file'] ?? '' );
            if ( '' === $file ) continue;
            if ( ! empty( $item['active'] ) ) {
                $results[] = array(
                    'file'    => $file,
                    'name'    => (string) ( $item['name'] ?? $file ),
                    'ok'      => false,
                    'skipped' => true,
                    'reason'  => 'source_active',
                );
                continue;
            }
            $proof = YSEC_Migration::run_cutover_proof( $file );
            $results[] = array(
                'file'    => $file,
                'name'    => (string) ( $item['name'] ?? $file ),
                'ok'      => ! empty( $proof['ok'] ),
                'skipped' => false,
                'reason'  => ! empty( $proof['ok'] ) ? 'proved' : 'review',
            );
        }

        $status = self::status();
        $receipt = array(
            'schema'       => 'yablonsky.security.takeover-closeout.v1',
            'generated_at' => gmdate( 'c' ),
            'plugin'       => 'Yablonsky Security',
            'version'      => YSEC_VERSION,
            'ready'        => ! empty( $status['ready'] ),
            'passed'       => (int) ( $status['passed'] ?? 0 ),
            'total'        => (int) ( $status['total'] ?? 0 ),
            'source_runs'  => $results,
            'source_proofs'=> YSEC_Migration::cutover_proofs(),
            'status'       => $status,
            'activation_state_changed_by_ysec' => false,
            'wp_config_changed_by_ysec'         => false,
        );
        update_option( self::OPTION, $receipt, false );
        YSEC_Events::log(
            'takeover_closeout_run',
            array(
                'severity' => ! empty( $receipt['ready'] ) ? 'info' : 'medium',
                'family'   => 'migration',
                'state'    => ! empty( $receipt['ready'] ) ? 'verified' : 'review',
                'details'  => array(
                    'ready'  => ! empty( $receipt['ready'] ),
                    'passed' => (int) $receipt['passed'],
                    'total'  => (int) $receipt['total'],
                    'sources'=> count( $results ),
                ),
            )
        );
        return $receipt;
    }

    public static function last(): array {
        $value = get_option( self::OPTION, array() );
        return is_array( $value ) ? $value : array();
    }
}
