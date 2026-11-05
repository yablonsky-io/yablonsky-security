<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Migration {
    private const APPLY_SNAPSHOT_OPTION = 'ysec_migration_apply_snapshot_v1';
    private const APPLY_RESULT_OPTION   = 'ysec_migration_apply_result_v1';
    private const CUTOVER_PROOF_OPTION  = 'ysec_cutover_proof_v1';
    private const CUTOVER_PROOFS_OPTION = 'ysec_cutover_proofs_v1';

    public static function source_snapshot( string $file ): array {
        $base = array( 'file'=>$file, 'readable'=>false, 'signals'=>array(), 'notes'=>array() );
        if ( 'all-in-one-wp-security-and-firewall/wp-security.php' === $file ) {
            $cfg = get_option( 'aio_wp_security_configs', false );
            $base['readable'] = is_array( $cfg );
            if ( is_array( $cfg ) ) {
                $keys = array(
                    'aiowps_enable_login_captcha'=>'Login CAPTCHA',
                    'aiowps_enable_woo_login_captcha'=>'Woo login CAPTCHA',
                    'aiowps_enable_login_honeypot'=>'Login honeypot',
                    'aiowps_enable_6g_firewall'=>'6G firewall',
                    'aiowps_enable_lost_password_captcha'=>'Recovery CAPTCHA',
                    'aiowps_enable_registration_page_captcha'=>'Registration CAPTCHA',
                );
                foreach ( $keys as $key=>$label ) if ( array_key_exists( $key, $cfg ) ) $base['signals'][$label] = (string) $cfg[$key];
                /* translators: %d: number of source plugin config keys. */
                $base['notes'][] = sprintf( __( 'AIOS configuration option is readable (%d keys).', 'yablonsky-security' ), count( $cfg ) );
            }
            return $base;
        }
        if ( 'wordfence/wordfence.php' === $file ) {
            global $wpdb;
            $table = $wpdb->prefix . 'wfConfig';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Read-only migration inventory of an explicitly detected competitor-owned table.
            $exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
            $base['readable'] = $exists === $table;
            if ( $base['readable'] ) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Read-only bounded migration preview of six exact allowlisted Wordfence configuration keys.
                $rows = $wpdb->get_results(
                    $wpdb->prepare(
                        'SELECT name,val FROM %i WHERE name IN (%s,%s,%s,%s,%s,%s)',
                        $table,
                        'firewallEnabled',
                        'autoBlockScanners',
                        'loginSecurityEnabled',
                        'loginSec_maskLoginErrors',
                        'loginSec_disableApplicationPasswords',
                        'disableCodeExecutionUploads'
                    ),
                    ARRAY_A
                ) ?: array();
                foreach ( $rows as $row ) $base['signals'][(string)$row['name']] = is_scalar($row['val']) ? substr((string)$row['val'],0,80) : '';
                $base['notes'][] = __( 'Wordfence wfConfig table is readable for a bounded allowlisted migration preview.', 'yablonsky-security' );
            }
            return $base;
        }
        if ( 'hide-my-wp/index.php' === $file ) {
            $candidate = get_option( 'hmwp_options', false );
            $base['readable'] = is_array( $candidate );
            $base['notes'][] = $base['readable'] ? __( 'Hide My WP option bundle is readable for future mapping.', 'yablonsky-security' ) : __( 'Hide My WP is detected, but no supported config bundle was found for automated mapping.', 'yablonsky-security' );
        }
        return $base;
    }

    public static function mapping_preview( string $file ): array {
        $snapshot = self::source_snapshot( $file );
        $rows = array();
        if ( empty( $snapshot['readable'] ) ) return $rows;
        $signals = is_array( $snapshot['signals'] ?? null ) ? $snapshot['signals'] : array();
        if ( 'all-in-one-wp-security-and-firewall/wp-security.php' === $file ) {
            $map = array(
                'Login CAPTCHA'        => array( 'target'=>'captcha_wp_login', 'label'=>__( 'WordPress login verification', 'yablonsky-security' ), 'kind'=>'bool' ),
                'Woo login CAPTCHA'    => array( 'target'=>'captcha_woo_login', 'label'=>__( 'WooCommerce login verification', 'yablonsky-security' ), 'kind'=>'bool' ),
                'Login honeypot'       => array( 'target'=>'firewall_policy_login_honeypot', 'label'=>__( 'Login honeypot', 'yablonsky-security' ), 'kind'=>'bool' ),
                '6G firewall'          => array( 'target'=>'firewall_profile', 'label'=>__( 'Firewall profile', 'yablonsky-security' ), 'kind'=>'profile6g' ),
                'Recovery CAPTCHA'     => array( 'target'=>'captcha_wp_recovery', 'label'=>__( 'WordPress recovery verification', 'yablonsky-security' ), 'kind'=>'bool' ),
                'Registration CAPTCHA' => array( 'target'=>'captcha_wp_register', 'label'=>__( 'WordPress registration verification', 'yablonsky-security' ), 'kind'=>'bool' ),
            );
            foreach ( $map as $source=>$target ) {
                if ( ! array_key_exists( $source, $signals ) ) continue;
                $enabled = self::source_truthy( (string) $signals[$source] );
                $value = 'profile6g' === $target['kind'] ? ( $enabled ? '6g' : null ) : ( $enabled ? 1 : 0 );
                $proposed = 'profile6g' === $target['kind'] ? ( $enabled ? '6g' : __( 'Keep current profile', 'yablonsky-security' ) ) : ( $enabled ? __( 'Enable', 'yablonsky-security' ) : __( 'Disable', 'yablonsky-security' ) );
                $rows[] = array(
                    'source'=>$source,
                    'source_value'=>(string)$signals[$source],
                    'target'=>$target['target'],
                    'target_label'=>$target['label'],
                    'proposed'=>$proposed,
                    'proposed_value'=>$value,
                    'mode'=>'preview_only',
                    'applyable'=>null !== $value,
                );
            }
        } elseif ( 'wordfence/wordfence.php' === $file ) {
            $map = array(
                'firewallEnabled'                      => array( 'target'=>'waf_enabled', 'label'=>__( 'Application firewall', 'yablonsky-security' ) ),
                'autoBlockScanners'                    => array( 'target'=>'auto_block', 'label'=>__( 'Automatic scanner response', 'yablonsky-security' ) ),
                'loginSec_maskLoginErrors'             => array( 'target'=>'reduce_user_enumeration', 'label'=>__( 'Generic login errors / enumeration reduction', 'yablonsky-security' ) ),
                'loginSec_disableApplicationPasswords' => array( 'target'=>'disable_application_passwords', 'label'=>__( 'Application Password policy', 'yablonsky-security' ) ),
            );
            foreach ( $map as $source=>$target ) {
                if ( ! array_key_exists( $source, $signals ) ) continue;
                $enabled = self::source_truthy( (string) $signals[$source] );
                $rows[] = array(
                    'source'=>$source,
                    'source_value'=>(string)$signals[$source],
                    'target'=>$target['target'],
                    'target_label'=>$target['label'],
                    'proposed'=>$enabled ? __( 'Enable', 'yablonsky-security' ) : __( 'Disable', 'yablonsky-security' ),
                    'proposed_value'=>$enabled ? 1 : 0,
                    'mode'=>'preview_only',
                    'applyable'=>true,
                );
            }
            if ( array_key_exists( 'disableCodeExecutionUploads', $signals ) ) {
                $rows[] = array( 'source'=>'disableCodeExecutionUploads', 'source_value'=>(string)$signals['disableCodeExecutionUploads'], 'target'=>'upload_guard', 'target_label'=>__( 'Executable upload protection', 'yablonsky-security' ), 'proposed'=>__( 'Review built-in YSec upload guard', 'yablonsky-security' ), 'proposed_value'=>null, 'mode'=>'manual_review', 'applyable'=>false );
            }
            if ( array_key_exists( 'loginSecurityEnabled', $signals ) ) {
                $rows[] = array( 'source'=>'loginSecurityEnabled', 'source_value'=>(string)$signals['loginSecurityEnabled'], 'target'=>'account_protection', 'target_label'=>__( 'Account / 2FA protection', 'yablonsky-security' ), 'proposed'=>__( 'Review YSec account controls', 'yablonsky-security' ), 'proposed_value'=>null, 'mode'=>'manual_review', 'applyable'=>false );
            }
        }
        return array_slice( $rows, 0, 20 );
    }

    public static function apply_selected_mapping( string $file, array $targets ): array {
        $targets = array_values( array_unique( array_filter( array_map( 'sanitize_key', $targets ) ) ) );
        $rows = self::mapping_preview( $file );
        if ( ! $rows ) return array( 'ok'=>false, 'message'=>__( 'No supported source settings are available for guided mapping.', 'yablonsky-security' ) );

        $allowed = array();
        foreach ( $rows as $row ) {
            if ( empty( $row['applyable'] ) ) continue;
            $allowed[ (string) $row['target'] ] = $row;
        }
        $selected = array();
        foreach ( $targets as $target ) if ( isset( $allowed[$target] ) ) $selected[$target] = $allowed[$target];
        if ( ! $selected ) return array( 'ok'=>false, 'message'=>__( 'Select at least one supported mapping row to apply.', 'yablonsky-security' ) );

        $before_settings = YSEC_Utils::settings();
        $before_policy = YSEC_Firewall_Policy::settings();
        $after_settings = $before_settings;
        $after_policy = $before_policy;
        $changes = array();
        foreach ( $selected as $target=>$row ) {
            $value = $row['proposed_value'];
            if ( null === $value ) continue;

            if ( 'firewall_policy_login_honeypot' === $target ) {
                $value = empty( $value ) ? 0 : 1;
                if ( (int) ( $after_policy['login_honeypot'] ?? 0 ) === $value ) continue;
                $changes['firewall_policy.login_honeypot'] = array(
                    'before'=>(int) ( $after_policy['login_honeypot'] ?? 0 ),
                    'after'=>$value,
                    'source'=>(string) $row['source'],
                );
                $after_policy['login_honeypot'] = $value;
                continue;
            }

            if ( 'firewall_profile' === $target && ! in_array( $value, array( 'minimal','5g','6g','7g','8g' ), true ) ) continue;
            if ( 'firewall_profile' !== $target ) $value = empty( $value ) ? 0 : 1;
            if ( ! array_key_exists( $target, $after_settings ) ) continue;
            if ( $after_settings[$target] === $value ) continue;
            $changes['settings.' . $target] = array( 'before'=>$after_settings[$target], 'after'=>$value, 'source'=>(string)$row['source'] );
            $after_settings[$target] = $value;
        }
        if ( ! $changes ) return array( 'ok'=>true, 'changed'=>0, 'message'=>__( 'Selected mappings already match the current YSec configuration.', 'yablonsky-security' ) );

        $policy_sanitized = $after_policy;
        if ( $after_policy !== $before_policy ) {
            $policy_sanitized = YSEC_Firewall_Policy::sanitize( $after_policy );
            if ( is_wp_error( $policy_sanitized ) ) {
                return array( 'ok'=>false, 'message'=>$policy_sanitized->get_error_message() );
            }
        }

        $snapshot = array(
            'schema'=>'yablonsky.security.migration-apply-snapshot.v1',
            'captured_at'=>gmdate('c'),
            'source_file'=>$file,
            'settings'=>$before_settings,
            'settings_hash'=>hash( 'sha256', wp_json_encode( $before_settings ) ),
            'firewall_policy'=>$before_policy,
            'firewall_policy_hash'=>hash( 'sha256', wp_json_encode( $before_policy ) ),
        );
        update_option( self::APPLY_SNAPSHOT_OPTION, $snapshot, false );
        if ( $after_settings !== $before_settings ) update_option( 'ysec_settings', $after_settings, false );
        if ( $policy_sanitized !== $before_policy ) update_option( 'ysec_firewall_policy', $policy_sanitized, false );
        delete_transient( 'ysec_compatibility_report_v2' );
        $result = array(
            'schema'=>'yablonsky.security.migration-apply-result.v1',
            'ok'=>true,
            'applied_at'=>gmdate('c'),
            'source_file'=>$file,
            'changed'=>count($changes),
            'changes'=>$changes,
            'stores_changed'=>array_values( array_filter( array(
                $after_settings !== $before_settings ? 'ysec_settings' : '',
                $policy_sanitized !== $before_policy ? 'ysec_firewall_policy' : '',
            ) ) ),
            'source_plugin_state_unchanged'=>true,
        );
        update_option( self::APPLY_RESULT_OPTION, $result, false );
        YSEC_Events::log( 'migration_mapping_applied', array( 'severity'=>'info', 'family'=>'migration', 'state'=>'observed', 'details'=>array( 'source_file'=>$file, 'changed'=>count($changes), 'source_plugin_state_unchanged'=>true ) ) );
        return $result;
    }

    public static function rollback_last_mapping(): array {
        $snapshot = get_option( self::APPLY_SNAPSHOT_OPTION, array() );
        if ( ! is_array( $snapshot ) || empty( $snapshot['settings'] ) || ! is_array( $snapshot['settings'] ) ) {
            return array( 'ok'=>false, 'message'=>__( 'No guided-mapping rollback snapshot is available.', 'yablonsky-security' ) );
        }
        update_option( 'ysec_settings', $snapshot['settings'], false );
        if ( isset( $snapshot['firewall_policy'] ) && is_array( $snapshot['firewall_policy'] ) ) {
            // Restore the exact pre-mapping YSec policy snapshot. Guided mapping never changes network lists.
            update_option( 'ysec_firewall_policy', $snapshot['firewall_policy'], false );
        }
        delete_transient( 'ysec_compatibility_report_v2' );
        $result = array( 'ok'=>true, 'rolled_back_at'=>gmdate('c'), 'snapshot_created_at'=>(string)($snapshot['captured_at'] ?? ''), 'restored_stores'=>array( 'ysec_settings', 'ysec_firewall_policy' ) );
        YSEC_Events::log( 'migration_mapping_rolled_back', array( 'severity'=>'info', 'family'=>'migration', 'state'=>'observed' ) );
        return $result;
    }

    public static function last_mapping_result(): array {
        $value = get_option( self::APPLY_RESULT_OPTION, array() );
        return is_array( $value ) ? $value : array();
    }

    public static function has_mapping_snapshot(): bool {
        $value = get_option( self::APPLY_SNAPSHOT_OPTION, array() );
        return is_array( $value ) && ! empty( $value['settings'] );
    }

    private static function source_truthy( string $value ): bool {
        return in_array( strtolower( trim( $value ) ), array( '1','true','yes','on','enabled' ), true );
    }

    public static function readiness(): array {
        $settings = YSEC_Utils::settings();
        $baseline = get_option( 'ysec_integrity_baseline', array() );
        $proof = YSEC_Firewall_Proof::last();
        $proof_engine = is_array( $proof['engine'] ?? null ) ? $proof['engine'] : array();
        $private_entry_ready = 'off' !== YSEC_Private_Login::mode() && '' !== (string) ( $settings['private_login_slug'] ?? '' ) && YSEC_Private_Login::pretty_permalinks();
        $gates = array(
            array( 'key'=>'waf', 'label'=>__( 'YSec application firewall enabled', 'yablonsky-security' ), 'pass'=>!empty($settings['waf_enabled']) ),
            array( 'key'=>'profile', 'label'=>__( 'Explicit firewall profile selected', 'yablonsky-security' ), 'pass'=>in_array($settings['firewall_profile']??'',array('5g','6g','7g','8g'),true) ),
            array( 'key'=>'firewall_proof', 'label'=>__( 'Current firewall profile deterministic proof passes', 'yablonsky-security' ), 'pass'=>!empty($proof_engine['ok']) && (string)($proof['profile']??'') === (string)($settings['firewall_profile']??'') ),
            array( 'key'=>'private_entry', 'label'=>__( 'Private administration entry prepared for path cutover', 'yablonsky-security' ), 'pass'=>$private_entry_ready ),
            array( 'key'=>'integrity', 'label'=>__( 'Trusted integrity baseline exists', 'yablonsky-security' ), 'pass'=>!empty($baseline['files']) ),
            array( 'key'=>'retention', 'label'=>__( 'Bounded evidence lifecycle configured', 'yablonsky-security' ), 'pass'=>absint($settings['event_max_rows']??0)>=10000 ),
            array( 'key'=>'recovery', 'label'=>__( 'Current administrator retains manage_options', 'yablonsky-security' ), 'pass'=>current_user_can('manage_options') ),
        );
        return array( 'gates'=>$gates, 'passed'=>count(array_filter($gates,static fn($g)=>!empty($g['pass']))), 'total'=>count($gates) );
    }

    public static function capture_snapshot(): array {
        $report = YSEC_Compatibility::report();
        $sources = array();
        foreach ( $report as $item ) $sources[] = array_merge( $item, array( 'snapshot'=>self::source_snapshot((string)$item['file']), 'mapping_preview'=>self::mapping_preview((string)$item['file']) ) );
        $snapshot = array(
            'schema'=>'yablonsky.security.cutover-snapshot.v1',
            'captured_at'=>gmdate('c'),
            'ysec_version'=>YSEC_VERSION,
            'ysec_settings_hash'=>hash('sha256', wp_json_encode(YSEC_Utils::settings())),
            'firewall_policy_hash'=>hash('sha256', wp_json_encode(YSEC_Firewall_Policy::settings())),
            'sources'=>$sources,
            'readiness'=>self::readiness(),
            'activation_state_unchanged'=>true,
        );
        update_option( 'ysec_cutover_snapshot_v1', $snapshot, false );
        YSEC_Events::log( 'cutover_snapshot_captured', array( 'severity'=>'info','family'=>'migration','details'=>array( 'sources'=>count($sources) ) ) );
        return $snapshot;
    }

    public static function last_snapshot(): array {
        $v = get_option( 'ysec_cutover_snapshot_v1', array() );
        return is_array($v) ? $v : array();
    }

    public static function run_cutover_proof( string $file ): array {
        if ( ! function_exists( 'is_plugin_active' ) ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $known = false;
        foreach ( YSEC_Compatibility::report() as $item ) if ( (string)($item['file'] ?? '') === $file ) { $known = $item; break; }
        if ( ! is_array( $known ) ) return array( 'ok'=>false, 'message'=>__( 'The selected source security product is not installed or is not supported by the cutover proof.', 'yablonsky-security' ) );

        $doctor = YSEC_Doctor::report();
        $firewall = YSEC_Firewall_Proof::run();
        $firewall_receipt = YSEC_Firewall_Proof::receipt();
        $readiness = self::readiness();
        $source_inactive = ! is_plugin_active( $file );
        $doctor_ok = ! empty( $doctor['ok'] ) || ( isset( $doctor['passed'], $doctor['total'] ) && (int)$doctor['passed'] === (int)$doctor['total'] );
        $firewall_ok = ! empty( $firewall_receipt['proved'] ) && ! empty( $firewall_receipt['rule_engine']['pass'] ) && ! empty( $firewall_receipt['live_enforcement']['pass'] );
        $settings = YSEC_Utils::settings();
        $private_mode = class_exists( 'YSEC_Private_Login' ) ? YSEC_Private_Login::mode() : 'off';
        $private_ok = 'off' === $private_mode || ( '' !== (string)($settings['private_login_slug'] ?? '') && YSEC_Private_Login::aliases_active() );
        $snapshot = self::last_snapshot();
        $snapshot_ok = ! empty( $snapshot['captured_at'] );
        $ok = $source_inactive && $doctor_ok && $firewall_ok && $private_ok && $snapshot_ok && ! empty( $settings['waf_enabled'] );

        $receipt = array(
            'schema'=>'yablonsky.security.cutover-proof.v1',
            'generated_at'=>gmdate('c'),
            'plugin'=>'Yablonsky Security',
            'version'=>YSEC_VERSION,
            'source'=>array(
                'file'=>$file,
                'name'=>(string)($known['name'] ?? $file),
                'installed'=>true,
                'active'=>!$source_inactive,
            ),
            'checks'=>array(
                'pre_cutover_snapshot'=>$snapshot_ok,
                'source_plugin_inactive'=>$source_inactive,
                'security_doctor'=>$doctor_ok,
                'firewall_live_proof'=>$firewall_ok,
                'private_entry'=>$private_ok,
                'waf_enabled'=>!empty($settings['waf_enabled']),
                'administrator_access'=>current_user_can('manage_options'),
            ),
            'doctor'=>array( 'passed'=>(int)($doctor['passed'] ?? 0), 'total'=>(int)($doctor['total'] ?? 0), 'ok'=>$doctor_ok ),
            'firewall_proof'=>$firewall_receipt,
            'readiness'=>array( 'passed'=>(int)$readiness['passed'], 'total'=>(int)$readiness['total'] ),
            'settings_hash'=>hash( 'sha256', wp_json_encode( $settings ) ),
            'source_plugin_state_changed_by_ysec'=>false,
            'ok'=>$ok,
        );
        update_option( self::CUTOVER_PROOF_OPTION, $receipt, false );
        $proofs = get_option( self::CUTOVER_PROOFS_OPTION, array() );
        if ( ! is_array( $proofs ) ) $proofs = array();
        $proofs[ $file ] = $receipt;
        update_option( self::CUTOVER_PROOFS_OPTION, $proofs, false );
        YSEC_Events::log( 'cutover_proof_run', array( 'severity'=>$ok?'info':'medium', 'family'=>'migration', 'state'=>$ok?'verified':'review', 'details'=>array( 'source_file'=>$file, 'ok'=>$ok ) ) );
        return $receipt;
    }

    public static function cutover_proofs(): array {
        $proofs = get_option( self::CUTOVER_PROOFS_OPTION, array() );
        if ( ! is_array( $proofs ) ) $proofs = array();
        $legacy = self::last_cutover_proof();
        $legacy_file = (string) ( $legacy['source']['file'] ?? '' );
        if ( '' !== $legacy_file && empty( $proofs[ $legacy_file ] ) ) $proofs[ $legacy_file ] = $legacy;
        return $proofs;
    }

    public static function cutover_proof_for( string $file ): array {
        $proofs = self::cutover_proofs();
        return isset( $proofs[ $file ] ) && is_array( $proofs[ $file ] ) ? $proofs[ $file ] : array();
    }

    public static function last_cutover_proof(): array {
        $value = get_option( self::CUTOVER_PROOF_OPTION, array() );
        return is_array( $value ) ? $value : array();
    }
}
