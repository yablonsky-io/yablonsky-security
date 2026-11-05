<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Autopilot {
    private const SNAPSHOT_OPTION = 'ysec_autopilot_snapshot_v1';
    private const RESULT_OPTION   = 'ysec_autopilot_result_v1';
    private const TX_OPTION       = 'ysec_autopilot_transaction_v1';

    public static function run(): array {
        $before_settings = YSEC_Utils::settings();
        $before_plugins  = self::active_plugins();
        $analysis        = self::analyze( $before_settings );
        $target          = self::safe_profile( $before_settings, $analysis );
        $snapshot        = array(
            'created_at' => gmdate( 'c' ),
            'version'    => YSEC_VERSION,
            'settings'   => $before_settings,
            'plugins'    => $before_plugins,
        );
        update_option( self::SNAPSHOT_OPTION, $snapshot, false );
        update_option( self::TX_OPTION, array( 'status'=>'applying', 'snapshot'=>$snapshot, 'started_at'=>gmdate('c') ), false );
        register_shutdown_function( array( __CLASS__, 'shutdown_rollback' ) );

        try {
            update_option( 'ysec_settings', $target, false );
            self::clear_runtime_caches();
            $verification = self::verify( $before_plugins );
            $rollback_reason = '';
            foreach ( $verification['checks'] as $check ) {
                if ( 'fail' === ( $check['state'] ?? '' ) && ! empty( $check['rollback'] ) ) {
                    $rollback_reason = (string) ( $check['label'] ?? 'verification_failed' );
                    break;
                }
            }
            $rolled_back = false;
            if ( '' !== $rollback_reason ) {
                self::restore_settings( $before_settings );
                $rolled_back = true;
            }
            $result = array(
                'schema'       => 'ysec-autopilot/3',
                'ran_at'       => gmdate( 'c' ),
                'analysis'     => $analysis,
                'applied'      => ! $rolled_back,
                'rolled_back'  => $rolled_back,
                'rollback_reason' => $rollback_reason,
                'verification' => $verification,
                'changes'      => self::diff_settings( $before_settings, $rolled_back ? $before_settings : $target ),
                'profile'      => $analysis['profile'],
                'proof'        => array(
                    'before_hash'=>hash('sha256',wp_json_encode($before_settings)),
                    'after_hash'=>hash('sha256',wp_json_encode($rolled_back?$before_settings:$target)),
                    'plugin_state_unchanged'=>self::active_plugins()===$before_plugins,
                ),
            );
            update_option( self::RESULT_OPTION, $result, false );
            update_option( self::TX_OPTION, array( 'status'=>$rolled_back?'rolled_back':'committed', 'finished_at'=>gmdate('c') ), false );
            YSEC_Events::log(
                $rolled_back ? 'autopilot_rolled_back' : 'autopilot_committed',
                array(
                    'severity'   => $rolled_back ? 'medium' : 'info',
                    'confidence' => 'high',
                    'state'      => $rolled_back ? 'observed' : 'protected',
                    'family'     => 'configuration',
                    'details'    => array( 'profile'=>$analysis['profile'], 'rollback_reason'=>$rollback_reason, 'check_count'=>count( $verification['checks'] ) ),
                )
            );
            return $result;
        } catch ( Throwable $e ) {
            self::restore_settings( $before_settings );
            $result=array('schema'=>'ysec-autopilot/3','ran_at'=>gmdate('c'),'analysis'=>$analysis,'applied'=>false,'rolled_back'=>true,'rollback_reason'=>'exception','verification'=>array('checks'=>array(),'hard_failures'=>1,'passed'=>false),'changes'=>array(),'profile'=>$analysis['profile']);
            update_option(self::RESULT_OPTION,$result,false);
            update_option(self::TX_OPTION,array('status'=>'rolled_back','finished_at'=>gmdate('c'),'reason'=>'exception'),false);
            return $result;
        }
    }

    public static function shutdown_rollback(): void {
        $tx=get_option(self::TX_OPTION,array());
        if(!is_array($tx)||'applying'!==($tx['status']??''))return;
        $error=error_get_last();
        if(!is_array($error)||!in_array((int)($error['type']??0),array(E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR,E_USER_ERROR,E_RECOVERABLE_ERROR),true))return;
        $snapshot=$tx['snapshot']??array();
        if(is_array($snapshot)&&is_array($snapshot['settings']??null))self::restore_settings($snapshot['settings']);
        $result=array('schema'=>'ysec-autopilot/3','ran_at'=>gmdate('c'),'applied'=>false,'rolled_back'=>true,'rollback_reason'=>'fatal_error','profile'=>'recovered','verification'=>array('checks'=>array(),'hard_failures'=>1,'passed'=>false),'changes'=>array());
        update_option(self::RESULT_OPTION,$result,false);
        update_option(self::TX_OPTION,array('status'=>'rolled_back','finished_at'=>gmdate('c'),'reason'=>'fatal_error'),false);
    }

    public static function rollback(): array {
        $snapshot = get_option( self::SNAPSHOT_OPTION, array() );
        if ( ! is_array( $snapshot ) || empty( $snapshot['settings'] ) || ! is_array( $snapshot['settings'] ) ) {
            return array( 'ok'=>false, 'message'=>__( 'No Autopilot snapshot is available.', 'yablonsky-security' ) );
        }
        self::restore_settings( $snapshot['settings'] );
        $result = array( 'ok'=>true, 'rolled_back_at'=>gmdate( 'c' ), 'snapshot_created_at'=>(string)($snapshot['created_at'] ?? '') );
        YSEC_Events::log( 'autopilot_manual_rollback', array( 'severity'=>'info', 'confidence'=>'high', 'state'=>'observed', 'family'=>'configuration' ) );
        return $result;
    }

    public static function last_result(): array {
        $value = get_option( self::RESULT_OPTION, array() );
        return is_array( $value ) ? $value : array();
    }

    public static function has_snapshot(): bool {
        $value = get_option( self::SNAPSHOT_OPTION, array() );
        return is_array( $value ) && ! empty( $value['settings'] );
    }

    private static function analyze( array $settings ): array {
        $compatibility = YSEC_Compatibility::report();
        $active_overlap = array_values( array_filter( $compatibility, static fn( $item ) => ! empty( $item['active'] ) ) );
        $captcha_ready = class_exists( 'YSEC_Captcha' ) && YSEC_Captcha::configured();
        $env = YSEC_Environment::detect();
        return array(
            'profile'          => $active_overlap ? 'safe_coexistence' : 'balanced_protection',
            'active_overlap'   => array_map( static fn( $item ) => (string) $item['name'], $active_overlap ),
            'captcha_ready'    => $captcha_ready,
            'https'            => ! empty( $env['https'] ),
            'server'           => (string) ( $env['server'] ?? 'Generic' ),
            'encryption_ready' => ! empty( $env['sodium'] ) || ! empty( $env['openssl'] ),
            'current_posture'  => YSEC_Posture::report()['score'] ?? 0,
        );
    }

    private static function safe_profile( array $current, array $analysis ): array {
        $target = $current;
        $target['observe_requests'] = 1;
        $target['extended_telemetry'] = 0;
        $target['waf_enabled'] = 1;
        $target['firewall_profile'] = empty( $analysis['active_overlap'] ) ? '6g' : '5g';
        $target['adaptive_404_shield'] = 1;
        $target['adaptive_recon_threshold'] = 15;
        $target['adaptive_recon_window'] = 10;
        $target['security_headers'] = 1;
        $target['disable_file_editor'] = 1;
        $target['reduce_user_enumeration'] = 1;
        // Low-risk anti-automation defaults: local form proof + hidden honeypot add no external dependency or visible challenge.
        $target['comment_form_proof'] = 1;
        $target['comment_honeypot'] = 1;
        $target['suspicious_rate_threshold'] = 120;
        $target['suspicious_rate_window'] = 10;
        // Scanner-rate enforcement is enabled only when no overlapping security plugin is active.
        // In coexistence mode Autopilot observes the signal but avoids duplicate enforcement.
        $target['suspicious_rate_enforce'] = empty( $analysis['active_overlap'] ) ? 1 : 0;
        $target['login_limit'] = min( max( 5, absint( $current['login_limit'] ?? 8 ) ), 8 );
        $target['login_window'] = 15;
        $target['block_minutes'] = 60;
        $target['recon_block_threshold'] = 25;
        $target['recon_block_window'] = 15;
        $target['campaign_family_threshold'] = 3;
        $target['campaign_hit_threshold'] = 35;
        $target['auto_block'] = empty( $analysis['active_overlap'] ) ? 1 : 0;
        $target['preserve_public_discovery'] = 1;
        $target['smart_response_window'] = 10;
        $target['smart_containment_score'] = 24;
        $target['smart_containment_families'] = 3;
        $target['smart_containment_attack_hits'] = 8;
        $target['retention_days'] = min( max( 7, absint( $current['retention_days'] ?? 30 ) ), 30 );
        $target['evidence_retention_info'] = 1;
        $target['evidence_retention_medium'] = 3;
        $target['evidence_retention_high'] = 7;
        $target['evidence_retention_critical'] = 30;
        $target['rollup_days'] = 365;
        $target['event_max_rows'] = min( max( 50000, absint( $current['event_max_rows'] ?? 250000 ) ), 250000 );
        if ( ! empty( $analysis['captcha_ready'] ) ) {
            foreach ( array( 'captcha_wp_login','captcha_wp_register','captcha_wp_recovery','captcha_woo_login','captcha_woo_register','captcha_woo_recovery' ) as $key ) $target[$key] = 1;
        }
        // Autopilot does not silently disable XML-RPC/Application Passwords, force 2FA, create a new integrity trust baseline,
        // or alter another plugin. Those operations need explicit site-owner context.
        return $target;
    }

    private static function verify( array $before_plugins ): array {
        $checks = array();
        $settings = YSEC_Utils::settings();
        $checks[] = self::check( 'Local control plane', ! empty( $settings['observe_requests'] ) && ! empty( $settings['waf_enabled'] ), true, __( 'Observation and application firewall are enabled.', 'yablonsky-security' ) );
        $checks[] = self::check( 'Administrator access', current_user_can( 'manage_options' ), true, __( 'The current administrator retains manage_options capability.', 'yablonsky-security' ) );
        $plugins_same = self::active_plugins() === $before_plugins;
        $checks[] = self::check( 'Plugin-state integrity', $plugins_same, true, __( 'Autopilot did not activate or deactivate another plugin.', 'yablonsky-security' ) );
        $bounded = absint( $settings['event_max_rows'] ?? 0 ) >= 10000 && absint( $settings['event_max_rows'] ?? 0 ) <= 2000000;
        $checks[] = self::check( 'Bounded evidence lifecycle', $bounded, true, __( 'Evidence storage has an explicit emergency row ceiling.', 'yablonsky-security' ) );
        if ( class_exists( 'YSEC_DB' ) && method_exists( 'YSEC_DB', 'storage_health' ) ) {
            $storage = YSEC_DB::storage_health();
            $valid = ! empty( $storage['valid'] );
            $pressure = (float) ( $storage['pressure_percent'] ?? 0 );
            // translators: %.1f: percentage of configured evidence row ceiling currently in use.
            $pressure_detail = sprintf( __( 'Current storage pressure is %.1f%% of the configured emergency ceiling.', 'yablonsky-security' ), $pressure );
            $checks[] = array(
                'label'    => __( 'Evidence storage pressure', 'yablonsky-security' ),
                'state'    => $valid && $pressure < 90 ? 'pass' : 'warning',
                'rollback' => false,
                'detail'   => $valid ? $pressure_detail : __( 'Review required', 'yablonsky-security' ),
            );
        }
        $checks[] = self::surface_check( home_url( '/' ), __( 'Public site', 'yablonsky-security' ) );
        $checks[] = self::surface_check( wp_login_url(), __( 'WordPress login', 'yablonsky-security' ) );
        if ( class_exists( 'WooCommerce' ) && function_exists( 'wc_get_page_permalink' ) ) {
            $account = wc_get_page_permalink( 'myaccount' );
            if ( is_string( $account ) && '' !== $account ) $checks[] = self::surface_check( $account, __( 'WooCommerce account', 'yablonsky-security' ) );
        }
        $hard_failures = count( array_filter( $checks, static fn( $check ) => 'fail' === ( $check['state'] ?? '' ) && ! empty( $check['rollback'] ) ) );
        return array( 'checks'=>$checks, 'hard_failures'=>$hard_failures, 'passed'=>$hard_failures === 0 );
    }

    private static function surface_check( string $url, string $label ): array {
        $response = wp_safe_remote_get( $url, array( 'timeout'=>8, 'redirection'=>3, 'sslverify'=>true, 'headers'=>array( 'User-Agent'=>'Yablonsky-Security-Autopilot/' . YSEC_VERSION ) ) );
        if ( is_wp_error( $response ) ) {
            return array( 'label'=>$label, 'state'=>'warning', 'rollback'=>false, 'detail'=>__( 'Loopback verification was unavailable; local checks passed, so the configuration was not rolled back.', 'yablonsky-security' ) );
        }
        $code = (int) wp_remote_retrieve_response_code( $response );
        $ok = $code > 0 && $code < 500;
        return array( 'label'=>$label, 'state'=>$ok?'pass':'fail', 'rollback'=>!$ok, 'detail'=>sprintf( 'HTTP %d', $code ) );
    }

    private static function check( string $label, bool $ok, bool $rollback, string $detail ): array {
        return array( 'label'=>$label, 'state'=>$ok?'pass':'fail', 'rollback'=>$rollback && !$ok, 'detail'=>$detail );
    }

    private static function active_plugins(): array {
        $plugins = get_option( 'active_plugins', array() );
        if ( ! is_array( $plugins ) ) $plugins = array();
        $network = is_multisite() ? get_site_option( 'active_sitewide_plugins', array() ) : array();
        if ( ! is_array( $network ) ) $network = array();
        $state = array_values( array_map( static fn( $plugin ) => 'site:' . $plugin, $plugins ) );
        foreach ( array_keys( $network ) as $plugin ) $state[] = 'network:' . $plugin;
        sort( $state );
        return $state;
    }

    private static function diff_settings( array $before, array $after ): array {
        $out = array();
        foreach ( $after as $key=>$value ) {
            if ( ! array_key_exists( $key, $before ) || $before[$key] !== $value ) $out[$key] = array( 'before'=>$before[$key] ?? null, 'after'=>$value );
        }
        return $out;
    }

    private static function restore_settings( array $settings ): void {
        update_option( 'ysec_settings', $settings, false );
        self::clear_runtime_caches();
    }

    private static function clear_runtime_caches(): void {
        delete_transient( 'ysec_event_summary_24h_v2' );
        delete_transient( 'ysec_event_storage_summary_v2' );
        delete_transient( 'ysec_compatibility_report_v2' );
    }
}
