<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class YSEC_Admin {
    public static function boot(): void {
        add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
        add_action( 'admin_init', array( __CLASS__, 'actions' ) );
        add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
        add_action( 'wp_ajax_ysec_ai_preview', array( __CLASS__, 'ajax_ai_preview' ) );
        add_action( 'wp_ajax_ysec_event_action', array( __CLASS__, 'ajax_event_action' ) );
        add_action( 'wp_ajax_ysec_campaign_action', array( __CLASS__, 'ajax_campaign_action' ) );
        add_action( 'wp_ajax_ysec_account_action', array( __CLASS__, 'ajax_account_action' ) );
        add_action( 'wp_ajax_ysec_firewall_action', array( __CLASS__, 'ajax_firewall_action' ) );
        add_action( 'wp_ajax_ysec_malware_scan_start', array( __CLASS__, 'ajax_malware_scan_start' ) );
        add_action( 'wp_ajax_ysec_malware_scan_step', array( __CLASS__, 'ajax_malware_scan_step' ) );
        add_action( 'wp_ajax_ysec_malware_scan_pause', array( __CLASS__, 'ajax_malware_scan_pause' ) );
        add_action( 'wp_ajax_ysec_malware_scan_resume', array( __CLASS__, 'ajax_malware_scan_resume' ) );
        add_action( 'wp_ajax_ysec_malware_scan_cancel', array( __CLASS__, 'ajax_malware_scan_cancel' ) );
        add_action( 'wp_ajax_ysec_malware_scan_status', array( __CLASS__, 'ajax_malware_scan_status' ) );
        add_action( 'admin_post_ysec_policy_export', array( __CLASS__, 'export_policy' ) );
        add_action( 'admin_post_ysec_fastpath_export', array( __CLASS__, 'export_fastpath' ) );
        add_action( 'admin_post_ysec_firewall_proof_run', array( __CLASS__, 'run_firewall_proof' ) );
        add_action( 'admin_post_ysec_firewall_proof_export', array( __CLASS__, 'export_firewall_proof' ) );
        add_action( 'admin_post_ysec_security_headers_export', array( __CLASS__, 'export_security_headers_report' ) );
        add_action( 'admin_post_ysec_posture_report', array( __CLASS__, 'export_posture_report' ) );
        add_action( 'admin_post_ysec_malware_export', array( __CLASS__, 'export_malware_report' ) );
        add_action( 'admin_post_ysec_malware_forensic_export', array( __CLASS__, 'export_malware_forensic_zip' ) );
        add_action( 'admin_post_ysec_doctor_export', array( __CLASS__, 'export_doctor_report' ) );
        add_action( 'admin_post_ysec_cutover_proof_export', array( __CLASS__, 'export_cutover_proof' ) );
        add_action( 'admin_post_ysec_takeover_closeout_export', array( __CLASS__, 'export_takeover_closeout' ) );
        add_action( 'wp_ajax_ysec_tab', array( __CLASS__, 'ajax_tab' ) );
        add_action( 'wp_ajax_ysec_autopilot_run', array( __CLASS__, 'ajax_autopilot_run' ) );
        add_action( 'wp_ajax_ysec_autopilot_rollback', array( __CLASS__, 'ajax_autopilot_rollback' ) );
        add_filter( 'plugin_action_links_' . plugin_basename( YSEC_FILE ), array( __CLASS__, 'plugin_action_links' ) );
    }

    public static function plugin_action_links( array $links ): array {
        $url=add_query_arg(array('page'=>'yablonsky-security','tab'=>'overview'),admin_url('admin.php'));
        array_unshift($links,'<a href="'.esc_url($url).'">'.esc_html__('Open Security','yablonsky-security').'</a>');
        return $links;
    }

    private static function tabs(): array {
        return array(
            'overview'=>__('Overview','yablonsky-security'),'events'=>__('Events','yablonsky-security'),'recon'=>__('Reconnaissance','yablonsky-security'),
            'firewall'=>__('Firewall','yablonsky-security'),'integrity'=>__('Integrity','yablonsky-security'),'vulnerabilities'=>__('Vulnerabilities','yablonsky-security'),
            'malware'=>__('Malware','yablonsky-security'),'accounts'=>__('Accounts','yablonsky-security'),'comment_abuse'=>__('Comment abuse','yablonsky-security'),'hardening'=>__('Hardening','yablonsky-security'),
            'compatibility'=>__('Compatibility','yablonsky-security'),'ai'=>__('Yablonsky AI','yablonsky-security'),'settings'=>__('Settings','yablonsky-security'),
        );
    }

    public static function ajax_tab(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( array( 'message' => __( 'Not allowed.', 'yablonsky-security' ) ), 403 );
        check_ajax_referer( 'ysec_tab', 'nonce' );
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- AJAX nonce is verified immediately above.
        $tab = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : 'overview';
        $tabs = self::tabs();
        if ( ! isset( $tabs[ $tab ] ) ) wp_send_json_error( array( 'message' => __( 'Unknown security section.', 'yablonsky-security' ) ), 400 );
        try {
            $html = self::render_tab_html( $tab );
        } catch ( Throwable $error ) {
            wp_send_json_error( array( 'message' => __( 'This security section could not be rendered. Reload the page and try again.', 'yablonsky-security' ), 'code' => 'tab_render_failed' ), 500 );
        }
        wp_send_json_success( array( 'html' => $html, 'tab' => $tab, 'title' => $tabs[ $tab ] ) );
    }

    private static function render_tab_html( string $tab ): string {
        $callback = array( __CLASS__, 'tab_' . $tab );
        if ( ! is_callable( $callback ) ) {
            return '<section class="ysec-surface"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Runtime recovery', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'Security section refresh', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'The YSec admin shell remains available while this section is refreshed. Reinstall the current package, then reload this page.', 'yablonsky-security' ) . '</p></div></div></section>';
        }
        $buffer_level = ob_get_level();
        ob_start();
        try {
            call_user_func( $callback );
            return (string) ob_get_clean();
        } catch ( Throwable $error ) {
            while ( ob_get_level() > $buffer_level ) ob_end_clean();
            throw $error;
        }
    }

    public static function ajax_autopilot_run(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( array( 'message'=>__( 'Not allowed.', 'yablonsky-security' ) ), 403 );
        check_ajax_referer( 'ysec_autopilot', 'nonce' );
        wp_send_json_success( YSEC_Autopilot::run() );
    }

    public static function ajax_autopilot_rollback(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( array( 'message'=>__( 'Not allowed.', 'yablonsky-security' ) ), 403 );
        check_ajax_referer( 'ysec_autopilot', 'nonce' );
        $result = YSEC_Autopilot::rollback();
        if ( empty( $result['ok'] ) ) wp_send_json_error( $result, 400 );
        wp_send_json_success( $result );
    }

    private static function malware_scan_guard(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( array( 'message'=>__( 'Not allowed.', 'yablonsky-security' ) ), 403 );
        check_ajax_referer( 'ysec_malware_scan', 'nonce' );
    }

    public static function ajax_malware_scan_start(): void {
        self::malware_scan_guard();
        wp_send_json_success( YSEC_Malware::full_scan_start() );
    }

    public static function ajax_malware_scan_step(): void {
        self::malware_scan_guard();
        wp_send_json_success( YSEC_Malware::full_scan_step() );
    }

    public static function ajax_malware_scan_pause(): void {
        self::malware_scan_guard();
        wp_send_json_success( YSEC_Malware::full_scan_pause() );
    }

    public static function ajax_malware_scan_resume(): void {
        self::malware_scan_guard();
        wp_send_json_success( YSEC_Malware::full_scan_resume() );
    }

    public static function ajax_malware_scan_cancel(): void {
        self::malware_scan_guard();
        wp_send_json_success( YSEC_Malware::full_scan_cancel() );
    }

    public static function ajax_malware_scan_status(): void {
        self::malware_scan_guard();
        wp_send_json_success( YSEC_Malware::full_scan_public_state() );
    }

    public static function menu(): void {
        add_menu_page( __( 'Yablonsky Security', 'yablonsky-security' ), __( 'Yablonsky Security', 'yablonsky-security' ), 'manage_options', 'yablonsky-security', array( __CLASS__, 'page' ), 'dashicons-shield-alt', 58 );
    }

    public static function assets( string $hook ): void {
        if ( 'toplevel_page_yablonsky-security' !== $hook ) {
            return;
        }
        $asset_version = str_replace( '.', '-', YSEC_VERSION );
        // Put the release coordinate in the asset path itself. Some optimization/privacy plugins
        // strip ?ver= query arguments, so path-versioning prevents stale admin CSS/JS after upgrades.
        wp_enqueue_style( 'ysec-admin', YSEC_URL . 'assets/admin-' . $asset_version . '.css', array(), YSEC_VERSION );
        wp_enqueue_script( 'ysec-admin', YSEC_URL . 'assets/admin-' . $asset_version . '.js', array( 'jquery' ), YSEC_VERSION, true );
        wp_localize_script(
            'ysec-admin',
            'YSEC_ADMIN',
            array(
                'ajaxUrl' => admin_url( 'admin-ajax.php' ),
                'nonce'          => wp_create_nonce( 'ysec_admin_tables' ),
                'aiPreviewNonce' => wp_create_nonce( 'ysec_ai_preview' ),
                'loading'        => __( 'Loading…', 'yablonsky-security' ),
                'aiProcessing'   => __( 'Processing…', 'yablonsky-security' ),
                'filterNoMatches' => __( 'No components match these filters.', 'yablonsky-security' ),
                'error'             => __( 'Unable to load security data. Please try again.', 'yablonsky-security' ),
                'confirmDisconnect' => __( 'Disconnect Yablonsky AI from this site? Local security protection will remain unchanged.', 'yablonsky-security' ),
                'previewError'      => __( 'Evidence preview could not be refreshed.', 'yablonsky-security' ),
                'actionNonce'       => wp_create_nonce( 'ysec_event_action' ),
                'exportNonce'       => wp_create_nonce( 'ysec_export_dataset' ),
                'exportUrl'         => admin_url( 'admin-post.php' ),
                'tabNonce'          => wp_create_nonce( 'ysec_tab' ),
                'jobNonce'          => wp_create_nonce( 'ysec_jobs' ),
                'autopilotNonce'    => wp_create_nonce( 'ysec_autopilot' ),
                'malwareScanNonce'  => wp_create_nonce( 'ysec_malware_scan' ),
                'malwareConfirmStart' => __( 'Scan the complete wp-content scope now?', 'yablonsky-security' ),
                'malwareConfirmRestart' => __( 'Start a new full wp-content scan now? This resets the current scan counters and begins from the start.', 'yablonsky-security' ),
                'malwareConfirmCancel' => __( 'Stop the current malware scan? Progress stops here and existing findings remain available.', 'yablonsky-security' ),
                'malwareScanAgain' => __( 'Scan again', 'yablonsky-security' ),
                'malwareScanAction' => __( 'Scan wp-content', 'yablonsky-security' ),
                'malwareStartNew' => __( 'Start new scan', 'yablonsky-security' ),
                'malwareProgressFull' => __( 'Scanning full scope', 'yablonsky-security' ),
                'malwareProgressEstimatedSuffix' => __( 'of estimated scope', 'yablonsky-security' ),
                'malwareElapsed' => __( 'Elapsed', 'yablonsky-security' ),
                'malwareEta' => __( 'Estimated remaining', 'yablonsky-security' ),
                'malwareEtaCalculating' => __( 'Estimating…', 'yablonsky-security' ),
                'malwareActivityEmpty' => __( 'File activity will appear here while the scan is running.', 'yablonsky-security' ),
                'malwareSummaryReady' => __( 'Ready to scan the complete wp-content scope.', 'yablonsky-security' ),
                'malwareSummaryRunning' => __( 'Scan in progress. File activity and counters update continuously.', 'yablonsky-security' ),
                'malwareSummaryPaused' => __( 'Scan paused. Progress is saved and ready to resume.', 'yablonsky-security' ),
                'malwareSummaryStopped' => __( 'Scan stopped. Progress is preserved and ready to resume, or you can start a new scan.', 'yablonsky-security' ),
                'malwareSummaryResume' => __( 'Scan progress is preserved and ready to resume after review.', 'yablonsky-security' ),
                'malwareSummaryAttention' => __( 'Review required', 'yablonsky-security' ),
                'malwareSummaryClear' => __( 'Scan complete. wp-content is clear across the active scanner layers.', 'yablonsky-security' ),
                /* translators: 1: confirmed-malware count, 2: additional review-item count. */
                'malwareSummaryConfirmed' => __( 'Scan complete. %1$d confirmed malware item(s); %2$d additional item(s) need review.', 'yablonsky-security' ),
                /* translators: %d: number of malware items that require origin review. */
                'malwareSummaryReviewOnly' => __( 'Scan complete. No signature-confirmed malware. %d item(s) need origin review.', 'yablonsky-security' ),
                /* translators: %d: number of malware findings ready for review. */
                'malwareSummaryFinding' => __( 'Scan complete. %d finding is ready for review.', 'yablonsky-security' ),
                /* translators: %d: number of malware findings ready for review. */
                'malwareSummaryFindings' => __( 'Scan complete. %d findings are ready for review.', 'yablonsky-security' ),
                'malwareReviewUrl' => admin_url( 'admin.php?page=yablonsky-security&tab=malware#ysec-malware-findings' ),
                'autopilotRunning'  => __( 'Analyzing, applying and verifying the safe profile…', 'yablonsky-security' ),
                'autopilotSuccess'  => __( 'Safe profile verified and committed.', 'yablonsky-security' ),
                'autopilotRollback' => __( 'Verification found a problem. The previous configuration was restored automatically.', 'yablonsky-security' ),
                'confirmAutopilot'  => __( 'Run Optimize Now? Yablonsky Security will snapshot the current configuration, apply a conservative profile, verify the site and automatically roll back on a hard verification failure.', 'yablonsky-security' ),
                'confirmAutopilotRollback' => __( 'Restore the configuration snapshot captured before the last Optimize Now run?', 'yablonsky-security' ),
                'jobStarting'       => __( 'Preparing job…', 'yablonsky-security' ),
                'jobWorking'        => __( 'Processing…', 'yablonsky-security' ),
                'jobCompleted'      => __( 'Completed', 'yablonsky-security' ),
                'jobReady'          => __( 'Ready to download', 'yablonsky-security' ),
                'jobFailed'         => __( 'Failed', 'yablonsky-security' ),
                'jobPaused'         => __( 'Paused', 'yablonsky-security' ),
                'confirmDelete'     => __( 'Delete the selected security-event records permanently?', 'yablonsky-security' ),
                'confirmArchive'    => __( 'Archive the selected evidence records?', 'yablonsky-security' ),
                'confirmFalsePositive' => __( 'Mark this evidence as a false positive? This changes the evidence disposition only; it does not create a firewall bypass or erase the historical deny.', 'yablonsky-security' ),
                'confirmAllowRequest' => __( 'Allow this exact method + path through the automatic firewall profile? Historical evidence remains unchanged, and explicit source blocks, Geo Security, rate containment, virtual patches and manual deny rules still take precedence.', 'yablonsky-security' ),
                'confirmRemoveRequestException' => __( 'Remove this exact request exception and return the method + path to normal automatic firewall-profile evaluation?', 'yablonsky-security' ),
                'confirmBlock'      => __( 'Apply an explicit full-source temporary block? Safe public discovery from this source will also be denied until the block expires or is removed.', 'yablonsky-security' ),
                'confirmBulkBlock'  => __( 'Apply temporary full-source blocks to the selected suspicious sources? YSec protects the current administrator source and existing allowlist. Recovery is available through Active source blocks or WP-CLI.', 'yablonsky-security' ),
                'confirmProtectAll' => __( 'Apply temporary full-source blocks to every suspicious source in the current filtered scope? YSec protects the current administrator source and existing allowlist. This action can remove public access from matching sources.', 'yablonsky-security' ),
                'confirmProtectAllFinal' => __( 'Final confirmation: start resumable full-source containment. Recovery outside wp-admin is available through WP-CLI, the YSEC_EMERGENCY_BYPASS wp-config switch, or a filesystem plugin-folder rename.', 'yablonsky-security' ),
                'confirmUnblockAll' => __( 'Unblock ALL distinct sources in the current filter scope? This runs as a resumable background job and does not depend on pagination.', 'yablonsky-security' ),
                'confirmAccountBulk' => __( 'Apply this account action to the selected users?', 'yablonsky-security' ),
                'confirmFirewallBulk' => __( 'Unblock the selected active source blocks?', 'yablonsky-security' ),
                'confirmAccountScope' => __( 'Apply this account action to ALL users matching the current filters? This runs as a resumable background job and does not depend on pagination.', 'yablonsky-security' ),
                'copied' => __( 'Copied', 'yablonsky-security' ),
            )
        );
    }

    public static function ajax_account_action(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( array( 'message'=>__( 'Not allowed.', 'yablonsky-security' ) ), 403 );
        check_ajax_referer( 'ysec_event_action', 'nonce' );
        $action = isset( $_POST['account_action'] ) ? sanitize_key( wp_unslash( $_POST['account_action'] ) ) : '';
        $ids_raw = isset( $_POST['ids'] ) ? map_deep( wp_unslash( (array) $_POST['ids'] ), 'sanitize_text_field' ) : array();
        $ids = array_slice( array_values( array_unique( array_filter( array_map( 'absint', (array) $ids_raw ) ) ) ), 0, 100 );
        if ( ! YSEC_Accounts::allowed_bulk_action( $action ) || ! $ids ) wp_send_json_error( array( 'message'=>__( 'Invalid account bulk action.', 'yablonsky-security' ) ), 400 );
        $changed = 0;
        foreach ( $ids as $user_id ) if ( YSEC_Accounts::apply( $user_id, $action ) ) $changed++;
        YSEC_Events::log( 'account_bulk_action', array( 'severity'=>'info','family'=>'authentication','details'=>array( 'action'=>$action,'selected'=>count($ids),'changed'=>$changed,'actor'=>get_current_user_id() ) ) );
        wp_send_json_success( array( 'changed'=>$changed ) );
    }

    public static function ajax_firewall_action(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( array( 'message'=>__( 'Not allowed.', 'yablonsky-security' ) ), 403 );
        check_ajax_referer( 'ysec_event_action', 'nonce' );
        $action = isset( $_POST['firewall_action'] ) ? sanitize_key( wp_unslash( $_POST['firewall_action'] ) ) : '';
        $ids_raw = isset( $_POST['ids'] ) ? map_deep( wp_unslash( (array) $_POST['ids'] ), 'sanitize_text_field' ) : array();
        $ids = array_slice( array_values( array_unique( array_filter( array_map( 'absint', (array) $ids_raw ) ) ) ), 0, 100 );
        if ( 'unblock' !== $action || ! $ids ) wp_send_json_error( array( 'message'=>__( 'Invalid firewall bulk action.', 'yablonsky-security' ) ), 400 );
        $changed = 0;
        foreach ( $ids as $block_id ) if ( YSEC_Firewall::unblock( $block_id ) ) $changed++;
        YSEC_Events::log( 'firewall_bulk_action', array( 'severity'=>'info', 'family'=>'configuration', 'details'=>array( 'action'=>'unblock', 'selected'=>count($ids), 'changed'=>$changed, 'actor'=>get_current_user_id() ) ) );
        wp_send_json_success( array( 'changed'=>$changed ) );
    }

    public static function ajax_ai_preview(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'You are not allowed to preview AI evidence.', 'yablonsky-security' ) ), 403 );
        }
        check_ajax_referer( 'ysec_ai_preview', 'nonce' );

        $preview = YSEC_AI::evidence_preview(
            array(
                'mode'                => isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'full_review',
                'window_hours'        => isset( $_POST['window_hours'] ) ? absint( wp_unslash( $_POST['window_hours'] ) ) : 24,
                'event_limit'         => isset( $_POST['event_limit'] ) ? absint( wp_unslash( $_POST['event_limit'] ) ) : 100,
                'include_environment' => isset( $_POST['include_environment'] ) ? 1 : 0,
                'include_hardening'   => isset( $_POST['include_hardening'] ) ? 1 : 0,
                'include_integrity'   => isset( $_POST['include_integrity'] ) ? 1 : 0,
                'include_malware'     => isset( $_POST['include_malware'] ) ? 1 : 0,
                'include_software'    => isset( $_POST['include_software'] ) ? 1 : 0,
            )
        );
        wp_send_json_success( $preview );
    }

    public static function ajax_event_action(): void {
        if(!current_user_can('manage_options'))wp_send_json_error(array('message'=>__('Not allowed.','yablonsky-security')),403);
        check_ajax_referer('ysec_event_action','nonce');
        $action=isset($_POST['event_action'])?sanitize_key(wp_unslash($_POST['event_action'])):'';
        $ids=isset($_POST['ids'])&&is_array($_POST['ids'])?array_map('absint',wp_unslash($_POST['ids'])):array();
        if(in_array($action,array('block_sources','unblock_sources'),true)){
            $changed=0;
            foreach(YSEC_Events::sources_for_ids($ids) as $source){
                if('block_sources'===$action){
                    if(YSEC_Firewall::block_hash((string)$source['source_hash'],'Manual event block: '.sanitize_key((string)$source['family'])))$changed++;
                }else{
                    $changed+=YSEC_Firewall::unblock_hash((string)$source['source_hash']);
                }
            }
            wp_send_json_success(array('changed'=>$changed));
        }
        if ( in_array( $action, array( 'allow_request', 'remove_request_exception' ), true ) ) {
            $changed = 0;
            foreach ( YSEC_Events::requests_for_ids( $ids ) as $request ) {
                $method = strtoupper( (string) ( $request['method'] ?? '' ) );
                $path = (string) ( $request['path'] ?? '' );
                $family = (string) ( $request['family'] ?? '' );
                if ( ! YSEC_Firewall_Policy::can_except_request( $family, $method, $path ) ) continue;
                $ok = 'allow_request' === $action
                    ? YSEC_Firewall_Policy::add_request_exception( $method, $path )
                    : YSEC_Firewall_Policy::remove_request_exception( $method, $path );
                if ( $ok ) $changed++;
            }
            YSEC_Events::log( 'firewall_request_exception_changed', array( 'severity'=>'info', 'family'=>'configuration', 'details'=>array( 'action'=>$action, 'selected'=>count($ids), 'changed'=>$changed, 'actor'=>get_current_user_id() ) ) );
            wp_send_json_success( array( 'changed'=>$changed ) );
        }
        if ( 'false_positive' === $action ) {
            $changed = YSEC_Events::mark_false_positive( $ids );
        } else {
            $changed = YSEC_Events::bulk_action( $ids, $action );
        }
        wp_send_json_success(array('changed'=>$changed));
    }
    public static function ajax_campaign_action(): void {
        if(!current_user_can('manage_options'))wp_send_json_error(array('message'=>__('Not allowed.','yablonsky-security')),403);
        check_ajax_referer('ysec_event_action','nonce');
        $action=isset($_POST['campaign_action'])?sanitize_key(wp_unslash($_POST['campaign_action'])):'';
        $source_hash=isset($_POST['source_hash'])?sanitize_text_field(wp_unslash($_POST['source_hash'])):'';
        $family=isset($_POST['family'])?sanitize_key(wp_unslash($_POST['family'])):'';
        if('block'===$action){$ok=YSEC_Firewall::block_hash($source_hash,'Manual campaign block: '.$family);if($ok)YSEC_Events::log('response_source_blocked',array('severity'=>'info','confidence'=>'high','state'=>'blocked','family'=>$family,'details'=>array('reason'=>'manual_campaign')));wp_send_json_success(array('changed'=>$ok?1:0));}
        if('unblock'===$action){$changed=YSEC_Firewall::unblock_hash($source_hash);if($changed)YSEC_Events::log('response_source_unblocked',array('severity'=>'info','confidence'=>'high','state'=>'observed','family'=>$family,'details'=>array('reason'=>'manual_campaign')));wp_send_json_success(array('changed'=>$changed));}
        if('archive'===$action){$changed=YSEC_Events::archive_campaign($source_hash,$family);wp_send_json_success(array('changed'=>$changed));}
        wp_send_json_error(array('message'=>__('Unknown campaign action.','yablonsky-security')),400);
    }

    public static function actions(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Retire any encrypted executable replacement staged by an older build.
        // Only previously staged ciphertext is discarded; live files are untouched.
        YSEC_Repair_Import::current_stage();

        if ( isset( $_POST['ysec_save_settings'] ) ) {
            check_admin_referer( 'ysec_settings' );
            $raw_settings = isset( $_POST['ysec'] ) && is_array( $_POST['ysec'] ) ? wp_unslash( $_POST['ysec'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Every supported field is sanitized by YSEC_Utils::sanitize_settings() after nonce verification.
            update_option( 'ysec_settings', YSEC_Utils::sanitize_settings( $raw_settings ), false );
            add_settings_error( 'ysec', 'saved', __( 'Settings saved.', 'yablonsky-security' ), 'success' );
        }

        if ( isset( $_POST['ysec_save_security_headers'] ) ) {
            check_admin_referer( 'ysec_security_headers' );
            $raw_policy = isset( $_POST['ysec_headers'] ) && is_array( $_POST['ysec_headers'] ) ? wp_unslash( $_POST['ysec_headers'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each policy field is validated and sanitized by YSEC_Security_Headers::sanitize_policy() after nonce verification.
            $previous = YSEC_Security_Headers::policy();
            $policy = YSEC_Security_Headers::sanitize_policy( $raw_policy );
            if ( is_wp_error( $policy ) ) {
                add_settings_error( 'ysec', 'security_headers_policy', $policy->get_error_message(), 'error' );
            } else {
                $requested_mode = (string) ( $policy['csp_mode'] ?? 'off' );
                if ( 'enforce' === $requested_mode ) {
                    $confirmed = isset( $_POST['csp_enforce_confirm'] ) && 1 === absint( wp_unslash( $_POST['csp_enforce_confirm'] ) );
                    $observed_report_only = '' !== (string) get_option( 'ysec_csp_report_only_since', '' );
                    $readiness = YSEC_Security_Headers::readiness( $policy );
                    if ( ! $confirmed ) {
                        $policy['csp_mode'] = 'report_only';
                        add_settings_error( 'ysec', 'csp_enforce_confirmation', __( 'CSP stayed in Report-Only because enforcement was not explicitly confirmed.', 'yablonsky-security' ), 'warning' );
                    } elseif ( ! $observed_report_only && 'enforce' !== (string) ( $previous['csp_mode'] ?? 'off' ) ) {
                        $policy['csp_mode'] = 'report_only';
                        add_settings_error( 'ysec', 'csp_report_first', __( 'CSP started in Report-Only first. Review real browser violations before enabling enforcement.', 'yablonsky-security' ), 'warning' );
                    } elseif ( ! empty( $readiness['unresolved'] ) ) {
                        $policy['csp_mode'] = 'report_only';
                        /* translators: %d: number of unresolved CSP source observations. */
                        add_settings_error( 'ysec', 'csp_unresolved', sprintf( __( 'CSP stayed in Report-Only because %d observed source entries still need a decision.', 'yablonsky-security' ), absint( $readiness['unresolved'] ) ), 'warning' );
                    }
                }
                update_option( 'ysec_security_headers_policy', $policy, false );
                if ( 'report_only' === (string) $policy['csp_mode'] && '' === (string) get_option( 'ysec_csp_report_only_since', '' ) ) {
                    update_option( 'ysec_csp_report_only_since', gmdate( 'c' ), false );
                } elseif ( 'off' === (string) $policy['csp_mode'] ) {
                    delete_option( 'ysec_csp_report_only_since' );
                }
                add_settings_error( 'ysec', 'security_headers_saved', __( 'Security Headers policy saved.', 'yablonsky-security' ), 'success' );
            }
        }

        if ( isset( $_POST['ysec_csp_discovery_action'] ) ) {
            $hash = isset( $_POST['csp_hash'] ) ? sanitize_text_field( wp_unslash( $_POST['csp_hash'] ) ) : '';
            check_admin_referer( 'ysec_csp_decision_' . $hash );
            $decision = isset( $_POST['csp_decision'] ) ? sanitize_key( wp_unslash( $_POST['csp_decision'] ) ) : '';
            $ok = YSEC_Security_Headers::set_decision( $hash, $decision );
            add_settings_error( 'ysec', 'csp_decision', $ok ? __( 'CSP source decision updated.', 'yablonsky-security' ) : __( 'The CSP source observation was not found.', 'yablonsky-security' ), $ok ? 'success' : 'error' );
        }

        if ( isset( $_POST['ysec_csp_approved_remove'] ) ) {
            $hash = isset( $_POST['csp_hash'] ) ? sanitize_text_field( wp_unslash( $_POST['csp_hash'] ) ) : '';
            check_admin_referer( 'ysec_csp_approved_remove_' . $hash );
            $ok = YSEC_Security_Headers::remove_approved_source( $hash );
            add_settings_error( 'ysec', 'csp_approved_remove', $ok ? __( 'Approved CSP source removed from the guided policy.', 'yablonsky-security' ) : __( 'The approved CSP source was not found.', 'yablonsky-security' ), $ok ? 'success' : 'error' );
        }

        if ( isset( $_POST['ysec_csp_discovery_clear'] ) ) {
            check_admin_referer( 'ysec_csp_discovery_clear' );
            YSEC_Security_Headers::clear_discovery();
            delete_option( 'ysec_csp_report_only_since' );
            add_settings_error( 'ysec', 'csp_discovery_cleared', __( 'CSP discovery evidence and source decisions were cleared.', 'yablonsky-security' ), 'success' );
        }

        if ( isset( $_POST['ysec_mu_install'] ) ) {
            check_admin_referer( 'ysec_mu_runtime' );
            $result = YSEC_Managed_MU::install();
            add_settings_error( 'ysec', 'mu_install', (string) ( $result['message'] ?? '' ), ! empty( $result['ok'] ) ? 'success' : 'error' );
        }
        if ( isset( $_POST['ysec_mu_refresh'] ) ) {
            check_admin_referer( 'ysec_mu_runtime' );
            $result = YSEC_Managed_MU::refresh_policy();
            add_settings_error( 'ysec', 'mu_refresh', (string) ( $result['message'] ?? '' ), ! empty( $result['ok'] ) ? 'success' : 'error' );
        }
        if ( isset( $_POST['ysec_mu_verify'] ) ) {
            check_admin_referer( 'ysec_mu_runtime' );
            $result = YSEC_Managed_MU::verify_live();
            add_settings_error( 'ysec', 'mu_verify', (string) ( $result['message'] ?? '' ), ! empty( $result['ok'] ) ? 'success' : 'warning' );
        }
        if ( isset( $_POST['ysec_mu_remove'] ) ) {
            check_admin_referer( 'ysec_mu_runtime' );
            $result = YSEC_Managed_MU::remove();
            add_settings_error( 'ysec', 'mu_remove', (string) ( $result['message'] ?? '' ), ! empty( $result['ok'] ) ? 'success' : 'error' );
        }

        if ( isset( $_POST['ysec_save_comment_guard'] ) ) {
            check_admin_referer( 'ysec_comment_guard_settings' );
            $current = YSEC_Utils::settings();
            $raw = isset( $_POST['ysec_comment_guard'] ) && is_array( $_POST['ysec_comment_guard'] ) ? wp_unslash( $_POST['ysec_comment_guard'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each supported field is normalized below after nonce verification.
            $current['comment_form_proof'] = empty( $raw['comment_form_proof'] ) ? 0 : 1;
            $current['comment_honeypot'] = empty( $raw['comment_honeypot'] ) ? 0 : 1;
            $current['comment_rate_enforce'] = empty( $raw['comment_rate_enforce'] ) ? 0 : 1;
            $current['comment_rate_limit'] = max( 3, min( 100, absint( $raw['comment_rate_limit'] ?? $current['comment_rate_limit'] ?? 10 ) ) );
            $current['comment_rate_window'] = max( 1, min( 60, absint( $raw['comment_rate_window'] ?? $current['comment_rate_window'] ?? 10 ) ) );
            $xmlrpc_mode = sanitize_key( (string) ( $raw['xmlrpc_mode'] ?? $current['xmlrpc_mode'] ?? 'monitor' ) );
            $current['xmlrpc_mode'] = in_array( $xmlrpc_mode, array( 'monitor', 'pingbacks', 'disable' ), true ) ? $xmlrpc_mode : 'monitor';
            update_option( 'ysec_settings', $current, false );
            YSEC_Events::log(
                'comment_abuse_policy_saved',
                array(
                    'severity' => 'info',
                    'family'   => 'configuration',
                    'details'  => array(
                        'form_proof'     => $current['comment_form_proof'],
                        'honeypot'       => $current['comment_honeypot'],
                        'rate_enforce'   => $current['comment_rate_enforce'],
                        'rate_limit'     => $current['comment_rate_limit'],
                        'rate_window'    => $current['comment_rate_window'],
                        'xmlrpc_mode'    => $current['xmlrpc_mode'],
                        'actor'          => get_current_user_id(),
                    ),
                )
            );
            add_settings_error( 'ysec', 'comment_guard_saved', __( 'Comment abuse protection settings saved.', 'yablonsky-security' ), 'success' );
        }

        if ( isset( $_POST['ysec_send_test_alert'] ) ) {
            check_admin_referer( 'ysec_settings' );
            $sent = YSEC_Alerts::send_test();
            add_settings_error( 'ysec', 'alert_test', $sent ? __( 'Test security alert sent.', 'yablonsky-security' ) : __( 'Test security alert could not be sent. Check the saved recipient and WordPress mail delivery.', 'yablonsky-security' ), $sent ? 'success' : 'error' );
        }

        if ( isset( $_POST['ysec_save_firewall_policy'] ) ) {
            check_admin_referer( 'ysec_firewall_policy' );
            $raw = isset( $_POST['ysec_policy'] ) && is_array( $_POST['ysec_policy'] ) ? wp_unslash( $_POST['ysec_policy'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized and validated by YSEC_Firewall_Policy::sanitize().
            $scope = isset( $_POST['policy_scope'] ) ? sanitize_key( wp_unslash( $_POST['policy_scope'] ) ) : 'all';
            $merged = YSEC_Firewall_Policy::settings();
            if ( 'firewall' === $scope ) {
                $merged['allowlist'] = (string) ( $raw['allowlist'] ?? '' );
                $merged['blocklist'] = (string) ( $raw['blocklist'] ?? '' );
                $merged['path_blocklist'] = (string) ( $raw['path_blocklist'] ?? '' );
                $merged['request_allowlist'] = (string) ( $raw['request_allowlist'] ?? '' );
            } elseif ( 'access' === $scope ) {
                $merged['login_allowlist_enabled'] = empty( $raw['login_allowlist_enabled'] ) ? 0 : 1;
                $merged['login_allowlist'] = (string) ( $raw['login_allowlist'] ?? '' );
                $merged['login_honeypot'] = empty( $raw['login_honeypot'] ) ? 0 : 1;
                $merged['registration_approval'] = empty( $raw['registration_approval'] ) ? 0 : 1;
            } else {
                $merged = $raw;
            }
            $policy = YSEC_Firewall_Policy::sanitize( $merged );
            if ( is_wp_error( $policy ) ) add_settings_error( 'ysec', 'firewall_policy_error', $policy->get_error_message(), 'error' );
            else {
                update_option( 'ysec_firewall_policy', $policy, false );
                YSEC_Events::log( 'firewall_policy_saved', array( 'severity'=>'info', 'family'=>'configuration', 'details'=>array( 'actor'=>get_current_user_id() ) ) );
                add_settings_error( 'ysec', 'firewall_policy_saved', __( 'Durable firewall policy saved.', 'yablonsky-security' ), 'success' );
            }
        }
        if ( isset( $_POST['ysec_policy_preview'] ) ) {
            check_admin_referer( 'ysec_policy_import' );
            $json = isset( $_POST['ysec_policy_json'] ) ? wp_unslash( $_POST['ysec_policy_json'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON is schema-validated field by field and is not stored until preview succeeds.
            $preview = YSEC_Policy_Portability::preview_json( (string) $json );
            if ( is_wp_error( $preview ) ) {
                add_settings_error( 'ysec', 'policy_preview', $preview->get_error_message(), 'error' );
            } else {
                set_transient( 'ysec_policy_preview_' . get_current_user_id(), $preview, 20 * MINUTE_IN_SECONDS );
                add_settings_error( 'ysec', 'policy_preview', __( 'Policy validated. Review the change summary before applying it.', 'yablonsky-security' ), 'success' );
            }
        }
        if ( isset( $_POST['ysec_policy_apply'] ) ) {
            check_admin_referer( 'ysec_policy_apply' );
            $preview = get_transient( 'ysec_policy_preview_' . get_current_user_id() );
            $digest = isset( $_POST['preview_digest'] ) ? sanitize_text_field( wp_unslash( $_POST['preview_digest'] ) ) : '';
            if ( ! is_array( $preview ) || ! hash_equals( (string) ( $preview['digest'] ?? '' ), $digest ) ) {
                add_settings_error( 'ysec', 'policy_apply', __( 'The validated policy preview expired or changed. Validate it again.', 'yablonsky-security' ), 'error' );
            } else {
                $result = YSEC_Policy_Portability::apply_preview( $preview );
                if ( ! empty( $result['ok'] ) ) delete_transient( 'ysec_policy_preview_' . get_current_user_id() );
                add_settings_error( 'ysec', 'policy_apply', (string) $result['message'], ! empty( $result['ok'] ) ? 'success' : 'error' );
            }
        }
        if ( isset( $_POST['ysec_policy_rollback'] ) ) {
            check_admin_referer( 'ysec_policy_rollback' );
            $result = YSEC_Policy_Portability::rollback();
            add_settings_error( 'ysec', 'policy_rollback', (string) $result['message'], ! empty( $result['ok'] ) ? 'success' : 'error' );
        }
        if ( isset( $_POST['ysec_conditional_rule_add'] ) ) {
            check_admin_referer( 'ysec_conditional_rule_add' );
            $raw = array(
                'label'          => isset( $_POST['ysec_conditional_rule']['label'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_conditional_rule']['label'] ) ) : '',
                'method'         => isset( $_POST['ysec_conditional_rule']['method'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_conditional_rule']['method'] ) ) : 'ANY',
                'path_mode'      => isset( $_POST['ysec_conditional_rule']['path_mode'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_conditional_rule']['path_mode'] ) ) : 'exact',
                'path'           => isset( $_POST['ysec_conditional_rule']['path'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_conditional_rule']['path'] ) ) : '',
                'auth'           => isset( $_POST['ysec_conditional_rule']['auth'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_conditional_rule']['auth'] ) ) : 'any',
                'source_network' => isset( $_POST['ysec_conditional_rule']['source_network'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_conditional_rule']['source_network'] ) ) : '',
                'enabled'        => isset( $_POST['ysec_conditional_rule']['enabled'] ) ? absint( wp_unslash( $_POST['ysec_conditional_rule']['enabled'] ) ) : 0,
            );
            $result = YSEC_Conditional_Rules::add( $raw );
            add_settings_error( 'ysec', 'conditional_rule_add', is_wp_error( $result ) ? $result->get_error_message() : __( 'Conditional deny rule created.', 'yablonsky-security' ), is_wp_error( $result ) ? 'error' : 'success' );
        }
        if ( isset( $_POST['ysec_conditional_rule_toggle'] ) || isset( $_POST['ysec_conditional_rule_delete'] ) ) {
            $rule_id = isset( $_POST['rule_id'] ) ? sanitize_text_field( wp_unslash( $_POST['rule_id'] ) ) : '';
            check_admin_referer( 'ysec_conditional_rule_' . $rule_id );
            if ( isset( $_POST['ysec_conditional_rule_delete'] ) ) {
                $ok = YSEC_Conditional_Rules::delete( $rule_id );
                add_settings_error( 'ysec', 'conditional_rule_delete', $ok ? __( 'Conditional deny rule deleted.', 'yablonsky-security' ) : __( 'Conditional deny rule was not found.', 'yablonsky-security' ), $ok ? 'success' : 'error' );
            } else {
                $enabled = isset( $_POST['enabled'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['enabled'] ) );
                $ok = YSEC_Conditional_Rules::toggle( $rule_id, $enabled );
                add_settings_error( 'ysec', 'conditional_rule_toggle', $ok ? __( 'Conditional deny rule state updated.', 'yablonsky-security' ) : __( 'Conditional deny rule was not found.', 'yablonsky-security' ), $ok ? 'success' : 'error' );
            }
        }

        if ( isset( $_POST['ysec_recovery_create'] ) ) {
            check_admin_referer( 'ysec_recovery_create' );
            $label = isset( $_POST['ysec_recovery_label'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_recovery_label'] ) ) : '';
            $result = YSEC_Recovery::create( $label );
            add_settings_error( 'ysec', 'recovery_create', ! empty( $result['ok'] ) ? __( 'Encrypted YSec recovery checkpoint created and verified.', 'yablonsky-security' ) : (string) ( $result['message'] ?? __( 'Recovery checkpoint failed.', 'yablonsky-security' ) ), ! empty( $result['ok'] ) ? 'success' : 'error' );
        }
        if ( isset( $_POST['ysec_recovery_restore'] ) || isset( $_POST['ysec_recovery_delete'] ) ) {
            $recovery_id = isset( $_POST['recovery_id'] ) ? sanitize_text_field( wp_unslash( $_POST['recovery_id'] ) ) : '';
            check_admin_referer( 'ysec_recovery_' . $recovery_id );
            if ( isset( $_POST['ysec_recovery_restore'] ) ) {
                $result = YSEC_Recovery::restore( $recovery_id );
                add_settings_error( 'ysec', 'recovery_restore', (string) ( $result['message'] ?? '' ), ! empty( $result['ok'] ) ? 'success' : 'error' );
            } else {
                $ok = YSEC_Recovery::delete( $recovery_id );
                add_settings_error( 'ysec', 'recovery_delete', $ok ? __( 'Recovery checkpoint deleted.', 'yablonsky-security' ) : __( 'Recovery checkpoint could not be deleted.', 'yablonsky-security' ), $ok ? 'success' : 'error' );
            }
        }

        if ( isset( $_POST['ysec_lockdown_enable'] ) ) {
            check_admin_referer( 'ysec_visitor_lockdown' );
            $minutes = isset( $_POST['lockdown_minutes'] ) ? absint( wp_unslash( $_POST['lockdown_minutes'] ) ) : 60;
            $until = YSEC_Hardening::enable_lockdown( $minutes );
            /* translators: %s: local date/time when emergency visitor lockdown ends. */
            add_settings_error( 'ysec', 'lockdown_enabled', sprintf( __( 'Emergency visitor lockdown enabled until %s.', 'yablonsky-security' ), wp_date( 'Y-m-d H:i', $until ) ), 'warning' );
        }
        if ( isset( $_POST['ysec_lockdown_disable'] ) ) {
            check_admin_referer( 'ysec_visitor_lockdown' );
            YSEC_Hardening::disable_lockdown();
            add_settings_error( 'ysec', 'lockdown_disabled', __( 'Emergency visitor lockdown disabled.', 'yablonsky-security' ), 'success' );
        }
        if ( isset( $_POST['ysec_approve_registration'] ) ) {
            $uid = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
            check_admin_referer( 'ysec_approve_registration_' . $uid );
            if ( $uid && current_user_can( 'edit_user', $uid ) ) {
                delete_user_meta( $uid, 'ysec_registration_pending' );
                YSEC_Events::log( 'registration_approved', array( 'severity'=>'info', 'family'=>'authentication', 'details'=>array( 'user_id'=>$uid, 'actor'=>get_current_user_id() ) ) );
                add_settings_error( 'ysec', 'registration_approved', __( 'User registration approved.', 'yablonsky-security' ), 'success' );
            }
        }
        // Legacy POST routes remain explicitly denied after upgrade. The
        // wp.org build never accepts or applies executable replacement ZIPs.
        if ( isset( $_POST['ysec_stage_repair_zip'] ) || isset( $_POST['ysec_apply_repair_stage'] ) || isset( $_POST['ysec_clear_repair_stage'] ) ) {
            if ( isset( $_POST['ysec_stage_repair_zip'] ) ) {
                check_admin_referer( 'ysec_stage_repair_zip' );
            } elseif ( isset( $_POST['ysec_apply_repair_stage'] ) ) {
                $stage_id = isset( $_POST['repair_stage_id'] ) ? sanitize_text_field( wp_unslash( $_POST['repair_stage_id'] ) ) : '';
                check_admin_referer( 'ysec_apply_repair_stage_' . $stage_id );
            } else {
                $stage_id = isset( $_POST['repair_stage_id'] ) ? sanitize_text_field( wp_unslash( $_POST['repair_stage_id'] ) ) : '';
                check_admin_referer( 'ysec_clear_repair_stage_' . $stage_id );
            }
            YSEC_Repair_Import::clear_stage();
            add_settings_error( 'ysec', 'repair_import_disabled', __( 'Code imports are disabled. No site files were changed.', 'yablonsky-security' ), 'warning' );
        }

        if ( isset( $_POST['ysec_ai_repair_draft'] ) ) {
            check_admin_referer( 'ysec_ai_repair_draft' );
            $advice = YSEC_AI::draft_malware_repairs( 3 );
            if ( is_wp_error( $advice ) ) {
                add_settings_error( 'ysec', 'ai_repair_advice', $advice->get_error_message(), 'error' );
                YSEC_Events::log( 'ai_malware_remediation_advice', array( 'severity'=>'info', 'family'=>'malware', 'state'=>'attention', 'details'=>array( 'ok'=>false, 'actor'=>get_current_user_id() ) ) );
            } else {
                $items = array_values( (array) ( $advice['manual_review'] ?? array() ) );
                // Save short, bounded text advice for this admin session. Never save
                // executable content, replacement files, patches or raw source.
                set_transient( 'ysec_ai_remediation_advice_v2_u' . get_current_user_id(), array( 'ok'=>1, 'advice'=>$items ), 30 * MINUTE_IN_SECONDS );
                add_settings_error( 'ysec', 'ai_repair_advice', __( 'Advice is ready. No site files were changed.', 'yablonsky-security' ), 'success' );
                YSEC_Events::log( 'ai_malware_remediation_advice', array( 'severity'=>'info', 'family'=>'malware', 'state'=>'observed', 'details'=>array( 'ok'=>true, 'items'=>count( $items ), 'actor'=>get_current_user_id() ) ) );
            }
        }

        if ( isset( $_POST['ysec_quarantine_file'] ) ) {
            check_admin_referer( 'ysec_quarantine_file' );
            $path = isset( $_POST['finding_path'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_path'] ) ) : '';
            $context = array(
                'rule'   => isset( $_POST['finding_rule'] ) ? sanitize_key( wp_unslash( $_POST['finding_rule'] ) ) : '',
                'reason' => isset( $_POST['finding_reason'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_reason'] ) ) : '',
                'sha256' => isset( $_POST['finding_sha256'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_sha256'] ) ) : '',
            );
            $result = YSEC_Quarantine::quarantine( $path, $context );
            add_settings_error( 'ysec', 'quarantine_file', ! empty( $result['ok'] ) ? __( 'File encrypted, verified and moved into local quarantine.', 'yablonsky-security' ) : (string) ( $result['message'] ?? __( 'Quarantine failed.', 'yablonsky-security' ) ), ! empty( $result['ok'] ) ? 'success' : 'error' );
            set_transient( 'ysec_last_malware', YSEC_Malware::scan(), 10 * MINUTE_IN_SECONDS );
        }
        if ( isset( $_POST['ysec_restore_quarantine'] ) || isset( $_POST['ysec_delete_quarantine'] ) ) {
            $qid = isset( $_POST['quarantine_id'] ) ? sanitize_text_field( wp_unslash( $_POST['quarantine_id'] ) ) : '';
            check_admin_referer( 'ysec_quarantine_' . $qid );
            if ( isset( $_POST['ysec_restore_quarantine'] ) ) {
                $result = YSEC_Quarantine::restore( $qid );
                add_settings_error( 'ysec', 'quarantine_restore', ! empty( $result['ok'] ) ? __( 'Quarantined file restored after integrity verification.', 'yablonsky-security' ) : (string) ( $result['message'] ?? __( 'Restore failed.', 'yablonsky-security' ) ), ! empty( $result['ok'] ) ? 'success' : 'error' );
            } else {
                $ok = YSEC_Quarantine::delete( $qid );
                add_settings_error( 'ysec', 'quarantine_delete', $ok ? __( 'Quarantine item permanently deleted.', 'yablonsky-security' ) : __( 'Quarantine item could not be deleted.', 'yablonsky-security' ), $ok ? 'success' : 'error' );
            }
        }

        if ( isset( $_POST['ysec_integrity_baseline'] ) ) {
            check_admin_referer( 'ysec_integrity' );
            YSEC_Integrity::baseline();
            add_settings_error( 'ysec', 'baseline', __( 'Integrity baseline created.', 'yablonsky-security' ), 'success' );
        }
        if ( isset( $_POST['ysec_integrity_scan'] ) ) {
            check_admin_referer( 'ysec_integrity' );
            set_transient( 'ysec_last_integrity', YSEC_Integrity::scan(), 10 * MINUTE_IN_SECONDS );
        }
        if ( isset( $_POST['ysec_integrity_save_ignores'] ) ) {
            check_admin_referer( 'ysec_integrity_ignores' );
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Strict exact/prefix sanitization is applied by YSEC_Integrity::set_ignores().
            $raw_ignores = isset( $_POST['ysec_integrity_ignores'] ) ? wp_unslash( $_POST['ysec_integrity_ignores'] ) : '';
            $items = YSEC_Integrity::set_ignores( is_string( $raw_ignores ) ? $raw_ignores : '' );
            /* translators: %d: number of saved integrity ignore rules. */
            add_settings_error( 'ysec', 'integrity_ignores_saved', sprintf( __( 'Integrity review policy saved: %d ignore rules.', 'yablonsky-security' ), count( $items ) ), 'success' );
        }
        if ( isset( $_POST['ysec_permission_scan'] ) ) {
            check_admin_referer( 'ysec_permissions' );
            set_transient( 'ysec_last_permissions', YSEC_Permissions::scan(), 10 * MINUTE_IN_SECONDS );
        }
        if ( isset( $_POST['ysec_permission_repair'] ) ) {
            check_admin_referer( 'ysec_permissions' );
            $repair = YSEC_Permissions::repair_safe();
            set_transient( 'ysec_last_permissions', $repair['after'] ?? YSEC_Permissions::scan(), 10 * MINUTE_IN_SECONDS );
            /* translators: %d: number of unsafe filesystem permissions repaired. */
            add_settings_error( 'ysec', 'permission_repair', ! empty( $repair['ok'] ) ? sprintf( __( '%d unsafe permission(s) repaired.', 'yablonsky-security' ), (int) ( $repair['changed'] ?? 0 ) ) : __( 'Permission repair completed with one or more paths requiring manual review.', 'yablonsky-security' ), ! empty( $repair['ok'] ) ? 'success' : 'warning' );
        }
        if ( isset( $_POST['ysec_malware_scan'] ) ) {
            check_admin_referer( 'ysec_malware' );
            YSEC_Malware::full_scan_start();
            add_settings_error( 'ysec', 'malware_scan_started', __( 'Complete wp-content malware scan started. The Malware screen can resume it in bounded batches.', 'yablonsky-security' ), 'success' );
        }

        if ( isset( $_POST['ysec_archive_before'] ) ) {
            check_admin_referer( 'ysec_event_maintenance' );
            $date=isset($_POST['ysec_archive_date'])?sanitize_text_field(wp_unslash($_POST['ysec_archive_date'])):'';
            $count=YSEC_Events::archive_before($date);
            /* translators: %d: number of security-event records archived. */
            add_settings_error('ysec','archive_done',sprintf(__( '%d security-event records archived.', 'yablonsky-security' ),$count),'success');
        }
        if ( isset( $_POST['ysec_delete_archived'] ) ) {
            check_admin_referer( 'ysec_event_maintenance' );
            $count=YSEC_Events::delete_archived();
            /* translators: %d: number of archived security-event records permanently deleted. */
            add_settings_error('ysec','archive_deleted',sprintf(__( '%d archived security-event records deleted.', 'yablonsky-security' ),$count),'success');
        }

        if ( isset( $_POST['ysec_run_retention'] ) ) {
            check_admin_referer( 'ysec_event_maintenance' );
            YSEC_DB::cleanup();
            $retention_error = get_option( 'ysec_last_retention_error', array() );
            if ( is_array( $retention_error ) && ! empty( $retention_error['at'] ) ) {
                add_settings_error( 'ysec', 'retention', __( 'Data maintenance', 'yablonsky-security' ) . ': ' . __( 'Review required', 'yablonsky-security' ), 'error' );
            } else {
                add_settings_error( 'ysec', 'retention', __( 'Evidence retention and rollup maintenance completed.', 'yablonsky-security' ), 'success' );
            }
        }
        if ( isset( $_POST['ysec_advisory_import'] ) ) {
            check_admin_referer( 'ysec_advisory_store' );
            $json = isset( $_POST['ysec_advisory_json'] ) ? wp_unslash( $_POST['ysec_advisory_json'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Schema validated by YSEC_Advisories::import_json().
            $result = YSEC_Advisories::import_json( (string) $json );
            add_settings_error( 'ysec', 'advisory_import', is_wp_error( $result ) ? $result->get_error_message() : sprintf( /* translators: %d: imported advisory records. */ __( '%d advisory records imported.', 'yablonsky-security' ), (int) $result ), is_wp_error( $result ) ? 'error' : 'success' );
        }
        if ( isset( $_POST['ysec_advisory_clear'] ) ) {
            check_admin_referer( 'ysec_advisory_store' );
            YSEC_Advisories::clear();
            add_settings_error( 'ysec', 'advisory_clear', __( 'Local advisory store cleared.', 'yablonsky-security' ), 'success' );
        }
        if ( isset( $_POST['ysec_virtual_patch_enable'] ) || isset( $_POST['ysec_virtual_patch_disable'] ) ) {
            $id = isset( $_POST['advisory_id'] ) ? sanitize_text_field( wp_unslash( $_POST['advisory_id'] ) ) : '';
            check_admin_referer( 'ysec_virtual_patch_' . $id );
            $result = isset( $_POST['ysec_virtual_patch_enable'] ) ? YSEC_Virtual_Patches::enable( $id ) : YSEC_Virtual_Patches::disable( $id );
            $ok = ! is_wp_error( $result ) && false !== $result;
            $message = is_wp_error( $result ) ? $result->get_error_message() : ( $ok ? __( 'Virtual patch policy updated.', 'yablonsky-security' ) : __( 'Virtual patch state did not change.', 'yablonsky-security' ) );
            add_settings_error( 'ysec', 'virtual_patch', $message, $ok ? 'success' : 'error' );
        }
        if ( isset( $_POST['ysec_firewall_proof'] ) ) {
            check_admin_referer( 'ysec_firewall_proof' );
            $result = YSEC_Firewall_Proof::run();
            $live = is_array( $result['live'] ?? null ) ? $result['live'] : array();
            $message = ! empty( $result['ok'] )
                ? __( 'Firewall proof completed. Review the engine and live-loopback results below.', 'yablonsky-security' )
                : __( 'Firewall proof found a result that requires review.', 'yablonsky-security' );
            $type = ! empty( $result['ok'] ) ? ( ! empty( $live['unavailable'] ) ? 'warning' : 'success' ) : 'warning';
            add_settings_error( 'ysec', 'firewall_proof', $message, $type );
        }
        if ( isset( $_POST['ysec_fastpath_verify'] ) ) {
            check_admin_referer( 'ysec_fastpath_verify' );
            $result = YSEC_Fast_Path::verify();
            set_transient( 'ysec_fastpath_verify_result', $result, 30 * MINUTE_IN_SECONDS );
            add_settings_error( 'ysec', 'fastpath_verify', (string) $result['message'], ! empty( $result['ok'] ) ? 'success' : 'warning' );
        }
        if ( isset( $_POST['ysec_capture_cutover_snapshot'] ) ) {
            check_admin_referer( 'ysec_cutover_snapshot' );
            $snapshot = YSEC_Migration::capture_snapshot();
            // translators: %d: source security products captured.
            add_settings_error( 'ysec', 'cutover_snapshot', sprintf( __( 'Migration snapshot captured for %d detected security product(s). Plugin activation remains administrator-controlled.', 'yablonsky-security' ), count( $snapshot['sources'] ?? array() ) ), 'success' );
        }
        if ( isset( $_POST['ysec_apply_migration_mapping'] ) ) {
            check_admin_referer( 'ysec_migration_mapping' );
            $source_file = isset( $_POST['source_file'] ) ? sanitize_text_field( wp_unslash( $_POST['source_file'] ) ) : '';
            $targets = isset( $_POST['mapping_targets'] ) && is_array( $_POST['mapping_targets'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['mapping_targets'] ) ) : array();
            $result = YSEC_Migration::apply_selected_mapping( $source_file, $targets );
            $ok = ! empty( $result['ok'] );
            $message = ! empty( $result['message'] ) ? (string) $result['message'] : sprintf(
                /* translators: %d: number of YSec settings changed by the guided migration mapping. */
                __( 'Guided mapping applied to YSec: %d setting(s) changed. Plugin activation remains administrator-controlled.', 'yablonsky-security' ),
                (int) ( $result['changed'] ?? 0 )
            );
            add_settings_error( 'ysec', 'migration_mapping', $message, $ok ? 'success' : 'error' );
        }
        if ( isset( $_POST['ysec_rollback_migration_mapping'] ) ) {
            check_admin_referer( 'ysec_migration_mapping_rollback' );
            $result = YSEC_Migration::rollback_last_mapping();
            add_settings_error( 'ysec', 'migration_mapping_rollback', ! empty( $result['ok'] ) ? __( 'The YSec configuration captured before the last guided mapping was restored.', 'yablonsky-security' ) : (string) ( $result['message'] ?? __( 'Guided-mapping rollback was not available.', 'yablonsky-security' ) ), ! empty( $result['ok'] ) ? 'success' : 'error' );
        }
        if ( isset( $_POST['ysec_run_cutover_proof'] ) ) {
            check_admin_referer( 'ysec_cutover_proof' );
            $source_file = isset( $_POST['source_file'] ) ? sanitize_text_field( wp_unslash( $_POST['source_file'] ) ) : '';
            $result = YSEC_Migration::run_cutover_proof( $source_file );
            $ok = ! empty( $result['ok'] );
            add_settings_error( 'ysec', 'cutover_proof', $ok ? __( 'Migration proof passed. YSec verified the selected protection ownership while plugin activation remained administrator-controlled.', 'yablonsky-security' ) : (string) ( $result['message'] ?? __( 'Migration proof is ready for review. Use the checks below to complete the selected ownership handoff.', 'yablonsky-security' ) ), $ok ? 'success' : 'warning' );
        }
        if ( isset( $_POST['ysec_run_takeover_closeout'] ) ) {
            check_admin_referer( 'ysec_takeover_closeout' );
            $result = YSEC_Takeover::run();
            $ok = ! empty( $result['ready'] );
            $message = $ok
                ? __( 'Migration completion passed. Source proofs, local runtime gates and exposure checks are green.', 'yablonsky-security' )
                : sprintf(
                    /* translators: 1: passed closeout gates, 2: total closeout gates. */
                    __( 'Migration completion: %1$d/%2$d gates passed. The status panel shows the next available action.', 'yablonsky-security' ),
                    (int) ( $result['passed'] ?? 0 ),
                    (int) ( $result['total'] ?? 0 )
                );
            add_settings_error( 'ysec', 'takeover_closeout', $message, $ok ? 'success' : 'warning' );
        }
        if ( isset( $_POST['ysec_ai_save'] ) ) {
            check_admin_referer( 'ysec_ai_account' );
            $ai_input = array();
            if ( isset( $_POST['ysec_ai_api_key'] ) ) {
                $ai_input['api_key'] = sanitize_text_field( wp_unslash( $_POST['ysec_ai_api_key'] ) );
            }
            if ( isset( $_POST['ysec_ai_workspace_id'] ) ) {
                $ai_input['workspace_id'] = sanitize_text_field( wp_unslash( $_POST['ysec_ai_workspace_id'] ) );
            }
            if ( isset( $_POST['ysec_ai_model_id'] ) ) {
                $ai_input['model_id'] = sanitize_text_field( wp_unslash( $_POST['ysec_ai_model_id'] ) );
            }
            if ( isset( $_POST['ysec_ai_reasoning'] ) ) {
                $ai_input['reasoning'] = sanitize_key( wp_unslash( $_POST['ysec_ai_reasoning'] ) );
            }
            $save_result = YSEC_AI::save_preferences( $ai_input );
            if ( is_wp_error( $save_result ) ) {
                add_settings_error( 'ysec', 'ai_saved', $save_result->get_error_message(), 'error' );
            } else {
                $saved_model = sanitize_text_field( (string) ( $save_result['model_id'] ?? '' ) );
                $state_after_save = YSEC_AI::state();
                $writer_after_save = is_array( $state_after_save['model_projection'] ?? null ) ? sanitize_text_field( (string) ( $state_after_save['model_projection']['writer_default'] ?? '' ) ) : '';
                $effective_model = '' !== $saved_model ? $saved_model : $writer_after_save;
                $message = '' !== $effective_model
                    ? sprintf( /* translators: %s: effective AI model ID. */ __( 'Yablonsky AI routing saved. Effective model: %s. No remote request was made.', 'yablonsky-security' ), $effective_model )
                    : __( 'Yablonsky AI routing saved. No remote request was made.', 'yablonsky-security' );
                add_settings_error( 'ysec', 'ai_saved', $message, 'success' );
            }
        }
        if ( isset( $_POST['ysec_ai_disconnect'] ) ) {
            check_admin_referer( 'ysec_ai_disconnect' );
            YSEC_AI::disconnect();
            add_settings_error( 'ysec', 'ai_disconnected', __( 'Yablonsky AI disconnected. Local security protection is unchanged.', 'yablonsky-security' ), 'success' );
        }
        if ( isset( $_POST['ysec_ai_test'] ) ) {
            check_admin_referer( 'ysec_ai_test' );
            $result = YSEC_AI::test_connection();
            set_transient( 'ysec_last_ai_test', is_wp_error( $result ) ? array( 'error' => $result->get_error_message() ) : array( 'ok' => true ), 10 * MINUTE_IN_SECONDS );
            YSEC_Events::log( 'ai_account_refresh', array( 'severity'=>'info', 'family'=>'configuration', 'state'=>is_wp_error( $result ) ? 'attention' : 'observed', 'details'=>array( 'ok'=>! is_wp_error( $result ), 'actor'=>get_current_user_id() ) ) );
        }
        if ( isset( $_POST['ysec_ai_canary'] ) ) {
            check_admin_referer( 'ysec_ai_canary' );
            $canary = YSEC_AI::model_canary();
            set_transient( 'ysec_last_ai_canary', is_wp_error( $canary ) ? array( 'error' => $canary->get_error_message() ) : array( 'ok' => 1, 'model' => $canary['model'] ?? '' ), 10 * MINUTE_IN_SECONDS );
            YSEC_Events::log( 'ai_model_canary', array( 'severity'=>'info', 'family'=>'configuration', 'state'=>is_wp_error( $canary ) ? 'attention' : 'observed', 'details'=>array( 'ok'=>! is_wp_error( $canary ), 'actor'=>get_current_user_id() ) ) );
        }

        if ( isset( $_POST['ysec_ai_history_delete'] ) ) {
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die( esc_html__( 'Not allowed.', 'yablonsky-security' ) );
            }
            $surface = isset( $_POST['ysec_ai_surface'] ) ? sanitize_key( wp_unslash( $_POST['ysec_ai_surface'] ) ) : '';
            if ( in_array( $surface, array( 'events', 'recon', 'firewall' ), true ) ) {
                check_admin_referer( 'ysec_ai_history_' . $surface );
                $selected = isset( $_POST['ysec_ai_history_ids'] ) && is_array( $_POST['ysec_ai_history_ids'] )
                    ? array_map( 'sanitize_text_field', wp_unslash( $_POST['ysec_ai_history_ids'] ) )
                    : array();
                self::delete_ai_context_history( $surface, $selected );
            }
        }

        if ( isset( $_POST['ysec_ai_context_analyze'] ) ) {
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die( esc_html__( 'Not allowed.', 'yablonsky-security' ) );
            }
            $surface = isset( $_POST['ysec_ai_surface'] ) ? sanitize_key( wp_unslash( $_POST['ysec_ai_surface'] ) ) : '';
            if ( in_array( $surface, array( 'events', 'recon', 'firewall' ), true ) ) {
                check_admin_referer( 'ysec_ai_context_' . $surface );
                $mode_map = array( 'events' => 'events_review', 'recon' => 'recon_review', 'firewall' => 'firewall_review' );
                $result = self::analyze_once_per_user(
                    array(
                        'mode'                => $mode_map[ $surface ],
                        'surface'             => $surface,
                        'window_hours'        => isset( $_POST['ysec_ai_window'] ) ? absint( wp_unslash( $_POST['ysec_ai_window'] ) ) : 24,
                        'event_limit'         => isset( $_POST['ysec_ai_event_limit'] ) ? absint( wp_unslash( $_POST['ysec_ai_event_limit'] ) ) : 100,
                        'include_environment' => 0,
                        'include_hardening'   => 0,
                        'include_integrity'   => 0,
                        'include_malware'     => 0,
                        'include_software'    => 0,
                    )
                );
                $context_key = 'ysec_last_ai_context_' . $surface . '_' . get_current_user_id();
                if ( is_wp_error( $result ) ) {
                    set_transient( $context_key, array( 'error' => $result->get_error_message() ), 30 * MINUTE_IN_SECONDS );
                } else {
                    delete_transient( $context_key );
                    self::store_ai_context_history( $surface, $mode_map[ $surface ], $result );
                }
                YSEC_Events::log( 'ai_security_analysis', array( 'severity'=>'info', 'family'=>'configuration', 'state'=>is_wp_error( $result ) ? 'attention' : 'observed', 'details'=>array( 'ok'=>! is_wp_error( $result ), 'mode'=>$mode_map[ $surface ], 'surface'=>$surface, 'actor'=>get_current_user_id() ) ) );
            }
        }

        if ( isset( $_POST['ysec_ai_analyze'] ) ) {
            check_admin_referer( 'ysec_ai_analyze' );
            $result = self::analyze_once_per_user(
                array(
                    'mode'                => isset( $_POST['ysec_ai_mode'] ) ? sanitize_key( wp_unslash( $_POST['ysec_ai_mode'] ) ) : 'full_review',
                    'window_hours'        => isset( $_POST['ysec_ai_window'] ) ? absint( wp_unslash( $_POST['ysec_ai_window'] ) ) : 24,
                    'event_limit'         => isset( $_POST['ysec_ai_event_limit'] ) ? absint( wp_unslash( $_POST['ysec_ai_event_limit'] ) ) : 100,
                    'include_environment' => isset( $_POST['ysec_ai_include_environment'] ) ? 1 : 0,
                    'include_hardening'   => isset( $_POST['ysec_ai_include_hardening'] ) ? 1 : 0,
                    'include_integrity'   => isset( $_POST['ysec_ai_include_integrity'] ) ? 1 : 0,
                    'include_malware'     => isset( $_POST['ysec_ai_include_malware'] ) ? 1 : 0,
                    'include_software'    => isset( $_POST['ysec_ai_include_software'] ) ? 1 : 0,
                )
            );
            set_transient( 'ysec_last_ai', is_wp_error( $result ) ? array( 'error' => $result->get_error_message() ) : $result, 30 * MINUTE_IN_SECONDS );
            YSEC_Events::log( 'ai_security_analysis', array( 'severity'=>'info', 'family'=>'configuration', 'state'=>is_wp_error( $result ) ? 'attention' : 'observed', 'details'=>array( 'ok'=>! is_wp_error( $result ), 'mode'=>isset( $_POST['ysec_ai_mode'] ) ? sanitize_key( wp_unslash( $_POST['ysec_ai_mode'] ) ) : 'full_review', 'actor'=>get_current_user_id() ) ) );
        }

        if ( isset( $_POST['ysec_unblock'] ) ) {
            $block_id = isset( $_POST['block_id'] ) ? absint( wp_unslash( $_POST['block_id'] ) ) : 0;
            check_admin_referer( 'ysec_unblock_' . $block_id );
            YSEC_Firewall::unblock( $block_id );
        }
        if ( isset( $_POST['ysec_revoke_sessions'] ) ) {
            $uid = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
            check_admin_referer( 'ysec_revoke_sessions_' . $uid );
            if ( $uid && current_user_can( 'edit_user', $uid ) ) {
                $manager = WP_Session_Tokens::get_instance( $uid );
                if ( $uid === get_current_user_id() ) {
                    $manager->destroy_others( wp_get_session_token() );
                } else {
                    $manager->destroy_all();
                }
                YSEC_Events::log( 'sessions_revoked', array( 'severity' => 'medium', 'family' => 'authentication', 'details' => array( 'user_id' => $uid, 'actor' => get_current_user_id() ) ) );
            }
        }
        if ( isset( $_POST['ysec_lock_account'] ) ) {
            $uid = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
            check_admin_referer( 'ysec_account_lock_' . $uid );
            if ( $uid && $uid !== get_current_user_id() && current_user_can( 'edit_user', $uid ) ) {
                $minutes = isset( $_POST['lock_minutes'] ) ? max( 5, min( 10080, absint( wp_unslash( $_POST['lock_minutes'] ) ) ) ) : 60;
                $until = time() + $minutes * MINUTE_IN_SECONDS;
                update_user_meta( $uid, 'ysec_account_locked_until', $until );
                WP_Session_Tokens::get_instance( $uid )->destroy_all();
                YSEC_Events::log( 'account_locked', array( 'severity'=>'high', 'family'=>'authentication', 'state'=>'contained', 'details'=>array( 'user_id'=>$uid, 'actor'=>get_current_user_id(), 'locked_until'=>$until ) ) );
                add_settings_error( 'ysec', 'account_locked', __( 'Account temporarily locked and active sessions revoked.', 'yablonsky-security' ), 'success' );
            }
        }
        if ( isset( $_POST['ysec_unlock_account'] ) ) {
            $uid = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
            check_admin_referer( 'ysec_account_unlock_' . $uid );
            if ( $uid && current_user_can( 'edit_user', $uid ) ) {
                delete_user_meta( $uid, 'ysec_account_locked_until' );
                YSEC_Events::log( 'account_unlocked', array( 'severity'=>'medium', 'family'=>'authentication', 'details'=>array( 'user_id'=>$uid, 'actor'=>get_current_user_id() ) ) );
                add_settings_error( 'ysec', 'account_unlocked', __( 'Account lock removed.', 'yablonsky-security' ), 'success' );
            }
        }
        if ( isset( $_GET['ysec_export'] ) && '1' === sanitize_text_field( wp_unslash( $_GET['ysec_export'] ) ) ) {
            check_admin_referer( 'ysec_export' );
            self::export();
        }
    }

    public static function export_policy(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export security policy.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_policy_export' );
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-policy-' . YSEC_VERSION . '.json"' );
        echo wp_json_encode( YSEC_Policy_Portability::package(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        exit;
    }

    public static function run_firewall_proof(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to run firewall proof.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_firewall_proof' );
        YSEC_Firewall_Proof::run();
        $url = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'firewall' ), admin_url( 'admin.php' ) );
        wp_safe_redirect( $url . '#ysec-firewall-proof' );
        exit;
    }

    public static function export_firewall_proof(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export firewall proof.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_firewall_proof_export' );
        $proof = YSEC_Firewall_Proof::receipt();
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-firewall-proof-' . YSEC_VERSION . '-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( $proof, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled application/json proof receipt; no proof token, secret or request body is included.
        exit;
    }

    public static function export_security_headers_report(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export the Security Headers report.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_security_headers_export' );
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-security-headers-' . YSEC_VERSION . '-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( YSEC_Security_Headers::export_bundle(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled JSON report contains bounded normalized origins/policy state and no credentials or request bodies.
        exit;
    }

    public static function export_fastpath(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export server rules.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_fastpath_export' );
        nocache_headers();
        header( 'Content-Type: text/plain; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-fast-path-' . YSEC_VERSION . '.txt"' );
        echo YSEC_Fast_Path::bundle(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled text/plain server-rule bundle; HTML escaping would corrupt Apache directives and no request data is included.
        exit;
    }

    private static function export(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You are not allowed to export security evidence.', 'yablonsky-security' ) );
        }
        $data = array(
            'schema'       => 'ysec-evidence/2',
            'generated_at' => gmdate( 'c' ),
            'version'      => YSEC_VERSION,
            'environment'  => YSEC_Environment::detect(),
            'summary'      => YSEC_Events::summary(),
            'events'       => YSEC_Events::recent( 500 ),
            'hardening'    => YSEC_Hardening::findings(),
        );
        foreach ( $data['events'] as &$event ) {
            unset( $event['source_hash'], $event['source_enc'] );
        }
        unset( $event );
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-evidence-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        exit;
    }

    public static function export_posture_report(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export the security posture report.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_posture_report' );
        $report = YSEC_Security_Report::build();
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-posture-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled application/json download built from sanitized/local bounded summaries; escaping would corrupt JSON.
        exit;
    }

    public static function export_doctor_report(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export Security Doctor diagnostics.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_doctor_export' );
        $report = array(
            'schema'       => 'yablonsky.security.doctor-report.v1',
            'generated_at' => gmdate( 'c' ),
            'plugin'       => 'Yablonsky Security',
            'version'      => YSEC_VERSION,
            'environment'  => YSEC_Environment::detect(),
            'doctor'       => YSEC_Doctor::report(),
            'db_contract'  => YSEC_DB::schema_contract(),
        );
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-doctor-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled JSON diagnostic without credentials or raw source identity.
        exit;
    }

    public static function export_cutover_proof(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export the cutover proof.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_cutover_proof_export' );
        $receipt = YSEC_Migration::last_cutover_proof();
        if ( ! $receipt ) wp_die( esc_html__( 'No cutover proof is available yet.', 'yablonsky-security' ), '', array( 'response'=>404 ) );
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-cutover-proof-' . YSEC_VERSION . '-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( $receipt, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled JSON receipt contains bounded status evidence and no source-plugin secrets.
        exit;
    }

    public static function export_takeover_closeout(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export the takeover closeout receipt.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_takeover_closeout_export' );
        $receipt = YSEC_Takeover::last();
        if ( ! $receipt ) wp_die( esc_html__( 'No takeover closeout receipt is available yet.', 'yablonsky-security' ), '', array( 'response'=>404 ) );
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-takeover-closeout-' . YSEC_VERSION . '-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( $receipt, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled JSON receipt contains bounded local proof state and no credentials or raw source identities.
        exit;
    }

    private static function csv_line( array $fields ): string {
        $escaped = array();
        foreach ( $fields as $field ) {
            $value = (string) $field;
            if ( '' !== $value && in_array( $value[0], array( '=', '+', '-', '@' ), true ) ) {
                $value = "'" . $value;
            }
            $escaped[] = '"' . str_replace( '"', '""', $value ) . '"';
        }
        return implode( ',', $escaped );
    }

    /**
     * Build a single complete scan report for both the standalone download and
     * the forensic ZIP. This report is metadata-only: never raw site files.
     */
    private static function malware_report_package( array $result ): array {
        return array(
            'schema'       => 'yablonsky.security.malware-report.v1',
            'generated_at' => gmdate( 'c' ),
            'plugin'       => 'Yablonsky Security',
            'version'      => YSEC_VERSION,
            'scan'         => $result,
        );
    }

    /** Build the same escaped, spreadsheet-formula-neutralized CSV for both exports. */
    private static function malware_report_csv( array $result ): string {
        $lines = array();
        $lines[] = self::csv_line( array( 'record_type', 'severity', 'rule_or_kind', 'path', 'reason_or_owner', 'sha256', 'size' ) );
        foreach ( (array) ( $result['findings'] ?? array() ) as $row ) {
            $lines[] = self::csv_line( array( 'finding', (string) ( $row['severity'] ?? '' ), (string) ( $row['rule'] ?? '' ), (string) ( $row['path'] ?? '' ), (string) ( $row['reason'] ?? '' ), (string) ( $row['sha256'] ?? '' ), (int) ( $row['size'] ?? 0 ) ) );
        }
        foreach ( (array) ( $result['trusted_artifacts'] ?? array() ) as $row ) {
            $lines[] = self::csv_line( array( 'trusted_artifact', '', (string) ( $row['kind'] ?? '' ), (string) ( $row['path'] ?? '' ), (string) ( $row['owner'] ?? '' ), (string) ( $row['sha256'] ?? '' ), (int) ( $row['size'] ?? 0 ) ) );
        }
        return implode( "\r\n", $lines ) . "\r\n";
    }

    public static function export_malware_report(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export malware scan evidence.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_malware_export' );
        $format = isset( $_GET['format'] ) ? sanitize_key( wp_unslash( $_GET['format'] ) ) : 'json'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce is verified above.
        $result = YSEC_Malware::export_result();
        nocache_headers();
        if ( 'csv' === $format ) {
            header( 'Content-Type: text/csv; charset=utf-8' );
            header( 'Content-Disposition: attachment; filename="yablonsky-security-malware-' . gmdate( 'Ymd-His' ) . '.csv"' );
            echo self::malware_report_csv( $result ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled CSV export; formula neutralization is applied per cell.
            exit;
        }
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-malware-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( self::malware_report_package( $result ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Controlled local malware metadata; no site-file contents.
        exit;
    }

    public static function export_malware_forensic_zip(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to export malware review files.', 'yablonsky-security' ), '', array( 'response'=>403 ) );
        check_admin_referer( 'ysec_malware_forensic_export' );

        $result = YSEC_Malware::export_result();
        $findings = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
        if ( ! class_exists( 'ZipArchive' ) ) wp_die( esc_html__( 'ZIP support is unavailable on this server.', 'yablonsky-security' ) );

        $temp = wp_tempnam( 'ysec-forensic-review-' . gmdate( 'Ymd-His' ) . '.zip' );
        if ( ! $temp ) wp_die( esc_html__( 'A temporary ZIP file could not be created.', 'yablonsky-security' ) );
        $zip = new ZipArchive();
        if ( true !== $zip->open( $temp, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
            @unlink( $temp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Temporary export file cleanup.
            wp_die( esc_html__( 'The forensic ZIP could not be opened.', 'yablonsky-security' ) );
        }

        $manifest_rows = array();
        $total_bytes = 0;
        $max_total = 200 * MB_IN_BYTES;
        foreach ( array_slice( $findings, 0, 1000 ) as $finding ) {
            if ( ! is_array( $finding ) ) continue;
            $finding = YSEC_Malware::normalize_finding( $finding );
            $path = (string) ( $finding['path'] ?? '' );
            $entry = array(
                'path'               => $path,
                'classification'     => (string) ( $finding['classification'] ?? 'review' ),
                'severity'           => (string) ( $finding['severity'] ?? '' ),
                'rule'               => (string) ( $finding['rule'] ?? '' ),
                'reason'             => (string) ( $finding['reason'] ?? '' ),
                'scan_sha256'        => (string) ( $finding['sha256'] ?? '' ),
                'scan_size'          => (int) ( $finding['size'] ?? 0 ),
                'recommended_action' => (string) ( $finding['recommended_action'] ?? 'review_origin' ),
                'export_status'      => 'metadata_only',
            );
            $absolute = YSEC_Malware::resolve_finding_path( $path );
            if ( is_wp_error( $absolute ) || ! is_readable( $absolute ) ) {
                $entry['export_status'] = 'file_unavailable';
                $manifest_rows[] = $entry;
                continue;
            }
            $size = @filesize( $absolute );
            $current_sha = @hash_file( 'sha256', $absolute ) ?: '';
            $entry['current_sha256'] = $current_sha;
            $entry['current_size'] = false === $size ? 0 : (int) $size;
            if ( ! empty( $entry['scan_sha256'] ) && ! hash_equals( $entry['scan_sha256'], $current_sha ) ) {
                $entry['export_status'] = 'changed_since_scan';
                $manifest_rows[] = $entry;
                continue;
            }
            if ( false === $size || $size < 0 || $total_bytes + (int) $size > $max_total ) {
                $entry['export_status'] = 'package_size_limit';
                $manifest_rows[] = $entry;
                continue;
            }
            $zip_path = 'files/' . ltrim( wp_normalize_path( $path ), '/' );
            if ( $zip->addFile( $absolute, $zip_path ) ) {
                $entry['export_status'] = 'included';
                $entry['zip_path'] = $zip_path;
                $total_bytes += (int) $size;
            } else {
                $entry['export_status'] = 'zip_add_failed';
            }
            $manifest_rows[] = $entry;
        }

        $manifest = array(
            'schema'       => 'yablonsky.security.forensic-review-package.v1',
            'reports'      => array( 'reports/scan.json', 'reports/scan.csv', 'reports/summary.txt' ),
            'generated_at' => gmdate( 'c' ),
            'plugin'       => 'Yablonsky Security',
            'version'      => YSEC_VERSION,
            'site_host'    => wp_parse_url( home_url( '/' ), PHP_URL_HOST ),
            'policy'       => array(
                'purpose' => 'offline_review_only',
                'live_files_modified' => false,
                'repair_import_trust' => 'none',
            ),
            'scan'         => array(
                'completed_at'    => (string) ( $result['completed_at'] ?? '' ),
                'files_processed' => (int) ( $result['files_processed'] ?? $result['checked'] ?? 0 ),
                'confirmed_count' => (int) ( $result['confirmed_count'] ?? 0 ),
                'review_count'    => (int) ( $result['review_count'] ?? 0 ),
            ),
            'items'        => $manifest_rows,
        );
        $readme = "Yablonsky Security — Forensic Review Package\n\n"
            . "reports/scan.json contains the COMPLETE saved scan result, including coverage, timings, findings and trusted artifacts.\n"
            . "reports/scan.csv lists review findings and trusted artifacts using the same schema as the standalone CSV export.\n"
            . "reports/summary.txt provides a brief human-readable coverage and findings summary.\n"
            . "This package is available even when no malware findings exist; in that case files/ is intentionally absent.\n"
            . "When findings exist, eligible files are preserved under files/wp-content/... with original relative paths.\n"
            . "A file being present in this package does not by itself prove malware. Review classification and hashes in manifest.json.\n"
            . "Do not copy this archive over a live WordPress installation. Verify findings offline, use reversible quarantine when warranted, and restore trusted originals using official WordPress installation or update workflows.\n";
        $complete_scan_json = wp_json_encode( self::malware_report_package( $result ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        $manifest_json = wp_json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        if ( ! is_string( $complete_scan_json ) || '' === $complete_scan_json || ! is_string( $manifest_json ) || '' === $manifest_json ) {
            $zip->close();
            @unlink( $temp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Temporary export file cleanup.
            wp_die( esc_html__( 'The forensic ZIP could not be opened.', 'yablonsky-security' ) );
        }
        $summary = "Yablonsky Security forensic scan report\n"
            . "Scan status: " . (string) ( $result['status'] ?? 'unavailable' ) . "\n"
            . "Started: " . (string) ( $result['started_at'] ?? '' ) . "\n"
            . "Completed: " . (string) ( $result['completed_at'] ?? '' ) . "\n"
            . "Files scanned: " . (int) ( $result['files_processed'] ?? $result['checked'] ?? 0 ) . "\n"
            . "Coverage gaps: " . (int) ( $result['coverage_gaps'] ?? 0 ) . "\n"
            . "Findings requiring review: " . count( $findings ) . "\n"
            . "Confirmed: " . (int) ( $result['confirmed_count'] ?? 0 ) . "\n"
            . "Trusted artifacts: " . count( (array) ( $result['trusted_artifacts'] ?? array() ) ) . "\n"
            . "Files copied into this ZIP: " . count( array_filter( $manifest_rows, static fn( $row ) => 'included' === ( $row['export_status'] ?? '' ) ) ) . "\n";
        $added = $zip->addFromString( 'README.txt', $readme )
            && $zip->addFromString( 'manifest.json', $manifest_json )
            && $zip->addFromString( 'reports/scan.json', $complete_scan_json )
            && $zip->addFromString( 'reports/scan.csv', self::malware_report_csv( $result ) )
            && $zip->addFromString( 'reports/summary.txt', $summary );
        $closed = $zip->close();
        if ( ! $added || ! $closed ) {
            @unlink( $temp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Temporary export file cleanup.
            wp_die( esc_html__( 'The forensic ZIP could not be opened.', 'yablonsky-security' ) );
        }

        nocache_headers();
        header( 'Content-Type: application/zip' );
        header( 'Content-Disposition: attachment; filename="yablonsky-security-forensic-review-' . gmdate( 'Ymd-His' ) . '.zip"' );
        $length = @filesize( $temp );
        if ( false !== $length ) header( 'Content-Length: ' . (string) $length );
        readfile( $temp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- Temporary binary download is streamed and deleted immediately after output.
        @unlink( $temp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Temporary export file cleanup.
        exit;
    }

    public static function page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only navigation parameter.
        $tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'overview';
        $tabs = self::tabs();
        if ( ! isset( $tabs[ $tab ] ) ) {
            $tab = 'overview';
        }

        $settings = YSEC_Utils::settings();
        $protection_on = ! empty( $settings['observe_requests'] ) && ! empty( $settings['waf_enabled'] );
        $settings_url = add_query_arg( array( 'page' => 'yablonsky-security', 'tab' => 'settings' ), admin_url( 'admin.php' ) );

        settings_errors( 'ysec' );
        echo '<div class="wrap ysec ysec-shell">';
        echo '<header class="ysec-product-header"><div class="ysec-product-title"><h1>' . esc_html__( 'Yablonsky Security', 'yablonsky-security' ) . '</h1><p>' . esc_html__( 'WordPress security control plane: observe, verify, protect and respond — local-first, server-agnostic, with AI assistance on administrator request.', 'yablonsky-security' ) . '</p></div>';
        echo '<div class="ysec-product-actions"><a class="button button-primary" href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Security Settings', 'yablonsky-security' ) . '</a>';
        echo '<span class="ysec-pill ' . ( $protection_on ? 'ysec-pill-success' : 'ysec-pill-attention' ) . '">' . esc_html( $protection_on ? __( 'Protection active', 'yablonsky-security' ) : __( 'Review settings', 'yablonsky-security' ) ) . '</span>';
        echo '<span class="ysec-pill">v' . esc_html( YSEC_VERSION ) . '</span><span class="ysec-pill ysec-pill-free">' . esc_html__( 'Local protection · Free', 'yablonsky-security' ) . '</span></div></header>';

        echo '<nav class="ysec-tabs" aria-label="' . esc_attr__( 'Yablonsky Security sections', 'yablonsky-security' ) . '">';
        foreach ( $tabs as $key => $label ) {
            $url = add_query_arg( array( 'page' => 'yablonsky-security', 'tab' => $key ), admin_url( 'admin.php' ) );
            echo '<a class="ysec-tab ' . ( $tab === $key ? 'is-active' : '' ) . '" data-ysec-tab="' . esc_attr( $key ) . '" href="' . esc_url( $url ) . '"' . ( $tab === $key ? ' aria-current="page"' : '' ) . '>' . esc_html( $label ) . '</a>';
        }
        echo '</nav><main class="ysec-workspace"><section class="ysec-panel">';
        echo self::render_tab_html( $tab ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Internal admin renderer returns escaped YSec markup.
        echo '</section></main></div>';
    }

    public static function tab_overview(): void {
        $summary = YSEC_Events::summary();
        $posture = YSEC_Posture::report();
        $settings = YSEC_Utils::settings();
        $compat = YSEC_Compatibility::report();
        $active_compat = array_values( array_filter( $compat, static fn( $item ) => ! empty( $item['active'] ) ) );
        $baseline = get_option( 'ysec_integrity_baseline', array() );
        $baseline_files = isset( $baseline['files'] ) && is_array( $baseline['files'] ) ? count( $baseline['files'] ) : 0;
        $last_autopilot = YSEC_Autopilot::last_result();
        $analytics = YSEC_Events::analytics( 7 );
        $operations = YSEC_Operations::snapshot( 24 );
        $custom_url = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'settings' ), admin_url( 'admin.php' ) );
        $ai_url = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'ai' ), admin_url( 'admin.php' ) );

        echo '<section class="ysec-autopilot-card" data-ysec-autopilot><div class="ysec-autopilot-main"><span class="ysec-eyebrow">' . esc_html__( 'Autopilot', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'Optimize Now', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'One guarded transaction: analyze the site, snapshot the current configuration, apply a conservative protection profile, verify critical surfaces, then commit or automatically roll back.', 'yablonsky-security' ) . '</p><div class="ysec-autopilot-actions"><button type="button" class="button button-primary button-hero ysec-autopilot-run">' . esc_html__( 'Optimize Now', 'yablonsky-security' ) . '</button>';
        if ( YSEC_Autopilot::has_snapshot() ) echo '<button type="button" class="button ysec-autopilot-rollback">' . esc_html__( 'Rollback last optimization', 'yablonsky-security' ) . '</button>';
        echo '<span class="ysec-pill ysec-pill-free">' . esc_html__( 'Local protection · AI optional', 'yablonsky-security' ) . '</span></div><div class="ysec-autopilot-status" data-ysec-autopilot-status aria-live="polite">';
        if ( $last_autopilot ) {
            $ok = ! empty( $last_autopilot['applied'] ) && empty( $last_autopilot['rolled_back'] );
            echo '<strong>' . esc_html( $ok ? __( 'Last run committed', 'yablonsky-security' ) : __( 'Last run rolled back', 'yablonsky-security' ) ) . '</strong><span>' . esc_html( (string) ( $last_autopilot['ran_at'] ?? '' ) ) . '</span>';
        } else {
            echo '<span>' . esc_html__( 'Autopilot is ready for its first verified run. Manual controls stay available until you choose Optimize Now.', 'yablonsky-security' ) . '</span>';
        }
        echo '</div></div><div class="ysec-autopilot-flow" aria-label="' . esc_attr__( 'Autopilot transaction', 'yablonsky-security' ) . '"><span>' . esc_html__( 'Analyze', 'yablonsky-security' ) . '</span><b>→</b><span>' . esc_html__( 'Snapshot', 'yablonsky-security' ) . '</span><b>→</b><span>' . esc_html__( 'Apply', 'yablonsky-security' ) . '</span><b>→</b><span>' . esc_html__( 'Verify', 'yablonsky-security' ) . '</span><b>→</b><span>' . esc_html__( 'Prove', 'yablonsky-security' ) . '</span><b>→</b><span>' . esc_html__( 'Commit / Roll back', 'yablonsky-security' ) . '</span></div></section>';
        echo '<div class="ysec-mode-grid"><a class="ysec-mode-card is-primary" href="#" data-ysec-run-autopilot><span class="ysec-eyebrow">' . esc_html__( 'Level 1', 'yablonsky-security' ) . '</span><strong>' . esc_html__( 'Autopilot', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'For most sites: one verified safe transaction.', 'yablonsky-security' ) . '</small></a><a class="ysec-mode-card" href="' . esc_url( $custom_url ) . '"><span class="ysec-eyebrow">' . esc_html__( 'Level 2', 'yablonsky-security' ) . '</span><strong>' . esc_html__( 'Custom controls', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Manual control of protection, response, authentication and security records.', 'yablonsky-security' ) . '</small></a><a class="ysec-mode-card" href="' . esc_url( $ai_url ) . '"><span class="ysec-eyebrow">' . esc_html__( 'Level 3', 'yablonsky-security' ) . '</span><strong>' . esc_html__( 'AI / Expert', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Deep security analysis for ambiguous cases; local protection continues independently with AI as an administrator-invoked expert layer.', 'yablonsky-security' ) . '</small></a></div>';

        echo '<div class="ysec-context-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Security posture', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'Protection at a glance', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Signals and verdicts use separate states: suspicious activity stays an observation until verification establishes impact.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-pass">' . esc_html__( 'Local-first', 'yablonsky-security' ) . '</span></div>';

        echo '<section class="ysec-posture-card"><div class="ysec-posture-ring" style="--ysec-score:' . esc_attr( (string) $posture['score'] ) . '"><strong>' . esc_html( (string) $posture['score'] ) . '</strong><span>/100</span></div><div class="ysec-posture-copy"><span class="ysec-eyebrow">' . esc_html__( 'Protection posture', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Protection coverage score', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Enabled local controls contribute to this transparent score. Exposure resistance and current threat pressure remain separate so configuration quality and attack volume stay easy to read.', 'yablonsky-security' ) . '</p><div class="ysec-posture-indicators"><span>' . esc_html__( 'Enabled coverage', 'yablonsky-security' ) . ' <b>' . esc_html( (string) $posture['coverage'] ) . '</b></span><span>' . esc_html__( 'Exposure resistance', 'yablonsky-security' ) . ' <b>' . esc_html( (string) $posture['exposure'] ) . '</b></span><span>' . esc_html__( 'Threat pressure', 'yablonsky-security' ) . ' <b>' . esc_html( null === $posture['threat_pressure'] ? __( 'Unavailable', 'yablonsky-security' ) : (string) $posture['threat_pressure'] ) . '</b></span></div></div></section>';
        echo '<details class="ysec-posture-details"><summary>' . esc_html__( 'Show score calculation', 'yablonsky-security' ) . '</summary><div class="ysec-posture-controls">';
        foreach ( $posture['controls'] as $control ) {
            echo '<div><span class="ysec-status-badge ' . ( $control['on'] ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $control['on'] ? __( 'Enabled', 'yablonsky-security' ) : __( 'Available', 'yablonsky-security' ) ) . '</span><strong>' . esc_html( $control['label'] ) . '</strong><b>+' . esc_html( (string) ( $control['on'] ? $control['points'] : 0 ) ) . '/' . esc_html( (string) $control['points'] ) . '</b><small>' . esc_html( $control['why'] ) . '</small></div>';
        }
        echo '</div></details>';
        echo '<section class="ysec-surface ysec-overview-summary-surface"><div class="ysec-metrics ysec-metrics-5">';
        self::metric( __( 'Firewall', 'yablonsky-security' ), ! empty( $settings['waf_enabled'] ) ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ), __( 'Application layer', 'yablonsky-security' ), ! empty( $settings['waf_enabled'] ) ? 'pass' : 'attention' );
        $signals_available = ! array_key_exists( 'valid', $summary ) || ! empty( $summary['valid'] );
        self::metric( __( 'Critical signals · 24h', 'yablonsky-security' ), $signals_available ? (string) ( $summary['critical'] ?? 0 ) : '—', __( 'Security events', 'yablonsky-security' ), ! $signals_available ? 'attention' : ( ! empty( $summary['critical'] ) ? 'danger' : 'pass' ) );
        self::metric( __( 'High signals · 24h', 'yablonsky-security' ), $signals_available ? (string) ( $summary['high'] ?? 0 ) : '—', __( 'Requires context', 'yablonsky-security' ), ! $signals_available ? 'attention' : ( ! empty( $summary['high'] ) ? 'attention' : 'pass' ) );
        self::metric( __( 'Integrity baseline', 'yablonsky-security' ), $baseline_files ? number_format_i18n( $baseline_files ) : __( 'Not set', 'yablonsky-security' ), $baseline_files ? __( 'Files tracked', 'yablonsky-security' ) : __( 'Create after trust review', 'yablonsky-security' ), $baseline_files ? 'pass' : 'attention' );
        self::metric( __( 'Active security overlap', 'yablonsky-security' ), (string) count( $active_compat ), __( 'Overlapping enforcement tools', 'yablonsky-security' ), $active_compat ? 'attention' : 'pass' );
        echo '</div></section>';

        echo '<section class="ysec-surface ysec-operational-intelligence"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Security activity', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Last 24 hours', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Observed request decisions, blocks and containment activity from the current site.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-pass">' . esc_html__( 'LIVE', 'yablonsky-security' ) . '</span></div><div class="ysec-metrics ysec-metrics-5">';
        self::metric( __( 'Request decisions', 'yablonsky-security' ), number_format_i18n( (int) $operations['request_decisions'] ), __( 'Request-decision hits · 24h', 'yablonsky-security' ), 'neutral' );
        self::metric( __( 'Request denies', 'yablonsky-security' ), number_format_i18n( (int) $operations['request_denies'] ), __( 'Denied before application handling', 'yablonsky-security' ), (int) $operations['request_denies'] > 0 ? 'pass' : 'neutral' );
        self::metric( __( 'Scoped containment', 'yablonsky-security' ), number_format_i18n( (int) $operations['source_containments'] ), __( 'Source / campaign containment · 24h', 'yablonsky-security' ), (int) $operations['source_containments'] > 0 ? 'pass' : 'neutral' );
        /* translators: %s: number of distinct reconnaissance sources observed in the last 24 hours. */
        self::metric( __( 'Recon campaigns', 'yablonsky-security' ), number_format_i18n( (int) $operations['recon_campaigns'] ), sprintf( __( '%s distinct sources', 'yablonsky-security' ), number_format_i18n( (int) $operations['recon_sources'] ) ), 'neutral' );
        self::metric( __( 'Handled share', 'yablonsky-security' ), number_format_i18n( (float) $operations['handled_ratio'], 1 ) . '%', __( 'Denied / contained among request decisions', 'yablonsky-security' ), 'neutral' );
        echo '</div><dl class="ysec-kv-list"><div><dt>' . esc_html__( 'Active source blocks', 'yablonsky-security' ) . '</dt><dd>' . esc_html( number_format_i18n( (int) $operations['active_source_blocks'] ) ) . '</dd></div><div><dt>' . esc_html__( 'Enabled conditional deny rules', 'yablonsky-security' ) . '</dt><dd>' . esc_html( number_format_i18n( (int) $operations['conditional_rules'] ) ) . '</dd></div><div><dt>' . esc_html__( 'Enabled advisory virtual patches', 'yablonsky-security' ) . '</dt><dd>' . esc_html( number_format_i18n( (int) $operations['virtual_patches'] ) ) . '</dd></div></dl></section>';

        self::threat_analytics_panel( $analytics );

        echo '<section class="ysec-surface ysec-protection-layers"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Protection layers', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Current enforcement', 'yablonsky-security' ) . '</h3></div><span class="ysec-status-badge ' . ( ! empty( $settings['waf_enabled'] ) ? 'ysec-status-pass' : 'ysec-status-attention' ) . '">' . esc_html( ! empty( $settings['waf_enabled'] ) ? __( 'ACTIVE', 'yablonsky-security' ) : __( 'REVIEW', 'yablonsky-security' ) ) . '</span></div>';
        echo '<div class="ysec-layer-list">';
        self::layer_row( __( 'Request observation', 'yablonsky-security' ), ! empty( $settings['observe_requests'] ), __( 'Reconnaissance and suspicious-path security records', 'yablonsky-security' ) );
        self::layer_row( __( 'Application firewall', 'yablonsky-security' ), ! empty( $settings['waf_enabled'] ), __( 'Injection, traversal and exploit-pattern blocking', 'yablonsky-security' ) );
        /* translators: %d: configured login attempt limit. */
        $login_meta = sprintf( __( '%d attempts per window', 'yablonsky-security' ), absint( $settings['login_limit'] ) );
        self::layer_row( __( 'Login protection', 'yablonsky-security' ), true, $login_meta );
        self::layer_row( __( 'Security headers', 'yablonsky-security' ), ! empty( $settings['security_headers'] ), __( 'Safe response hardening', 'yablonsky-security' ) );
        echo '</div></section>';

        $export_url = wp_nonce_url( add_query_arg( array( 'page' => 'yablonsky-security', 'ysec_export' => 1 ), admin_url( 'admin.php' ) ), 'ysec_export' );
        $posture_report_url = wp_nonce_url( admin_url( 'admin-post.php?action=ysec_posture_report' ), 'ysec_posture_report' );
        echo '<div class="ysec-footer-actions"><div class="ysec-footer-action-buttons"><a class="button" href="' . esc_url( $export_url ) . '">' . esc_html__( 'Export security evidence', 'yablonsky-security' ) . '</a><a class="button" href="' . esc_url( $posture_report_url ) . '">' . esc_html__( 'Download posture report', 'yablonsky-security' ) . '</a></div><span>' . esc_html__( 'Evidence export removes source fingerprints. The posture report contains bounded security/runtime summaries and excludes raw IP evidence, user agents and API secrets.', 'yablonsky-security' ) . '</span></div>';
    }

    private static function threat_analytics_panel( array $analytics ): void {
        // A failed SQL read must not render an all-zero trend or the 'Local data' success badge.
        if ( array_key_exists( 'valid', $analytics ) && empty( $analytics['valid'] ) ) {
            echo '<section class="ysec-threat-analytics ysec-overview-trend"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Threat analytics', 'yablonsky-security' ) . '</span><h3>' . esc_html__( '7-day security pressure', 'yablonsky-security' ) . '</h3></div><span class="ysec-status-badge ysec-status-neutral">' . esc_html__( 'Review required', 'yablonsky-security' ) . '</span></div><div class="ysec-empty-cell">' . esc_html__( 'Unavailable', 'yablonsky-security' ) . '</div></section>';
            return;
        }
        $days = is_array( $analytics['days'] ?? null ) ? $analytics['days'] : array();
        $primary_points = array();
        $secondary_points = array();
        $count = count( $days );
        $baseline = 198.0;
        $plot_height = 170.0;
        $max_value = 1;
        foreach ( $days as $row ) {
            $max_value = max( $max_value, (int) ( $row['hits'] ?? 0 ), (int) ( $row['blocked'] ?? 0 ) );
        }
        foreach ( $days as $index => $row ) {
            $x = $count > 1 ? 24.0 + ( 952.0 * $index / ( $count - 1 ) ) : 500.0;
            $hits = (int) ( $row['hits'] ?? 0 );
            $blocked = (int) ( $row['blocked'] ?? 0 );
            $primary_y = $baseline - ( $plot_height * $hits / $max_value );
            $secondary_y = $baseline - ( $plot_height * $blocked / $max_value );
            $primary_points[] = array( $x, $primary_y, $hits, (string) ( $row['day'] ?? '' ) );
            $secondary_points[] = array( $x, $secondary_y, $blocked, (string) ( $row['day'] ?? '' ) );
        }
        $to_path = static function( array $points ): string {
            $parts = array();
            foreach ( $points as $index => $point ) {
                $parts[] = ( 0 === $index ? 'M ' : 'L ' ) . number_format( (float) $point[0], 2, '.', '' ) . ' ' . number_format( (float) $point[1], 2, '.', '' );
            }
            return implode( ' ', $parts );
        };

        echo '<section class="ysec-threat-analytics ysec-overview-trend"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Threat analytics', 'yablonsky-security' ) . '</span><h3>' . esc_html__( '7-day security pressure', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Compact local analytics preserves the security trend after raw records expire. Charts show observed requests and confirmed enforcement; incident verification remains a separate forensic step.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-pass">' . esc_html__( 'Local data', 'yablonsky-security' ) . '</span></div>';
        if ( $primary_points ) {
            $primary_line = $to_path( $primary_points );
            $secondary_line = $to_path( $secondary_points );
            $primary_area = $primary_line . ' L ' . number_format( $primary_points[ $count - 1 ][0], 2, '.', '' ) . ' ' . number_format( $baseline, 2, '.', '' ) . ' L ' . number_format( $primary_points[0][0], 2, '.', '' ) . ' ' . number_format( $baseline, 2, '.', '' ) . ' Z';
            $secondary_area = $secondary_line . ' L ' . number_format( $secondary_points[ $count - 1 ][0], 2, '.', '' ) . ' ' . number_format( $baseline, 2, '.', '' ) . ' L ' . number_format( $secondary_points[0][0], 2, '.', '' ) . ' ' . number_format( $baseline, 2, '.', '' ) . ' Z';
            echo '<div class="ysec-trend-chart"><svg viewBox="0 0 1000 230" preserveAspectRatio="xMidYMid meet" role="img" aria-label="' . esc_attr__( 'Observed security hits and blocked or contained requests by day', 'yablonsky-security' ) . '">';
            foreach ( array( 0.25, 0.5, 0.75, 1.0 ) as $fraction ) {
                $y = $baseline - $plot_height * $fraction;
                echo '<line class="ysec-trend-gridline" x1="18" y1="' . esc_attr( number_format( $y, 2, '.', '' ) ) . '" x2="982" y2="' . esc_attr( number_format( $y, 2, '.', '' ) ) . '"></line>';
            }
            echo '<path class="ysec-trend-area ysec-trend-area-primary" d="' . esc_attr( $primary_area ) . '"></path><path class="ysec-trend-area ysec-trend-area-secondary" d="' . esc_attr( $secondary_area ) . '"></path><path class="ysec-trend-line ysec-trend-line-primary" d="' . esc_attr( $primary_line ) . '"></path><path class="ysec-trend-line ysec-trend-line-secondary" d="' . esc_attr( $secondary_line ) . '"></path>';
            foreach ( $primary_points as $index => $point ) {
                $secondary = $secondary_points[ $index ];
                $day_label = $point[3] ? wp_date( 'M j', strtotime( $point[3] . ' 12:00:00 UTC' ) ) : '';
                echo '<circle class="ysec-trend-point ysec-trend-point-primary" cx="' . esc_attr( number_format( $point[0], 2, '.', '' ) ) . '" cy="' . esc_attr( number_format( $point[1], 2, '.', '' ) ) . '" r="3"><title>' . esc_html( $day_label . ' · ' . __( 'Observed security hits', 'yablonsky-security' ) . ': ' . number_format_i18n( $point[2] ) ) . '</title></circle>';
                echo '<circle class="ysec-trend-point ysec-trend-point-secondary" cx="' . esc_attr( number_format( $secondary[0], 2, '.', '' ) ) . '" cy="' . esc_attr( number_format( $secondary[1], 2, '.', '' ) ) . '" r="3"><title>' . esc_html( $day_label . ' · ' . __( 'Blocked / contained', 'yablonsky-security' ) . ': ' . number_format_i18n( $secondary[2] ) ) . '</title></circle>';
            }
            echo '</svg><div class="ysec-trend-axis-labels">';
            foreach ( $days as $row ) {
                $day = (string) ( $row['day'] ?? '' );
                echo '<span>' . esc_html( $day ? wp_date( 'D', strtotime( $day . ' 12:00:00 UTC' ) ) : '' ) . '</span>';
            }
            echo '</div></div>';
        } else {
            echo '<div class="ysec-empty-cell">' . esc_html__( 'No analytics data is available yet.', 'yablonsky-security' ) . '</div>';
        }
        echo '<div class="ysec-threat-columns">';
        self::analytics_rank( __( 'Top attack families', 'yablonsky-security' ), $analytics['families'] ?? array() );
        self::analytics_rank( __( 'Country signals', 'yablonsky-security' ), $analytics['countries'] ?? array() );
        $path_items = array();
        foreach ( ( $analytics['paths'] ?? array() ) as $row ) {
            $path_items[ (string) ( $row['path'] ?? '' ) ] = (int) ( $row['hits'] ?? 0 );
        }
        self::analytics_rank( __( 'Hot targeted paths', 'yablonsky-security' ), $path_items );
        echo '</div><div class="ysec-chart-legend"><span><i class="is-requests"></i>' . esc_html__( 'Observed security hits', 'yablonsky-security' ) . '</span><span><i class="is-blocked"></i>' . esc_html__( 'Blocked / contained', 'yablonsky-security' ) . '</span></div></section>';
    }

    private static function analytics_rank( string $title, array $items ): void {
        echo '<div class="ysec-threat-rank"><strong>' . esc_html( $title ) . '</strong>';
        $max=$items?max(array_map('intval',$items)):1; $shown=0;
        foreach($items as $label=>$hits){ if(''===(string)$label)continue; $shown++; $width=max(2,(int)round(100*(int)$hits/max(1,$max))); echo '<div><span title="' . esc_attr((string)$label) . '">' . esc_html((string)$label) . '</span><i><b style="--w:' . esc_attr((string)$width) . '%"></b></i><em>' . esc_html(number_format_i18n((int)$hits)) . '</em></div>'; }
        if(!$shown) echo '<small>' . esc_html__( 'No signal in this window.', 'yablonsky-security' ) . '</small>';
        echo '</div>';
    }

    public static function tab_events(): void {
        YSEC_Admin_Tables::events();
    }

    public static function tab_recon(): void {
        YSEC_Admin_Tables::recon();
    }

    public static function tab_compatibility(): void {
        $items = YSEC_Compatibility::report();
        $active_items = array_values( array_filter( $items, static fn( $item ) => ! empty( $item['active'] ) ) );
        $interop = YSEC_Discovery_Interop::admin_summary();
        $request_contract = YSEC_Request_Contract::admin_summary();

        echo '<div class="ysec-context-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Compatibility', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'Security stack compatibility', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'See which security tools are installed, where responsibilities overlap, and open migration tools only when you choose to move protection into YSec.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $active_items ? 'ysec-status-attention' : 'ysec-status-pass' ) . '">' . esc_html( $active_items ? __( 'OVERLAP TO REVIEW', 'yablonsky-security' ) : __( 'STACK CLEAR', 'yablonsky-security' ) ) . '</span></div>';

        echo '<section class="ysec-surface ysec-security-stack"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Current stack', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Installed security tools', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Active overlap deserves one clear owner per enforcement responsibility. Installed inactive tools remain available for deliberate migration or removal.', 'yablonsky-security' ) . '</p></div></div>';
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Plugin', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'State', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Overlapping protection', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Next action', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $items as $item ) {
            $state_label = ! empty( $item['active'] ) ? __( 'Active', 'yablonsky-security' ) : __( 'Installed · inactive', 'yablonsky-security' );
            $state_class = ! empty( $item['active'] ) ? 'high' : 'info';
            echo '<tr><td><strong>' . esc_html( (string) $item['name'] ) . '</strong></td><td><span class="ysec-badge ysec-badge-' . esc_attr( $state_class ) . '">' . esc_html( $state_label ) . '</span></td><td>' . esc_html( implode( ', ', (array) $item['overlap'] ) ) . '</td><td>' . esc_html( (string) $item['recommendation'] ) . '</td></tr>';
        }
        if ( ! $items ) {
            echo '<tr><td colspan="4" class="ysec-empty-cell">' . esc_html__( 'The current WordPress stack has no known overlapping security products.', 'yablonsky-security' ) . '</td></tr>';
        }
        echo '</tbody></table></div></section>';

        echo '<section class="ysec-surface ysec-responsibility-boundaries"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Responsibilities', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'One clear authority for each layer', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Security, performance and discovery stay coordinated while each product keeps a focused responsibility.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-pass">v' . esc_html( (string) ( $request_contract['version'] ?? '1' ) ) . '</span></div><div class="ysec-grid ysec-grid-3">';
        self::metric( __( 'Security', 'yablonsky-security' ), __( 'YSec', 'yablonsky-security' ), __( 'Request safety · containment · authentication', 'yablonsky-security' ), 'pass' );
        self::metric( __( 'Performance', 'yablonsky-security' ), __( 'YPerf', 'yablonsky-security' ), __( 'Cache · backpressure · render efficiency', 'yablonsky-security' ), 'neutral' );
        self::metric( __( 'Discovery', 'yablonsky-security' ), ! empty( $interop['yseo_active'] ) ? __( 'YSEO', 'yablonsky-security' ) : __( 'Site policy', 'yablonsky-security' ), __( 'Indexing · AI discovery · retrieval', 'yablonsky-security' ), 'neutral' );
        echo '</div><div class="ysec-policy-strip ysec-discovery-safe-strip"><span class="ysec-status-badge ysec-status-pass">' . esc_html__( 'Discovery-friendly security', 'yablonsky-security' ) . '</span><span>' . esc_html__( 'Public search and AI crawler access stays available while concrete exploit, secret and abuse behavior drives the security response.', 'yablonsky-security' ) . '</span></div></section>';

        $fleet = YSEC_Multisite::report();
        if ( ! empty( $fleet['multisite'] ) ) {
            echo '<section class="ysec-surface ysec-fleet-readiness"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'WordPress network', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Network policy consistency', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'YSec compares bounded, non-secret policy fingerprints across the current WordPress network so administrators can spot configuration drift.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-neutral">' . esc_html__( 'LOCAL DIAGNOSTICS', 'yablonsky-security' ) . '</span></div>';
            /* translators: %s: number of multisite installs inspected during this bounded diagnostics pass. */
            echo '<div class="ysec-metrics ysec-metrics-4"><div class="ysec-metric ysec-metric-neutral"><span>' . esc_html__( 'Sites', 'yablonsky-security' ) . '</span><strong>' . esc_html( number_format_i18n( (int) $fleet['site_count'] ) ) . '</strong><small>' . esc_html( sprintf( __( '%s inspected in this bounded pass', 'yablonsky-security' ), number_format_i18n( (int) $fleet['scanned_sites'] ) ) ) . '</small></div><div class="ysec-metric ysec-metric-neutral"><span>' . esc_html__( 'YSec active', 'yablonsky-security' ) . '</span><strong>' . esc_html( number_format_i18n( (int) $fleet['active_sites'] ) ) . '</strong><small>' . esc_html( ! empty( $fleet['network_active'] ) ? __( 'Network activated', 'yablonsky-security' ) : __( 'Site activation observed', 'yablonsky-security' ) ) . '</small></div><div class="ysec-metric ysec-metric-neutral"><span>' . esc_html__( 'Policy groups', 'yablonsky-security' ) . '</span><strong>' . esc_html( number_format_i18n( (int) $fleet['policy_groups'] ) ) . '</strong><small>' . esc_html__( 'Non-secret configuration fingerprints', 'yablonsky-security' ) . '</small></div><div class="ysec-metric ' . ( (int) $fleet['divergent_sites'] > 0 ? 'ysec-metric-attention' : 'ysec-metric-pass' ) . '"><span>' . esc_html__( 'Divergent sites', 'yablonsky-security' ) . '</span><strong>' . esc_html( number_format_i18n( (int) $fleet['divergent_sites'] ) ) . '</strong><small>' . esc_html__( 'Compared across active inspected sites', 'yablonsky-security' ) . '</small></div></div>';
            if ( ! empty( $fleet['truncated'] ) ) {
                echo '<p class="description">' . esc_html__( 'This network exceeds the bounded diagnostics window; the current pass inspects the first 100 sites.', 'yablonsky-security' ) . '</p>';
            }
            echo '</section>';
        }

        if ( ! $items ) {
            return;
        }

        $readiness = YSEC_Migration::readiness();
        $last_cutover = YSEC_Migration::last_snapshot();
        $last_mapping = YSEC_Migration::last_mapping_result();
        $last_proof = YSEC_Migration::last_cutover_proof();
        $takeover = YSEC_Takeover::status();
        $takeover_last = YSEC_Takeover::last();

        echo '<details class="ysec-surface ysec-migration-tools"><summary class="ysec-migration-tools-summary"><span><strong>' . esc_html__( 'Migration from detected security tools', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Open these controls when you choose to move overlapping protection responsibilities into YSec.', 'yablonsky-security' ) . '</small></span><span class="ysec-status-badge ' . esc_attr( $readiness['passed'] === $readiness['total'] ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $readiness['passed'] . '/' . $readiness['total'] ) . '</span></summary><div class="ysec-migration-tools-body">';

        echo '<div class="ysec-grid ysec-grid-3">';
        self::metric( __( 'Detected tools', 'yablonsky-security' ), number_format_i18n( count( $items ) ), __( 'Installed security products', 'yablonsky-security' ), 'neutral' );
        self::metric( __( 'Active overlaps', 'yablonsky-security' ), number_format_i18n( count( $active_items ) ), __( 'Current enforcement overlap', 'yablonsky-security' ), $active_items ? 'attention' : 'pass' );
        self::metric( __( 'Migration checks', 'yablonsky-security' ), $readiness['passed'] . '/' . $readiness['total'], __( 'Protection handoff prerequisites', 'yablonsky-security' ), $readiness['passed'] === $readiness['total'] ? 'pass' : 'neutral' );
        echo '</div>';

        if ( $last_mapping ) {
            echo '<div class="ysec-policy-strip"><span class="ysec-status-badge ysec-status-pass">' . esc_html__( 'Last guided mapping', 'yablonsky-security' ) . '</span><span>' . esc_html( sprintf(
                /* translators: %d: number of YSec settings changed by the most recent guided mapping. */
                __( '%d YSec setting(s) changed. Plugin activation remained administrator-controlled.', 'yablonsky-security' ),
                (int) ( $last_mapping['changed'] ?? 0 )
            ) ) . '</span></div>';
        }
        if ( $last_proof ) {
            $proof_ok = ! empty( $last_proof['ok'] );
            $proof_url = wp_nonce_url( add_query_arg( array( 'action'=>'ysec_cutover_proof_export' ), admin_url( 'admin-post.php' ) ), 'ysec_cutover_proof_export' );
            echo '<div class="ysec-cutover-proof-summary"><div><span class="ysec-status-badge ' . esc_attr( $proof_ok ? 'ysec-status-pass' : 'ysec-status-attention' ) . '">' . esc_html( $proof_ok ? __( 'MIGRATION PROVED', 'yablonsky-security' ) : __( 'REVIEW', 'yablonsky-security' ) ) . '</span><strong>' . esc_html( (string) ( $last_proof['source']['name'] ?? __( 'Security source', 'yablonsky-security' ) ) ) . '</strong><small>' . esc_html( (string) ( $last_proof['generated_at'] ?? '' ) ) . '</small></div><a class="button" href="' . esc_url( $proof_url ) . '">' . esc_html__( 'Export migration proof JSON', 'yablonsky-security' ) . '</a></div>';
        }

        foreach ( $items as $item ) {
            $source_file = (string) $item['file'];
            $snap = YSEC_Migration::source_snapshot( $source_file );
            $source_state = ! empty( $item['active'] ) ? __( 'active', 'yablonsky-security' ) : __( 'installed · inactive', 'yablonsky-security' );
            echo '<details class="ysec-migration-source"><summary><strong>' . esc_html( (string) $item['name'] ) . '</strong> — ' . esc_html( $source_state ) . '</summary>';
            if ( ! empty( $snap['signals'] ) ) {
                echo '<dl class="ysec-kv-list">';
                foreach ( $snap['signals'] as $key => $value ) {
                    echo '<div><dt>' . esc_html( (string) $key ) . '</dt><dd><code>' . esc_html( (string) $value ) . '</code></dd></div>';
                }
                echo '</dl>';
            }
            $mapping = YSEC_Migration::mapping_preview( $source_file );
            if ( $mapping ) {
                echo '<form method="post" class="ysec-migration-map">';
                wp_nonce_field( 'ysec_migration_mapping' );
                echo '<input type="hidden" name="source_file" value="' . esc_attr( $source_file ) . '"><div class="ysec-surface-head ysec-migration-map-head"><div><strong>' . esc_html__( 'Guided mapping', 'yablonsky-security' ) . '</strong><p class="description">' . esc_html__( 'Select the source controls you want represented in YSec. YSec snapshots its current settings before applying the selected mapping, while plugin activation remains administrator-controlled.', 'yablonsky-security' ) . '</p></div></div><div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><th class="check-column"><span class="screen-reader-text">' . esc_html__( 'Select', 'yablonsky-security' ) . '</span></th><th>' . esc_html__( 'Source signal', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'YSec target', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Proposed state', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Mode', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
                foreach ( $mapping as $map ) {
                    $applyable = ! empty( $map['applyable'] );
                    /* translators: %s: target YSec setting label. */
                    $mapping_aria = sprintf( __( 'Apply mapping for %s', 'yablonsky-security' ), (string) $map['target_label'] );
                    echo '<tr><th class="check-column">' . ( $applyable ? '<input type="checkbox" name="mapping_targets[]" value="' . esc_attr( (string) $map['target'] ) . '" aria-label="' . esc_attr( $mapping_aria ) . '">' : '<span aria-hidden="true">—</span>' ) . '</th><td><strong>' . esc_html( (string) $map['source'] ) . '</strong><br><code>' . esc_html( (string) $map['source_value'] ) . '</code></td><td>' . esc_html( (string) $map['target_label'] ) . '<br><code>' . esc_html( (string) $map['target'] ) . '</code></td><td>' . esc_html( (string) $map['proposed'] ) . '</td><td><span class="ysec-badge ysec-badge-' . esc_attr( $applyable ? 'info' : 'medium' ) . '">' . esc_html( $applyable ? __( 'Selectable', 'yablonsky-security' ) : __( 'Manual review', 'yablonsky-security' ) ) . '</span></td></tr>';
                }
                echo '</tbody></table></div><div class="ysec-migration-actions"><button class="button button-primary" name="ysec_apply_migration_mapping" value="1">' . esc_html__( 'Apply selected to YSec', 'yablonsky-security' ) . '</button><span>' . esc_html__( 'Plugin activation remains administrator-controlled.', 'yablonsky-security' ) . '</span></div></form>';
            }
            foreach ( (array) ( $snap['notes'] ?? array() ) as $note ) {
                echo '<p class="description">' . esc_html( (string) $note ) . '</p>';
            }
            echo '<form method="post" class="ysec-action-row ysec-cutover-proof-action">';
            wp_nonce_field( 'ysec_cutover_proof' );
            echo '<input type="hidden" name="source_file" value="' . esc_attr( $source_file ) . '"><button class="button" name="ysec_run_cutover_proof" value="1">' . esc_html__( 'Run migration proof', 'yablonsky-security' ) . '</button><span>' . esc_html__( 'Use this after the selected protection responsibility has moved to YSec. The proof checks YSec runtime health and live firewall enforcement.', 'yablonsky-security' ) . '</span></form>';
            echo '</details>';
        }

        echo '<div class="ysec-cutover-toolbar"><form method="post" class="ysec-action-row">';
        wp_nonce_field( 'ysec_cutover_snapshot' );
        echo '<button class="button" name="ysec_capture_cutover_snapshot" value="1">' . esc_html__( 'Capture migration snapshot', 'yablonsky-security' ) . '</button>';
        if ( $last_cutover ) {
            echo '<span>' . esc_html__( 'Last snapshot:', 'yablonsky-security' ) . ' <strong>' . esc_html( (string) ( $last_cutover['captured_at'] ?? '' ) ) . '</strong></span>';
        }
        echo '</form>';
        if ( YSEC_Migration::has_mapping_snapshot() ) {
            echo '<form method="post" class="ysec-action-row">';
            wp_nonce_field( 'ysec_migration_mapping_rollback' );
            echo '<button class="button" name="ysec_rollback_migration_mapping" value="1">' . esc_html__( 'Restore pre-mapping YSec settings', 'yablonsky-security' ) . '</button></form>';
        }
        echo '</div>';

        $takeover_ready = ! empty( $takeover['ready'] );
        echo '<div class="ysec-migration-completion"><div class="ysec-surface-head"><div><strong>' . esc_html__( 'Migration completion', 'yablonsky-security' ) . '</strong><p>' . esc_html__( 'Confirm source-plugin state, YSec runtime health, live firewall proof and production exposure before retiring prior security tooling.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $takeover_ready ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( (int) $takeover['passed'] . '/' . (int) $takeover['total'] ) . '</span></div><div class="ysec-grid ysec-grid-2">';
        foreach ( (array) $takeover['gates'] as $gate ) {
            echo '<div class="ysec-mini-card"><span class="ysec-badge ysec-badge-' . esc_attr( ! empty( $gate['pass'] ) ? 'low' : 'info' ) . '">' . esc_html( ! empty( $gate['pass'] ) ? __( 'Pass', 'yablonsky-security' ) : __( 'Available', 'yablonsky-security' ) ) . '</span><strong>' . esc_html( (string) $gate['label'] ) . '</strong><small>' . esc_html( (string) $gate['detail'] ) . '</small></div>';
        }
        echo '</div><div class="ysec-action-row"><form method="post">';
        wp_nonce_field( 'ysec_takeover_closeout' );
        echo '<button class="button button-primary" name="ysec_run_takeover_closeout" value="1">' . esc_html__( 'Run migration completion check', 'yablonsky-security' ) . '</button></form>';
        if ( $takeover_last ) {
            $takeover_url = wp_nonce_url( add_query_arg( array( 'action'=>'ysec_takeover_closeout_export' ), admin_url( 'admin-post.php' ) ), 'ysec_takeover_closeout_export' );
            echo '<a class="button" href="' . esc_url( $takeover_url ) . '">' . esc_html__( 'Export migration completion JSON', 'yablonsky-security' ) . '</a>';
        }
        echo '</div></div></div></details>';
    }

    public static function tab_accounts(): void {
        YSEC_Admin_Tables::accounts();
    }

    public static function tab_firewall(): void {
        YSEC_Admin_Tables::firewall( static function(): void {
            self::origin_protection_tools();
        } );
    }

    private static function origin_protection_tools(): void {
        $summary = YSEC_DDoS_Operations::summary();
        $core_ready = absint( $summary['core_ready'] ?? 0 );
        $core_total = max( 1, absint( $summary['core_total'] ?? 0 ) );
        echo '<section class="ysec-surface ysec-origin-protection-tools"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Origin protection', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Application DDoS and early-runtime layers', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'The live Firewall monitor stays primary. These controls explain and verify the earlier protection layers that reduce origin pressure before normal WordPress processing.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-pass">' . esc_html( sprintf( '%1$d/%2$d', $core_ready, $core_total ) ) . '</span></div>';
        echo '<div class="ysec-origin-tabs" role="tablist" aria-label="' . esc_attr__( 'Origin protection tools', 'yablonsky-security' ) . '"><button type="button" class="ysec-origin-tab is-active" role="tab" aria-selected="true" data-ysec-origin-tab="status">' . esc_html__( 'Protection layers', 'yablonsky-security' ) . '</button><button type="button" class="ysec-origin-tab" role="tab" aria-selected="false" data-ysec-origin-tab="mu">' . esc_html__( 'Managed MU runtime', 'yablonsky-security' ) . '</button></div>';
        echo '<div class="ysec-origin-panel is-active" data-ysec-origin-panel="status">';
        self::application_ddos_panel( $summary );
        echo '</div><div class="ysec-origin-panel" data-ysec-origin-panel="mu" hidden>';
        self::managed_mu_runtime_panel();
        echo '</div></section>';
    }

    private static function application_ddos_panel( array $summary ): void {
        $core_ready = absint( $summary['core_ready'] ?? 0 );
        $core_total = max( 1, absint( $summary['core_total'] ?? 0 ) );
        $extended_ready = absint( $summary['extended_ready'] ?? 0 );
        $extended_total = max( 1, absint( $summary['extended_total'] ?? 0 ) );
        $core_complete = $core_ready >= $core_total;
        $profile_label = trim( (string) ( $summary['profile_label'] ?? '' ) );
        if ( '' === $profile_label ) $profile_label = __( 'Active profile', 'yablonsky-security' );
        echo '<div class="ysec-origin-panel-head"><div><strong>' . esc_html__( 'Application-layer DDoS protection', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Core layers stop or classify hostile Layer-7 traffic early; extended layers add persistent burst counters and server filtering before PHP.', 'yablonsky-security' ) . '</span></div><span class="ysec-status-badge ' . esc_attr( $core_complete ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $core_complete ? __( 'CORE PROTECTED', 'yablonsky-security' ) : __( 'CORE READY TO EXTEND', 'yablonsky-security' ) ) . '</span></div><div class="ysec-grid ysec-grid-4">';
        self::metric( __( 'Firewall profile', 'yablonsky-security' ), $profile_label, __( 'request-safety policy', 'yablonsky-security' ), 'pass' );
        self::metric( __( 'Core application layers', 'yablonsky-security' ), sprintf( '%1$d of %2$d', $core_ready, $core_total ), __( 'active security layers', 'yablonsky-security' ), $core_complete ? 'pass' : 'neutral' );
        self::metric( __( 'Extended origin layers', 'yablonsky-security' ), sprintf( '%1$d of %2$d', $extended_ready, $extended_total ), __( 'available origin extensions', 'yablonsky-security' ), $extended_ready > 0 ? 'pass' : 'neutral' );
        self::metric( __( 'Crawler posture', 'yablonsky-security' ), __( 'Discovery-friendly', 'yablonsky-security' ), __( 'behavior-first security', 'yablonsky-security' ), 'pass' );
        echo '</div><div class="ysec-grid ysec-grid-2 ysec-origin-layer-grid">';
        foreach ( (array) ( $summary['layers'] ?? array() ) as $layer ) {
            $state = (string) ( $layer['state'] ?? 'available' );
            $label = ucwords( str_replace( '_', ' ', $state ) );
            $group = 'core' === (string) ( $layer['group'] ?? '' ) ? __( 'Core application layer', 'yablonsky-security' ) : __( 'Extended origin layer', 'yablonsky-security' );
            echo '<div class="ysec-mini-card"><span class="ysec-badge ysec-badge-' . esc_attr( in_array( $state, array( 'ready','verified','observing' ), true ) ? 'low' : 'info' ) . '">' . esc_html( $label ) . '</span><strong>' . esc_html( (string) ( $layer['label'] ?? '' ) ) . '</strong><small>' . esc_html( $group . ' · ' . (string) ( $layer['detail'] ?? '' ) ) . '</small><small><strong>' . esc_html__( 'Next action:', 'yablonsky-security' ) . '</strong> ' . esc_html( (string) ( $layer['next'] ?? '' ) ) . '</small></div>';
        }
        echo '</div>';
    }

    private static function managed_mu_runtime_panel(): void {
        $status = YSEC_Managed_MU::status();
        $verify = get_transient( 'ysec_mu_verify_result' );
        $active = ! empty( $status['installed'] ) && ! empty( $status['owned'] ) && ! empty( $status['runtime_readable'] ) && ! empty( $status['policy_valid'] );
        $duplicates = is_array( $status['duplicates'] ?? null ) ? $status['duplicates'] : array();
        $badge = $active ? __( 'READY', 'yablonsky-security' ) : ( ! empty( $status['installed'] ) ? __( 'REVIEW', 'yablonsky-security' ) : __( 'AVAILABLE', 'yablonsky-security' ) );
        $badge_class = $active ? 'ysec-status-pass' : ( ! empty( $status['installed'] ) ? 'ysec-status-attention' : 'ysec-status-neutral' );
        echo '<div class="ysec-origin-panel-head"><div><strong>' . esc_html__( 'Managed MU DDoS & Early Guard', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'A thin managed MU bridge applies deterministic local security rules at the earliest WordPress stage while preserving discovery-friendly public traffic.', 'yablonsky-security' ) . '</span></div><span class="ysec-status-badge ' . esc_attr( $badge_class ) . '">' . esc_html( $badge ) . '</span></div>';
        echo '<div class="ysec-grid ysec-grid-4">';
        self::metric( __( 'Loader', 'yablonsky-security' ), ! empty( $status['installed'] ) && ! empty( $status['owned'] ) ? __( 'Owned', 'yablonsky-security' ) : __( 'Available', 'yablonsky-security' ), __( 'mu-plugins', 'yablonsky-security' ), ! empty( $status['installed'] ) ? 'low' : 'neutral' );
        self::metric( __( 'Handshake', 'yablonsky-security' ), ! empty( $status['policy_valid'] ) ? __( 'Valid', 'yablonsky-security' ) : __( 'Standby', 'yablonsky-security' ), 'ABI ' . absint( $status['abi'] ?? 0 ), ! empty( $status['policy_valid'] ) ? 'low' : 'neutral' );
        self::metric( __( 'Crawler treatment', 'yablonsky-security' ), __( 'Discovery-friendly', 'yablonsky-security' ), __( 'Behavior-first security', 'yablonsky-security' ), 'low' );
        self::metric( __( 'Other early guards', 'yablonsky-security' ), (string) count( $duplicates ), __( 'Detected and preserved', 'yablonsky-security' ), $duplicates ? 'medium' : 'neutral' );
        echo '</div><div class="ysec-callout ysec-origin-callout"><strong>' . esc_html__( 'WordPress-edge protection.', 'yablonsky-security' ) . '</strong> ' . esc_html__( 'Early request shedding reduces origin pressure from hostile Layer-7 floods before WooCommerce, themes and normal plugins load. Network-edge protection complements this layer for bandwidth and connection floods.', 'yablonsky-security' ) . '</div>';
        if ( $duplicates ) {
            echo '<details class="ysec-origin-provider-list"><summary><strong>' . esc_html__( 'Detected third-party / historical MU security providers', 'yablonsky-security' ) . '</strong></summary><ul class="ysec-findings">';
            foreach ( $duplicates as $provider ) echo '<li><strong>' . esc_html( (string) ( $provider['file'] ?? '' ) ) . '</strong> · ' . esc_html( (string) ( $provider['provider'] ?? '' ) ) . ' · <code>' . esc_html( substr( (string) ( $provider['sha256'] ?? '' ), 0, 16 ) ) . '…</code></li>';
            echo '</ul></details>';
        }
        if ( is_array( $verify ) ) echo '<p class="ysec-origin-proof"><strong>' . esc_html__( 'Last live proof:', 'yablonsky-security' ) . '</strong> ' . esc_html( ! empty( $verify['ok'] ) ? 'PASS' : 'ATTENTION' ) . ' · HTTP ' . esc_html( (string) absint( $verify['code'] ?? 0 ) ) . ' · ' . esc_html( (string) ( $verify['checked_at'] ?? '' ) ) . '</p>';
        echo '<form method="post" class="ysec-action-row ysec-origin-actions">';
        wp_nonce_field( 'ysec_mu_runtime' );
        if ( empty( $status['installed'] ) ) {
            echo '<button class="button button-primary" name="ysec_mu_install" value="1">' . esc_html__( 'Install Managed MU Runtime', 'yablonsky-security' ) . '</button>';
        } else {
            echo '<button class="button" name="ysec_mu_refresh" value="1">' . esc_html__( 'Refresh compiled policy', 'yablonsky-security' ) . '</button>';
            echo '<button class="button button-primary" name="ysec_mu_verify" value="1">' . esc_html__( 'Verify early runtime', 'yablonsky-security' ) . '</button>';
            if ( ! empty( $status['owned'] ) ) echo '<button class="button" name="ysec_mu_remove" value="1">' . esc_html__( 'Remove managed MU runtime', 'yablonsky-security' ) . '</button>';
        }
        echo '</form>';
    }

    public static function tab_integrity(): void {
        echo '<div class="ysec-context-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Integrity', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'File integrity & permissions', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Compare trusted hashes and audit critical WordPress file/folder permissions. Permission drift is monitored separately from content drift.', 'yablonsky-security' ) . '</p></div></div><div class="ysec-action-split"><form method="post" class="ysec-action-row">';
        wp_nonce_field( 'ysec_integrity' );
        echo '<button class="button button-primary" name="ysec_integrity_scan" value="1">' . esc_html__( 'Run integrity scan', 'yablonsky-security' ) . '</button> <button class="button" name="ysec_integrity_baseline" value="1">' . esc_html__( 'Create new baseline', 'yablonsky-security' ) . '</button></form><form method="post" class="ysec-action-row">';
        wp_nonce_field( 'ysec_permissions' );
        echo '<button class="button" name="ysec_permission_scan" value="1">' . esc_html__( 'Scan permissions', 'yablonsky-security' ) . '</button> <button class="button" name="ysec_permission_repair" value="1">' . esc_html__( 'Repair unsafe permissions', 'yablonsky-security' ) . '</button></form></div>';
        $ignore_rules = YSEC_Integrity::ignored_paths();
        echo '<details class="ysec-surface ysec-integrity-policy"><summary><strong>' . esc_html__( 'Integrity review policy', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Optional exact/prefix paths excluded from drift alerts', 'yablonsky-security' ) . '</span></summary><form method="post">';
        wp_nonce_field( 'ysec_integrity_ignores' );
        echo '<label class="ysec-field"><span>' . esc_html__( 'Ignored integrity paths', 'yablonsky-security' ) . '</span><textarea rows="6" name="ysec_integrity_ignores" placeholder="wp-content/cache/*">' . esc_textarea( implode( "\n", $ignore_rules ) ) . '</textarea><small>' . esc_html__( 'One path per line, relative to WordPress root. Use a trailing * for a prefix. Do not ignore application code merely to hide unexplained drift.', 'yablonsky-security' ) . '</small></label><p><button class="button" name="ysec_integrity_save_ignores" value="1">' . esc_html__( 'Save review policy', 'yablonsky-security' ) . '</button></p></form></details>';
        YSEC_Admin_Tables::integrity_result();
        YSEC_Admin_Tables::permissions_result();
    }

    public static function tab_vulnerabilities(): void {
        YSEC_Admin_Tables::vulnerabilities();
    }

    public static function tab_malware(): void {
        $stored_scan = YSEC_Malware::latest_result();
        $has_scan = ! empty( $stored_scan ) && YSEC_Malware::result_has_current_coverage( $stored_scan );
        $engine = YSEC_Malware::engine_info();
        $scan_state = YSEC_Malware::full_scan_public_state();
        $clam_ready = ! empty( $engine['clamav_available'] );
        $ingress = YSEC_File_Ingress::last_receipt();
        $scan_status = (string) ( $scan_state['status'] ?? 'idle' );
        $has_report_state = $has_scan || 'idle' !== $scan_status;
        $clamav_complete = ! array_key_exists( 'clamav_complete', $scan_state ) || ! empty( $scan_state['clamav_complete'] );
        $finding_count = (int) ( $scan_state['finding_count'] ?? 0 );
        $confirmed_count = (int) ( $scan_state['confirmed_count'] ?? 0 );
        $review_count = (int) ( $scan_state['review_count'] ?? 0 );
        $progress_known = ! empty( $scan_state['progress_known'] );
        $progress_percent = (int) ( $scan_state['progress_percent'] ?? 0 );
        $elapsed_seconds = max( 0, (int) ( $scan_state['elapsed_seconds'] ?? 0 ) );
        $eta_seconds = max( 0, (int) ( $scan_state['eta_seconds'] ?? 0 ) );
        $eta_known = ! empty( $scan_state['eta_known'] );
        $recent_paths = isset( $scan_state['recent_paths'] ) && is_array( $scan_state['recent_paths'] ) ? $scan_state['recent_paths'] : array();

        $status_labels = array(
            'idle'      => __( 'READY', 'yablonsky-security' ),
            'running'   => __( 'SCANNING', 'yablonsky-security' ),
            'paused'    => __( 'PAUSED', 'yablonsky-security' ),
            'failed'    => __( 'READY TO RESUME', 'yablonsky-security' ),
            'cancelled' => __( 'STOPPED', 'yablonsky-security' ),
            'completed' => __( 'COMPLETE', 'yablonsky-security' ),
        );
        $status_label = (string) ( $status_labels[ $scan_status ] ?? strtoupper( $scan_status ) );
        $status_class = 'completed' === $scan_status && 0 === $finding_count && $clamav_complete ? 'ysec-status-pass' : ( 'completed' === $scan_status ? 'ysec-status-attention' : 'ysec-status-neutral' );

        $json_url = wp_nonce_url( add_query_arg( array( 'action'=>'ysec_malware_export', 'format'=>'json' ), admin_url( 'admin-post.php' ) ), 'ysec_malware_export' );
        $csv_url = wp_nonce_url( add_query_arg( array( 'action'=>'ysec_malware_export', 'format'=>'csv' ), admin_url( 'admin-post.php' ) ), 'ysec_malware_export' );
        $forensic_zip_url = wp_nonce_url( add_query_arg( array( 'action'=>'ysec_malware_forensic_export' ), admin_url( 'admin-post.php' ) ), 'ysec_malware_forensic_export' );

        echo '<div class="ysec-context-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Malware', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'Local malware screening & quarantine', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Scan WordPress content with local deterministic checks and optional ClamAV signatures, then review findings and quarantine only the files you explicitly choose.', 'yablonsky-security' ) . '</p></div></div>';
        echo '<div class="ysec-policy-strip ysec-malware-engine-strip"><span class="ysec-status-badge ysec-status-pass">' . esc_html( (string) $engine['label'] ) . '</span><span>' . esc_html( sprintf( /* translators: 1: number of scanner rules, 2: scanner scope. */ __( '%1$d deterministic checks · scope: %2$s · real-time upload screening active.', 'yablonsky-security' ), (int) $engine['rule_count'], (string) $engine['scope'] ) ) . '</span><span class="ysec-malware-engine-clam ' . esc_attr( $clam_ready ? 'is-connected' : '' ) . '">' . esc_html( $clam_ready ? __( 'ClamAV connected', 'yablonsky-security' ) : __( 'ClamAV ready to connect', 'yablonsky-security' ) ) . '</span></div>';

        $install_command = "sudo apt update && sudo apt install -y clamav clamav-daemon";
        $signatures_command = "sudo systemctl stop clamav-freshclam\nsudo freshclam\nsudo systemctl enable --now clamav-freshclam";
        $verify_command = "sudo systemctl enable --now clamav-daemon.socket\nsudo systemctl restart clamav-daemon\nsudo clamdscan --ping 5:2\nsudo find /run /var/run -maxdepth 3 -type s -print 2>/dev/null | grep -Ei 'clam|clamd'";
        echo '<details id="ysec-clamav-server-setup" class="ysec-surface ysec-clamav-quick-setup"><summary><span><strong>' . esc_html__( 'ClamAV server setup · Debian / Ubuntu', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Optional local signature layer · install once per host', 'yablonsky-security' ) . '</small></span><span class="ysec-status-badge ' . esc_attr( $clam_ready ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $clam_ready ? __( 'CONNECTED', 'yablonsky-security' ) : __( 'SETUP', 'yablonsky-security' ) ) . '</span></summary><div class="ysec-clamav-quick-body">';
        echo '<p>' . esc_html__( 'A single local clamd service can serve multiple local WordPress sites on the same host when their PHP runtimes can reach its Unix socket. YSec does not require a mail server or an external malware API.', 'yablonsky-security' ) . '</p>';
        if ( $clam_ready ) echo '<p class="description"><strong>' . esc_html__( 'Detected socket:', 'yablonsky-security' ) . '</strong> <code>' . esc_html( (string) ( $engine['clamav_socket'] ?? '' ) ) . '</code></p>';
        echo '<div class="ysec-clamav-setup"><div class="ysec-command-block"><div><strong>' . esc_html__( '1. Install', 'yablonsky-security' ) . '</strong><button type="button" class="button button-small" data-ysec-copy-target="#ysec-clamav-install"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span> ' . esc_html__( 'Copy', 'yablonsky-security' ) . '</button></div><textarea id="ysec-clamav-install" readonly rows="2">' . esc_textarea( $install_command ) . '</textarea></div>';
        echo '<div class="ysec-command-block"><div><strong>' . esc_html__( '2. Signatures', 'yablonsky-security' ) . '</strong><button type="button" class="button button-small" data-ysec-copy-target="#ysec-clamav-signatures"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span> ' . esc_html__( 'Copy', 'yablonsky-security' ) . '</button></div><textarea id="ysec-clamav-signatures" readonly rows="4">' . esc_textarea( $signatures_command ) . '</textarea></div>';
        echo '<div class="ysec-command-block"><div><strong>' . esc_html__( '3. Start & verify', 'yablonsky-security' ) . '</strong><button type="button" class="button button-small" data-ysec-copy-target="#ysec-clamav-verify"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span> ' . esc_html__( 'Copy', 'yablonsky-security' ) . '</button></div><textarea id="ysec-clamav-verify" readonly rows="5">' . esc_textarea( $verify_command ) . '</textarea></div></div>';
        echo '<p class="description">' . esc_html__( 'After clamd answers PONG, reload this Malware tab. YSec detects the local Unix socket automatically and keeps deterministic heuristics active independently.', 'yablonsky-security' ) . '</p></div></details>';

        echo '<section class="ysec-surface ysec-surface-primary ysec-malware-full-scan" data-ysec-malware-scan data-status="' . esc_attr( $scan_status ) . '"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Malware scanner', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Scan wp-content', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'The scanner walks the complete wp-content scope in bounded resumable batches while the site remains responsive.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $status_class ) . '" data-ysec-malware-status>' . esc_html( $status_label ) . '</span></div>';

        echo '<div class="ysec-malware-metrics ysec-malware-metrics-5">';
        echo '<div class="ysec-malware-metric"><span>' . esc_html__( 'Files processed', 'yablonsky-security' ) . '</span><strong data-ysec-malware-files>' . esc_html( number_format_i18n( (int) ( $scan_state['files_processed'] ?? 0 ) ) ) . '</strong><small>' . esc_html__( 'complete scope traversal', 'yablonsky-security' ) . '</small></div>';
        echo '<div class="ysec-malware-metric"><span>' . esc_html__( 'Confirmed malware', 'yablonsky-security' ) . '</span><strong data-ysec-malware-confirmed>' . esc_html( number_format_i18n( $confirmed_count ) ) . '</strong><small>' . esc_html__( 'signature or deterministic exploit evidence', 'yablonsky-security' ) . '</small></div>';
        echo '<div class="ysec-malware-metric"><span>' . esc_html__( 'Review items', 'yablonsky-security' ) . '</span><strong data-ysec-malware-review-count>' . esc_html( number_format_i18n( $review_count ) ) . '</strong><small>' . esc_html__( 'suspicious context requiring origin review', 'yablonsky-security' ) . '</small></div>';
        echo '<div class="ysec-malware-metric"><span>' . esc_html__( 'ClamAV scanned', 'yablonsky-security' ) . '</span><strong data-ysec-malware-clam>' . esc_html( number_format_i18n( (int) ( $scan_state['clamav_scanned'] ?? 0 ) ) ) . '</strong><small>' . esc_html__( 'local signature checks', 'yablonsky-security' ) . '</small></div>';
        echo '<div class="ysec-malware-metric"><span>' . esc_html__( 'Directories pending', 'yablonsky-security' ) . '</span><strong data-ysec-malware-pending>' . esc_html( number_format_i18n( (int) ( $scan_state['pending_directories'] ?? 0 ) ) ) . '</strong><small>' . esc_html__( 'resumable traversal queue', 'yablonsky-security' ) . '</small></div>';
        echo '</div>';

        $progress_label = $progress_known ? sprintf( /* translators: %d: malware scan progress percentage. */ __( '%d%% of estimated scope', 'yablonsky-security' ), $progress_percent ) : __( 'Scanning full scope', 'yablonsky-security' );
        $show_timing = in_array( $scan_status, array( 'running', 'paused', 'failed', 'cancelled', 'completed' ), true ) && $elapsed_seconds > 0;
        $eta_label = $eta_known ? self::format_duration_compact( $eta_seconds ) : __( 'Estimating…', 'yablonsky-security' );
        echo '<div class="ysec-malware-workbench"><div class="ysec-malware-progress-head"><strong>' . esc_html__( 'Scan progress', 'yablonsky-security' ) . '</strong><div class="ysec-malware-progress-meta"><span data-ysec-malware-progress-label>' . esc_html( $progress_label ) . '</span><span class="ysec-malware-timing" data-ysec-malware-timing style="' . esc_attr( $show_timing ? '' : 'display:none' ) . '"><span>' . esc_html__( 'Elapsed', 'yablonsky-security' ) . '</span> <strong data-ysec-malware-elapsed>' . esc_html( self::format_duration_compact( $elapsed_seconds ) ) . '</strong><i aria-hidden="true">·</i><span data-ysec-malware-eta-label>' . esc_html__( 'Estimated remaining', 'yablonsky-security' ) . '</span> <strong data-ysec-malware-eta>' . esc_html( 'completed' === $scan_status ? '—' : $eta_label ) . '</strong></span></div></div>';
        echo '<div class="ysec-malware-progress-track ' . esc_attr( $progress_known ? '' : 'is-indeterminate' ) . '" data-ysec-malware-progress-track><i data-ysec-malware-progress-bar style="width:' . esc_attr( (string) $progress_percent ) . '%"></i></div>';
        echo '<div class="ysec-malware-activity-head"><strong>' . esc_html__( 'Current activity', 'yablonsky-security' ) . '</strong><span class="spinner ' . esc_attr( 'running' === $scan_status ? 'is-active' : '' ) . '" data-ysec-malware-spinner></span></div>';
        echo '<ol class="ysec-malware-recent" data-ysec-malware-recent>';
        if ( $recent_paths ) {
            foreach ( $recent_paths as $recent_path ) echo '<li><code title="' . esc_attr( (string) $recent_path ) . '">' . esc_html( (string) $recent_path ) . '</code></li>';
        } else {
            echo '<li class="is-empty">' . esc_html__( 'File activity will appear here while the scan is running.', 'yablonsky-security' ) . '</li>';
        }
        echo '</ol></div>';

        $summary_class = 'ysec-malware-outcome is-ready';
        $summary_text = __( 'Ready to scan the complete wp-content scope.', 'yablonsky-security' );
        if ( 'running' === $scan_status ) {
            $summary_class = 'ysec-malware-outcome is-running';
            $summary_text = __( 'Scan in progress. File activity and counters update continuously.', 'yablonsky-security' );
        } elseif ( 'paused' === $scan_status ) {
            $summary_class = 'ysec-malware-outcome is-paused';
            $summary_text = __( 'Scan paused. Progress is saved and ready to resume.', 'yablonsky-security' );
        } elseif ( 'cancelled' === $scan_status ) {
            $summary_class = 'ysec-malware-outcome is-paused';
            $summary_text = __( 'Scan stopped. Progress is preserved and ready to resume, or you can start a new scan.', 'yablonsky-security' );
        } elseif ( 'failed' === $scan_status ) {
            $summary_class = 'ysec-malware-outcome is-attention';
            $summary_text = __( 'Scan progress is preserved and ready to resume after review.', 'yablonsky-security' );
        } elseif ( 'completed' === $scan_status && $confirmed_count > 0 ) {
            $summary_class = 'ysec-malware-outcome is-attention';
            $summary_text = sprintf( /* translators: 1: confirmed malware count, 2: review-item count. */ __( 'Scan complete. %1$d confirmed malware item(s); %2$d additional item(s) need review.', 'yablonsky-security' ), $confirmed_count, $review_count );
        } elseif ( 'completed' === $scan_status && $review_count > 0 ) {
            $summary_class = 'ysec-malware-outcome is-attention';
            $summary_text = sprintf( /* translators: %d: review-item count. */ __( 'Scan complete. No signature-confirmed malware. %d item(s) need origin review.', 'yablonsky-security' ), $review_count );
        } elseif ( 'completed' === $scan_status && ! $clamav_complete ) {
            $summary_class = 'ysec-malware-outcome is-attention';
            $summary_text = __( 'Review required', 'yablonsky-security' );
        } elseif ( 'completed' === $scan_status ) {
            $summary_class = 'ysec-malware-outcome is-pass';
            $summary_text = __( 'Scan complete. wp-content is clear across the active scanner layers.', 'yablonsky-security' );
        }
        echo '<div class="' . esc_attr( $summary_class ) . '" data-ysec-malware-outcome><strong data-ysec-malware-outcome-title>' . esc_html( $summary_text ) . '</strong>';
        $scan_error = (string) ( $scan_state['last_error'] ?? '' );
        echo '<small class="ysec-malware-error" data-ysec-malware-error style="' . esc_attr( '' !== $scan_error ? '' : 'display:none' ) . '"><strong>' . esc_html__( 'Info', 'yablonsky-security' ) . ':</strong> <code>' . esc_html( $scan_error ) . '</code></small><div data-ysec-malware-preview>';
        if ( $finding_count > 0 && ! empty( $scan_state['findings_preview'] ) ) {
            echo '<ul>';
            foreach ( (array) $scan_state['findings_preview'] as $preview ) {
                $classification = (string) ( $preview['classification'] ?? 'review' );
                echo '<li><span class="ysec-badge ysec-badge-' . esc_attr( 'confirmed' === $classification ? 'high' : 'medium' ) . '">' . esc_html( strtoupper( $classification ) ) . '</span><code>' . esc_html( (string) ( $preview['path'] ?? '' ) ) . '</code><small>' . esc_html( (string) ( $preview['reason'] ?? '' ) ) . '</small></li>';
            }
            echo '</ul>';
        }
        echo '</div></div>';

        $show_start = ! in_array( $scan_status, array( 'running', 'paused' ), true );
        $show_pause = 'running' === $scan_status;
        $show_resume = in_array( $scan_status, array( 'paused', 'failed', 'cancelled' ), true );
        $show_stop = in_array( $scan_status, array( 'running', 'paused', 'failed' ), true );
        $start_label = 'completed' === $scan_status ? __( 'Scan again', 'yablonsky-security' ) : ( in_array( $scan_status, array( 'failed', 'cancelled' ), true ) ? __( 'Start new scan', 'yablonsky-security' ) : __( 'Scan wp-content', 'yablonsky-security' ) );
        echo '<div class="ysec-malware-toolbar"><div class="ysec-action-row ysec-malware-scan-actions">';
        echo '<button type="button" class="button button-primary ysec-malware-start" style="' . esc_attr( $show_start ? '' : 'display:none' ) . '">' . esc_html( $start_label ) . '</button>';
        echo '<button type="button" class="button ysec-malware-pause" style="' . esc_attr( $show_pause ? '' : 'display:none' ) . '">' . esc_html__( 'Pause', 'yablonsky-security' ) . '</button>';
        echo '<button type="button" class="button ysec-malware-resume" style="' . esc_attr( $show_resume ? '' : 'display:none' ) . '">' . esc_html__( 'Resume', 'yablonsky-security' ) . '</button>';
        echo '<button type="button" class="button ysec-malware-cancel" style="' . esc_attr( $show_stop ? '' : 'display:none' ) . '">' . esc_html__( 'Stop scan', 'yablonsky-security' ) . '</button>';
        echo '<a class="button ysec-malware-review" data-ysec-malware-review href="' . esc_url( admin_url( 'admin.php?page=yablonsky-security&tab=malware#ysec-malware-findings' ) ) . '" style="' . esc_attr( 'completed' === $scan_status && $finding_count > 0 ? '' : 'display:none' ) . '">' . esc_html__( 'Review findings', 'yablonsky-security' ) . '</a>';
        echo '</div><div class="ysec-action-row ysec-malware-report-actions" data-ysec-malware-report-actions style="' . esc_attr( $has_report_state ? '' : 'display:none' ) . '"><a class="button" href="' . esc_url( $json_url ) . '">' . esc_html__( 'Download scan JSON', 'yablonsky-security' ) . '</a><a class="button" href="' . esc_url( $csv_url ) . '">' . esc_html__( 'Download scan CSV', 'yablonsky-security' ) . '</a><a class="button ysec-malware-forensic-export" href="' . esc_url( $forensic_zip_url ) . '">' . esc_html__( 'Download forensic ZIP', 'yablonsky-security' ) . '</a></div></div>';
        echo '</section>';

        echo '<section id="ysec-malware-findings" class="ysec-malware-findings-surface">';
        YSEC_Admin_Tables::malware_result();
        echo '</section>';

        $ai_repair = YSEC_AI::malware_repair_readiness();
        $ai_repair_confirmed = (int) ( $ai_repair['confirmed_count'] ?? 0 );
        $ai_repair_ready = ! empty( $ai_repair['configured'] ) && ! empty( $ai_repair['account_verified'] ) && ! empty( $ai_repair['route_ready'] );
        echo '<section class="ysec-surface ysec-malware-ai-repair"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Yablonsky AI', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'AI malware guidance', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'AI suggests safe actions. It cannot install or run generated code.', 'yablonsky-security' ) . '</p></div></div>';
        echo '<div class="ysec-malware-metrics ysec-malware-metrics-3"><div class="ysec-malware-metric"><span>' . esc_html__( 'Confirmed malware', 'yablonsky-security' ) . '</span><strong>' . esc_html( number_format_i18n( $ai_repair_confirmed ) ) . '</strong></div><div class="ysec-malware-metric"><span>' . esc_html__( 'Repair authority', 'yablonsky-security' ) . '</span><strong class="ysec-malware-metric-text">' . esc_html__( 'Human', 'yablonsky-security' ) . '</strong></div><div class="ysec-malware-metric"><span>' . esc_html__( 'Live writes', 'yablonsky-security' ) . '</span><strong>0</strong></div></div>';
        if ( 0 === $ai_repair_confirmed ) {
            echo '<p class="description">' . esc_html__( 'No confirmed malware in the latest scan.', 'yablonsky-security' ) . '</p>';
        } elseif ( $ai_repair_ready ) {
            echo '<form method="post" class="ysec-action-row ysec-ai-repair-action">';
            wp_nonce_field( 'ysec_ai_repair_draft' );
            echo '<button class="button button-primary" name="ysec_ai_repair_draft" value="1" onclick="return confirm(this.dataset.confirm);" data-confirm="' . esc_attr__( 'Send limited malware metadata to Yablonsky AI? AI credits may apply. Files stay on your site.', 'yablonsky-security' ) . '">' . esc_html__( 'Get AI advice', 'yablonsky-security' ) . '</button></form>';
        } else {
            $ai_url = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'ai' ), admin_url( 'admin.php' ) );
            echo '<div class="ysec-action-row"><a class="button button-primary" href="' . esc_url( $ai_url ) . '">' . esc_html__( 'Connect Yablonsky AI', 'yablonsky-security' ) . '</a><span class="description">' . esc_html__( 'Local malware scanning, quarantine and forensic export remain fully available without AI.', 'yablonsky-security' ) . '</span></div>';
        }
        $advice_report = get_transient( 'ysec_ai_remediation_advice_v2_u' . get_current_user_id() );
        if ( is_array( $advice_report ) && ! empty( $advice_report['ok'] ) && ! empty( $advice_report['advice'] ) ) {
            echo '<div class="ysec-table-scroll ysec-bounded-record-list"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Path', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Action', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Verification', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
            $advice_actions = array(
                'quarantine' => __( 'Quarantine', 'yablonsky-security' ),
                'official_reinstall' => __( 'Reinstall from WordPress.org', 'yablonsky-security' ),
                'manual_review' => __( 'Manual review', 'yablonsky-security' ),
            );
            foreach ( array_slice( (array) $advice_report['advice'], 0, 3 ) as $item ) {
                $action = (string) ( $item['action'] ?? 'manual_review' );
                $action_label = $advice_actions[ $action ] ?? $advice_actions['manual_review'];
                echo '<tr><td><code>' . esc_html( (string) ( $item['path'] ?? '' ) ) . '</code></td><td>' . esc_html( $action_label ) . '</td><td>' . esc_html( (string) ( $item['summary'] ?? '' ) ) . '</td></tr>';
            }
            echo '</tbody></table></div>';
        }
        echo '<p class="description">' . esc_html__( 'Export evidence, quarantine affected files, or reinstall trusted packages in WordPress.', 'yablonsky-security' ) . '</p></section>';

        echo '<details class="ysec-surface ysec-malware-secondary"><summary><strong>' . esc_html__( 'Scanner details & upload protection', 'yablonsky-security' ) . '</strong> — ' . esc_html( $clam_ready ? __( 'ClamAV connected', 'yablonsky-security' ) : __( 'built-in protection active · ClamAV ready to connect', 'yablonsky-security' ) ) . '</summary><div class="ysec-malware-secondary-body">';
        echo '<section class="ysec-malware-provider"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Signature provider', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Local ClamAV / clamd', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'ClamAV complements deterministic checks with a local signature database. File content stays on this server, and clamd reads server-local files through its Unix socket.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $clam_ready ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $clam_ready ? __( 'CONNECTED', 'yablonsky-security' ) : __( 'READY TO CONNECT', 'yablonsky-security' ) ) . '</span></div>';
        if ( $clam_ready ) {
            echo '<p class="description"><strong>' . esc_html__( 'Socket:', 'yablonsky-security' ) . '</strong> <code>' . esc_html( (string) ( $engine['clamav_socket'] ?? '' ) ) . '</code> · ' . esc_html__( 'Server setup commands are available above the scanner.', 'yablonsky-security' ) . '</p>';
        } else {
            echo '<p class="description">' . esc_html__( 'Built-in heuristics and real-time ingress protection are active. Use the Debian / Ubuntu server setup above to add local ClamAV signatures.', 'yablonsky-security' ) . '</p>';
        }
        echo '</section>';

        echo '<section class="ysec-malware-ingress-receipt"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Real-time file ingress', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Latest upload security receipt', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Each WordPress upload is screened before normal placement. The latest local decision is shown here without adding clean uploads to the security-event stream.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( ! empty( $ingress ) && 'blocked' === (string) ( $ingress['decision'] ?? '' ) ? 'ysec-status-attention' : 'ysec-status-pass' ) . '">' . esc_html( ! empty( $ingress ) ? strtoupper( (string) ( $ingress['decision'] ?? 'ready' ) ) : __( 'READY', 'yablonsky-security' ) ) . '</span></div>';
        if ( $ingress ) {
            echo '<div class="ysec-malware-metrics ysec-malware-ingress-metrics"><div class="ysec-malware-metric"><span>' . esc_html__( 'File', 'yablonsky-security' ) . '</span><strong class="ysec-malware-metric-text">' . esc_html( (string) ( $ingress['file'] ?? '' ) ) . '</strong><small>' . esc_html( size_format( (int) ( $ingress['size'] ?? 0 ) ) ) . '</small></div><div class="ysec-malware-metric"><span>' . esc_html__( 'Decision', 'yablonsky-security' ) . '</span><strong class="ysec-malware-metric-text">' . esc_html( strtoupper( (string) ( $ingress['decision'] ?? '' ) ) ) . '</strong><small>' . esc_html( (string) ( $ingress['provider'] ?? '' ) ) . '</small></div><div class="ysec-malware-metric"><span>' . esc_html__( 'ClamAV', 'yablonsky-security' ) . '</span><strong class="ysec-malware-metric-text">' . esc_html( strtoupper( (string) ( $ingress['clamav_status'] ?? 'standby' ) ) ) . '</strong><small>' . esc_html( (string) ( $ingress['detail'] ?? '' ) ) . '</small></div><div class="ysec-malware-metric"><span>' . esc_html__( 'Checked', 'yablonsky-security' ) . '</span><strong class="ysec-malware-metric-text">' . esc_html( (string) ( $ingress['checked_at'] ?? '' ) ) . '</strong><small>' . esc_html( (string) ( $ingress['context'] ?? '' ) ) . '</small></div></div>';
        } else {
            echo '<p class="description">' . esc_html__( 'The next WordPress upload will create a local receipt here.', 'yablonsky-security' ) . '</p>';
        }
        echo '</section></div></details>';

        $items = array_values( YSEC_Quarantine::items() );
        $quarantine_page = isset( $_GET['quarantine_page'] ) ? max( 1, absint( wp_unslash( $_GET['quarantine_page'] ) ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only pagination.
        $quarantine_per_page = 25;
        $quarantine_pages = max( 1, (int) ceil( count( $items ) / $quarantine_per_page ) );
        $quarantine_page = min( $quarantine_page, $quarantine_pages );
        $quarantine_rows = array_slice( $items, ( $quarantine_page - 1 ) * $quarantine_per_page, $quarantine_per_page );
        echo '<div class="ysec-section-intro"><h3>' . esc_html__( 'Encrypted quarantine', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Quarantined payloads are encrypted locally and can be restored only after SHA-256 verification. Restore refuses to overwrite an existing path.', 'yablonsky-security' ) . '</p></div><div class="ysec-table-scroll ysec-bounded-record-list"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Path', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Detection', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'SHA-256 / size', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Integrity', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Quarantined', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Action', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $quarantine_rows as $item ) {
            $qid = (string) ( $item['id'] ?? '' );
            $verify = YSEC_Quarantine::verify_item( $qid );
            echo '<tr><td><code>' . esc_html( (string) ( $item['path'] ?? '' ) ) . '</code></td><td><strong>' . esc_html( (string) ( $item['rule'] ?? __( 'Reviewed finding', 'yablonsky-security' ) ) ) . '</strong><br><small>' . esc_html( (string) ( $item['reason'] ?? '' ) ) . '</small></td><td><code>' . esc_html( substr( (string) ( $item['sha256'] ?? '' ), 0, 20 ) ) . '…</code><br><small>' . esc_html( size_format( (int) ( $item['size'] ?? 0 ) ) ) . '</small></td><td><span class="ysec-badge ysec-badge-' . esc_attr( ! empty( $verify['ok'] ) ? 'low' : 'high' ) . '">' . esc_html( ! empty( $verify['ok'] ) ? __( 'Verified', 'yablonsky-security' ) : __( 'Failed', 'yablonsky-security' ) ) . '</span></td><td>' . esc_html( (string) ( $item['quarantined_at'] ?? '' ) ) . '</td><td><form method="post" class="ysec-inline-form">';
            wp_nonce_field( 'ysec_quarantine_' . $qid );
            echo '<input type="hidden" name="quarantine_id" value="' . esc_attr( $qid ) . '"><button class="button button-small" name="ysec_restore_quarantine" value="1">' . esc_html__( 'Restore', 'yablonsky-security' ) . '</button> <button class="button button-small button-link-delete" name="ysec_delete_quarantine" value="1" onclick="return confirm(this.dataset.confirm);" data-confirm="' . esc_attr__( 'Permanently delete this encrypted quarantine item?', 'yablonsky-security' ) . '">' . esc_html__( 'Delete permanently', 'yablonsky-security' ) . '</button></form></td></tr>';
        }
        if ( ! $items ) echo '<tr><td colspan="6" class="ysec-empty-cell">' . esc_html__( 'Quarantine is empty.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        self::bounded_page_nav( 'quarantine_page', $quarantine_page, $quarantine_pages, count( $items ) );
    }


    private static function bounded_page_nav( string $key, int $page, int $pages, int $total ): void {
        if ( $total <= 0 ) return;
        $from = ( $page - 1 ) * 25 + 1;
        $to = min( $total, $page * 25 );
        echo '<div class="ysec-bounded-page-nav"><span>' . esc_html( sprintf( /* translators: 1: first visible row, 2: last visible row, 3: total rows. */ __( 'Showing %1$d–%2$d of %3$d', 'yablonsky-security' ), $from, $to, $total ) ) . '</span><div>';
        if ( $page > 1 ) {
            $prev = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'malware', $key=>$page - 1 ), admin_url( 'admin.php' ) );
            echo '<a class="button button-small" href="' . esc_url( $prev ) . '">' . esc_html__( 'Previous', 'yablonsky-security' ) . '</a> ';
        }
        if ( $page < $pages ) {
            $next = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'malware', $key=>$page + 1 ), admin_url( 'admin.php' ) );
            echo '<a class="button button-small" href="' . esc_url( $next ) . '">' . esc_html__( 'Next', 'yablonsky-security' ) . '</a>';
        }
        echo '</div></div>';
    }

    public static function tab_comment_abuse(): void {
        $settings = YSEC_Utils::settings();
        $comment_guard = YSEC_Comment_Guard::summary();
        $guard_on = ! empty( $comment_guard['proof_enabled'] ) && ! empty( $comment_guard['honeypot_enabled'] );
        $spam_firewall_url = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'firewall', 'family'=>'spam_abuse' ), admin_url( 'admin.php' ) );
        $pending_comments_url = add_query_arg( array( 'comment_status'=>'moderated' ), admin_url( 'edit-comments.php' ) );
        $spam_comments_url = add_query_arg( array( 'comment_status'=>'spam' ), admin_url( 'edit-comments.php' ) );
        $xmlrpc_mode = (string) ( $settings['xmlrpc_mode'] ?? 'monitor' );
        $xmlrpc_label = 'disable' === $xmlrpc_mode ? __( 'Disable XML-RPC', 'yablonsky-security' ) : ( 'pingbacks' === $xmlrpc_mode ? __( 'Block pingbacks only', 'yablonsky-security' ) : __( 'Monitor / allow', 'yablonsky-security' ) );

        echo '<div class="ysec-context-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Comment abuse', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'Anonymous comment abuse protection', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'YSec rejects abusive direct submissions before WordPress creates a comment. Normal comments that reach Pending or the WordPress Spam queue remain WordPress moderation decisions, not YSec blocks.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $guard_on ? 'ysec-status-pass' : 'ysec-status-attention' ) . '">' . esc_html( $guard_on ? __( 'LOCAL GUARD ON', 'yablonsky-security' ) : __( 'REVIEW', 'yablonsky-security' ) ) . '</span></div>';

        echo '<div class="ysec-metrics ysec-metrics-4">';
        self::metric( __( 'Form proof', 'yablonsky-security' ), $comment_guard['proof_enabled'] ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ), __( 'Blocks unsourced direct POSTs', 'yablonsky-security' ), $comment_guard['proof_enabled'] ? 'pass' : 'attention' );
        self::metric( __( 'Honeypot', 'yablonsky-security' ), $comment_guard['honeypot_enabled'] ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ), __( 'Anonymous comment trap', 'yablonsky-security' ), $comment_guard['honeypot_enabled'] ? 'pass' : 'neutral' );
        self::metric( __( 'Rate policy', 'yablonsky-security' ), $comment_guard['rate_enabled'] ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ), $comment_guard['rate_enabled'] ? sprintf( /* translators: 1: comment count limit, 2: time window in minutes. */ __( '%1$d comments / %2$d min', 'yablonsky-security' ), $comment_guard['rate_limit'], $comment_guard['rate_window'] ) : __( 'Optional enforcement', 'yablonsky-security' ), $comment_guard['rate_enabled'] ? 'pass' : 'neutral' );
        self::metric( __( 'Blocks · 24h', 'yablonsky-security' ), number_format_i18n( $comment_guard['blocked_24h'] ), __( 'Proof + honeypot + rate', 'yablonsky-security' ), $comment_guard['blocked_24h'] ? 'attention' : 'neutral' );
        echo '</div>';

        echo '<section class="ysec-surface ysec-comment-abuse-console"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Protection settings', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Comment abuse policy', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Keep local form proof enabled for direct-POST protection. Honeypot and bounded source-rate enforcement are independent layers and can be tuned without an external account.', 'yablonsky-security' ) . '</p></div></div><form method="post" class="ysec-comment-abuse-form">';
        wp_nonce_field( 'ysec_comment_guard_settings' );
        echo '<div class="ysec-settings-subgroup"><div><strong>' . esc_html__( 'Public form protection', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Applies to anonymous WordPress comments and standard WooCommerce review forms using the native comment pipeline.', 'yablonsky-security' ) . '</small></div></div>';
        echo '<label class="ysec-toggle-row"><span><strong>' . esc_html__( 'Require local comment form proof', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Reject anonymous submissions sent directly to wp-comments-post.php unless they carry a valid cache-compatible proof rendered with the public comment form. REST, XML-RPC, WP-CLI and authenticated comments are not affected.', 'yablonsky-security' ) . '</small></span><span class="ysec-switch"><input type="checkbox" name="ysec_comment_guard[comment_form_proof]" value="1" ' . checked( ! empty( $settings['comment_form_proof'] ), true, false ) . '><i aria-hidden="true"></i></span></label>';
        echo '<label class="ysec-toggle-row"><span><strong>' . esc_html__( 'Anonymous comment honeypot', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Add an invisible field to public WordPress comment forms and reject automated submissions that fill it.', 'yablonsky-security' ) . '</small></span><span class="ysec-switch"><input type="checkbox" name="ysec_comment_guard[comment_honeypot]" value="1" ' . checked( ! empty( $settings['comment_honeypot'] ), true, false ) . '><i aria-hidden="true"></i></span></label>';
        echo '<label class="ysec-toggle-row"><span><strong>' . esc_html__( 'Anonymous comment rate enforcement', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Bound accepted public comment submissions by stable source identity without affecting logged-in users.', 'yablonsky-security' ) . '</small></span><span class="ysec-switch"><input type="checkbox" name="ysec_comment_guard[comment_rate_enforce]" value="1" ' . checked( ! empty( $settings['comment_rate_enforce'] ), true, false ) . '><i aria-hidden="true"></i></span></label>';
        echo '<div class="ysec-grid ysec-grid-2"><label class="ysec-field"><span>' . esc_html__( 'Comment source limit', 'yablonsky-security' ) . '</span><input type="number" min="3" max="100" name="ysec_comment_guard[comment_rate_limit]" value="' . esc_attr( (string) (int) $settings['comment_rate_limit'] ) . '"><small>' . esc_html__( 'comments', 'yablonsky-security' ) . '</small></label><label class="ysec-field"><span>' . esc_html__( 'Comment rate window', 'yablonsky-security' ) . '</span><input type="number" min="1" max="60" name="ysec_comment_guard[comment_rate_window]" value="' . esc_attr( (string) (int) $settings['comment_rate_window'] ) . '"><small>' . esc_html__( 'minutes', 'yablonsky-security' ) . '</small></label></div>';
        echo '<div class="ysec-settings-subgroup"><div><strong>' . esc_html__( 'XML-RPC / pingback policy', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Pingbacks do not use the browser comment-form proof. Control them explicitly through the XML-RPC policy instead of treating them as ordinary form submissions.', 'yablonsky-security' ) . '</small></div></div>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'XML-RPC policy', 'yablonsky-security' ) . '</span><select name="ysec_comment_guard[xmlrpc_mode]"><option value="monitor" ' . selected( $xmlrpc_mode, 'monitor', false ) . '>' . esc_html__( 'Monitor / allow', 'yablonsky-security' ) . '</option><option value="pingbacks" ' . selected( $xmlrpc_mode, 'pingbacks', false ) . '>' . esc_html__( 'Block pingbacks only', 'yablonsky-security' ) . '</option><option value="disable" ' . selected( $xmlrpc_mode, 'disable', false ) . '>' . esc_html__( 'Disable XML-RPC', 'yablonsky-security' ) . '</option></select><small>' . esc_html( $xmlrpc_label ) . '</small></label>';
        echo '<p class="ysec-action-row"><button class="button button-primary" name="ysec_save_comment_guard" value="1">' . esc_html__( 'Save protection settings', 'yablonsky-security' ) . '</button></p></form></section>';

        echo '<section class="ysec-surface"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Evidence', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Comment-abuse decisions', 'yablonsky-security' ) . '</h3><p>' . esc_html( sprintf( /* translators: 1: form-proof blocks, 2: honeypot blocks, 3: rate-limit blocks. */ __( '24h breakdown: form proof %1$d · honeypot %2$d · rate %3$d', 'yablonsky-security' ), $comment_guard['proof_blocks_24h'], $comment_guard['honeypot_24h'], $comment_guard['rate_limited_24h'] ) ) . '</p></div></div><div class="ysec-action-row"><a class="button button-primary" href="' . esc_url( $spam_firewall_url ) . '">' . esc_html__( 'Open spam-abuse enforcement', 'yablonsky-security' ) . '</a><a class="button" href="' . esc_url( $pending_comments_url ) . '">' . esc_html__( 'Open pending comments', 'yablonsky-security' ) . '</a><a class="button" href="' . esc_url( $spam_comments_url ) . '">' . esc_html__( 'Open WordPress spam queue', 'yablonsky-security' ) . '</a></div></section>';

        echo '<section class="ysec-surface"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Boundary', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'What the form proof does not intercept', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Authenticated comments, REST, XML-RPC and WP-CLI remain outside the browser form-proof boundary by design. Their authentication and abuse controls stay on their native security paths.', 'yablonsky-security' ) . '</p></div></div></section>';
    }

    private static function render_security_headers_control_plane(): void {
        $policy = YSEC_Security_Headers::policy();
        $summary = YSEC_Security_Headers::summary();
        $readiness = (array) ( $summary['readiness'] ?? array() );
        $discovery = YSEC_Security_Headers::discovery();
        $decisions = YSEC_Security_Headers::decisions();
        $catalog = YSEC_Security_Headers::known_services();
        $mode = (string) ( $policy['csp_mode'] ?? 'off' );
        $mode_label = 'enforce' === $mode ? __( 'ENFORCING', 'yablonsky-security' ) : ( 'report_only' === $mode ? __( 'REPORT-ONLY', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ) );
        $mode_class = 'enforce' === $mode ? 'ysec-status-pass' : ( 'report_only' === $mode ? 'ysec-status-attention' : 'ysec-status-neutral' );
        $settings_url = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'settings' ), admin_url( 'admin.php' ) );
        $export_url = wp_nonce_url( admin_url( 'admin-post.php?action=ysec_security_headers_export' ), 'ysec_security_headers_export' );
        $observed_services = array();
        foreach ( $discovery as $item ) {
            $service = YSEC_Security_Headers::classify_service( (string) ( $item['origin'] ?? '' ) );
            if ( '' !== $service ) $observed_services[ $service ] = true;
        }

        echo '<section class="ysec-surface ysec-security-headers" id="ysec-security-headers"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Security Headers', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Browser security policy control plane', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Build a site-specific Content Security Policy from known integrations, custom/self-hosted origins and local browser evidence. Observed sources are evidence, not trust: YSec never auto-authorizes an origin merely because it appeared on the site.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $mode_class ) . '">' . esc_html( $mode_label ) . '</span></div>';
        echo '<div class="ysec-metrics ysec-metrics-4">';
        self::metric( __( 'Baseline headers', 'yablonsky-security' ), ! empty( $summary['baseline_enabled'] ) ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ), __( 'nosniff · referrer · frame · permissions', 'yablonsky-security' ), ! empty( $summary['baseline_enabled'] ) ? 'pass' : 'neutral' );
        self::metric( __( 'CSP mode', 'yablonsky-security' ), $mode_label, 'report_only' === $mode ? __( 'Collecting violations without blocking', 'yablonsky-security' ) : ( 'enforce' === $mode ? __( 'Production browser enforcement', 'yablonsky-security' ) : __( 'No CSP header emitted', 'yablonsky-security' ) ), 'enforce' === $mode ? 'pass' : ( 'report_only' === $mode ? 'attention' : 'neutral' ) );
        self::metric( __( 'Observed sources', 'yablonsky-security' ), number_format_i18n( absint( $readiness['observed'] ?? 0 ) ), __( 'Bounded normalized origin/directive pairs', 'yablonsky-security' ), 'neutral' );
        self::metric( __( 'Unresolved', 'yablonsky-security' ), number_format_i18n( absint( $readiness['unresolved'] ?? 0 ) ), ! empty( $readiness['ready'] ) ? __( 'Ready for reviewed enforcement', 'yablonsky-security' ) : __( 'Needs allow, block or ignore decision', 'yablonsky-security' ), ! empty( $readiness['ready'] ) ? 'pass' : 'attention' );
        echo '</div>';
        echo '<div class="ysec-security-headers-flow"><strong>' . esc_html__( 'Safe workflow', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Discover → build proposal → Report-Only → review violations → human approval → Enforce → monitor drift', 'yablonsky-security' ) . '</span></div>';

        echo '<details class="ysec-security-headers-editor" open><summary><strong>' . esc_html__( 'CSP policy builder', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Guided presets + custom origins + advanced raw policy', 'yablonsky-security' ) . '</span></summary><div class="ysec-security-headers-editor-body"><form method="post">';
        wp_nonce_field( 'ysec_security_headers' );
        echo '<div class="ysec-grid ysec-grid-2"><label class="ysec-field"><span>' . esc_html__( 'CSP mode', 'yablonsky-security' ) . '</span><select name="ysec_headers[csp_mode]"><option value="off" ' . selected( $mode, 'off', false ) . '>' . esc_html__( 'Off — discovery only', 'yablonsky-security' ) . '</option><option value="report_only" ' . selected( $mode, 'report_only', false ) . '>' . esc_html__( 'Report-Only — observe without blocking', 'yablonsky-security' ) . '</option><option value="enforce" ' . selected( $mode, 'enforce', false ) . '>' . esc_html__( 'Enforce — block policy violations', 'yablonsky-security' ) . '</option></select><small>' . esc_html__( 'A new policy cannot jump directly from Off to Enforce. YSec first keeps it in Report-Only so real browser behavior can be reviewed.', 'yablonsky-security' ) . '</small></label>';
        echo '<div class="ysec-security-headers-note"><strong>' . esc_html__( 'Human-governed allowlist', 'yablonsky-security' ) . '</strong><p>' . esc_html__( 'Known-service detection is a recommendation layer only. Unknown custom and self-hosted domains remain first-class sources and can be added explicitly below.', 'yablonsky-security' ) . '</p></div></div>';

        echo '<div class="ysec-settings-subgroup"><div><strong>' . esc_html__( 'Known integration presets', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Select only services the site intentionally uses. Detection never checks a box automatically.', 'yablonsky-security' ) . '</small></div></div><div class="ysec-service-preset-grid">';
        foreach ( $catalog as $key => $service ) {
            $checked = in_array( $key, (array) ( $policy['csp_known_services'] ?? array() ), true );
            $detected = ! empty( $observed_services[ $key ] );
            echo '<label class="ysec-service-preset"><input type="checkbox" name="ysec_headers[csp_known_services][]" value="' . esc_attr( $key ) . '" ' . checked( $checked, true, false ) . '><span><strong>' . esc_html( (string) $service['label'] ) . '</strong><small>' . esc_html( $detected ? __( 'Detected on this site', 'yablonsky-security' ) : __( 'Preset available', 'yablonsky-security' ) ) . '</small></span></label>';
        }
        echo '</div>';

        echo '<label class="ysec-field ysec-csp-custom"><span>' . esc_html__( 'Custom / self-hosted sources', 'yablonsky-security' ) . '</span><textarea rows="6" name="ysec_headers[csp_custom_sources]" placeholder="connect-src https://api.example.com&#10;connect-src wss://chat.example.com&#10;frame-src https://support.example.com">' . esc_textarea( (string) ( $policy['csp_custom_sources'] ?? '' ) ) . '</textarea><small>' . esc_html__( 'One directive plus one or more origins per line. Exact origins and wildcard subdomains are accepted; paths and query strings are deliberately excluded.', 'yablonsky-security' ) . '</small></label>';
        $approved_sources = is_array( $policy['csp_approved_sources'] ?? null ) ? $policy['csp_approved_sources'] : array();
        if ( $approved_sources ) {
            echo '<div class="ysec-csp-approved"><strong>' . esc_html__( 'Approved discovery sources', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'These origins were explicitly approved from discovery evidence and are part of the guided policy even if evidence is later cleared.', 'yablonsky-security' ) . '</small><div class="ysec-csp-approved-list">';
            foreach ( $approved_sources as $approved_hash => $approved ) {
                if ( ! is_array( $approved ) ) continue;
                echo '<div><code>' . esc_html( (string) ( $approved['directive'] ?? '' ) . ' ' . (string) ( $approved['source'] ?? '' ) ) . '</code><form method="post">';
                wp_nonce_field( 'ysec_csp_approved_remove_' . $approved_hash );
                echo '<input type="hidden" name="csp_hash" value="' . esc_attr( (string) $approved_hash ) . '"><button class="button button-small" name="ysec_csp_approved_remove" value="1">' . esc_html__( 'Remove', 'yablonsky-security' ) . '</button></form></div>';
            }
            echo '</div></div>';
        }
        echo '<div class="ysec-csp-toggles">';
        self::headers_checkbox( 'csp_allow_inline_styles', __( 'Allow inline styles', 'yablonsky-security' ), __( 'Compatibility option. Weakens style-src but is commonly required by WordPress themes and plugins.', 'yablonsky-security' ), ! empty( $policy['csp_allow_inline_styles'] ) );
        self::headers_checkbox( 'csp_allow_inline_scripts', __( 'Allow inline scripts', 'yablonsky-security' ), __( 'High-impact compatibility option. Prefer resolving inline script violations before enabling this broadly.', 'yablonsky-security' ), ! empty( $policy['csp_allow_inline_scripts'] ) );
        self::headers_checkbox( 'csp_allow_eval', __( 'Allow unsafe-eval', 'yablonsky-security' ), __( 'Keep disabled unless a required application explicitly depends on evaluated JavaScript.', 'yablonsky-security' ), ! empty( $policy['csp_allow_eval'] ) );
        self::headers_checkbox( 'csp_upgrade_insecure', __( 'Upgrade insecure requests', 'yablonsky-security' ), __( 'Ask supporting browsers to upgrade HTTP subresources to HTTPS.', 'yablonsky-security' ), ! empty( $policy['csp_upgrade_insecure'] ) );
        echo '</div>';

        echo '<details class="ysec-csp-advanced"><summary><strong>' . esc_html__( 'Advanced CSP editor', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Exact raw policy for experienced administrators', 'yablonsky-security' ) . '</span></summary><div><label class="ysec-checkbox-line"><input type="checkbox" name="ysec_headers[csp_use_raw]" value="1" ' . checked( ! empty( $policy['csp_use_raw'] ), true, false ) . '><span>' . esc_html__( 'Use the raw policy below instead of the guided builder', 'yablonsky-security' ) . '</span></label><label class="ysec-field"><span>' . esc_html__( 'Raw Content-Security-Policy', 'yablonsky-security' ) . '</span><textarea rows="7" name="ysec_headers[csp_raw_policy]" spellcheck="false">' . esc_textarea( (string) ( $policy['csp_raw_policy'] ?? '' ) ) . '</textarea><small>' . esc_html__( 'YSec validates directive names, source expressions and header-injection boundaries before saving. The local report endpoint is appended when report-uri is absent.', 'yablonsky-security' ) . '</small></label></div></details>';

        echo '<details class="ysec-csp-advanced"><summary><strong>' . esc_html__( 'Transport security (HSTS)', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Separate from CSP and disabled by default', 'yablonsky-security' ) . '</span></summary><div class="ysec-grid ysec-grid-2">';
        self::headers_checkbox( 'hsts_enabled', __( 'Enable Strict-Transport-Security', 'yablonsky-security' ), __( 'Send HSTS only over HTTPS. Confirm the site and intended subdomains are permanently HTTPS-ready first.', 'yablonsky-security' ), ! empty( $policy['hsts_enabled'] ) );
        echo '<label class="ysec-field"><span>' . esc_html__( 'HSTS max-age', 'yablonsky-security' ) . '</span><input type="number" min="300" max="63072000" name="ysec_headers[hsts_max_age]" value="' . esc_attr( absint( $policy['hsts_max_age'] ?? 15552000 ) ) . '"><small>' . esc_html__( 'Seconds. Preload requires at least one year and includeSubDomains; YSec enforces those prerequisites automatically.', 'yablonsky-security' ) . '</small></label>';
        self::headers_checkbox( 'hsts_include_subdomains', __( 'Include subdomains', 'yablonsky-security' ), __( 'Apply HSTS to all subdomains. Do not enable if any required subdomain still needs plain HTTP.', 'yablonsky-security' ), ! empty( $policy['hsts_include_subdomains'] ) );
        self::headers_checkbox( 'hsts_preload', __( 'Preload-compatible directive', 'yablonsky-security' ), __( 'Adds preload and raises the policy to the technical preload prerequisites. Browser-list submission remains a separate administrator decision.', 'yablonsky-security' ), ! empty( $policy['hsts_preload'] ) );
        echo '</div></details>';

        echo '<div class="ysec-csp-preview"><strong>' . esc_html__( 'Current generated CSP', 'yablonsky-security' ) . '</strong><code>' . esc_html( (string) ( $summary['policy'] ?? '' ) ) . '</code></div>';
        echo '<label class="ysec-checkbox-line ysec-csp-enforce-confirm"><input type="checkbox" name="csp_enforce_confirm" value="1"><span><strong>' . esc_html__( 'I reviewed the Report-Only evidence and want enforcement when the policy is ready.', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'This approval is required each time Enforce is requested; it is not stored as a permanent bypass.', 'yablonsky-security' ) . '</small></span></label>';
        echo '<div class="ysec-security-headers-actions"><button class="button button-primary" name="ysec_save_security_headers" value="1">' . esc_html__( 'Save Security Headers policy', 'yablonsky-security' ) . '</button><a class="button" href="' . esc_url( $export_url ) . '">' . esc_html__( 'Download headers JSON', 'yablonsky-security' ) . '</a><a class="button" href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Baseline header toggle', 'yablonsky-security' ) . '</a></div></form></div></details>';

        $resolved = absint( $readiness['approved'] ?? 0 ) + absint( $readiness['blocked'] ?? 0 ) + absint( $readiness['ignored'] ?? 0 );
        /* translators: 1: observed CSP source count, 2: resolved source count, 3: unresolved source count. */
        $discovery_counts = sprintf( __( '%1$s observed · %2$s resolved · %3$s unresolved', 'yablonsky-security' ), number_format_i18n( count( $discovery ) ), number_format_i18n( $resolved ), number_format_i18n( absint( $readiness['unresolved'] ?? 0 ) ) );
        echo '<details class="ysec-security-headers-discovery"><summary><strong>' . esc_html__( 'CSP discovery & drift evidence', 'yablonsky-security' ) . '</strong><span>' . esc_html( $discovery_counts ) . '</span></summary><div class="ysec-security-headers-discovery-body">';
        echo '<p class="description">' . esc_html__( 'Runtime enqueue discovery and browser CSP reports store only bounded directive/origin evidence. Full URLs, query strings, request bodies and cookies are not retained here.', 'yablonsky-security' ) . '</p>';
        if ( $discovery ) {
            echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table ysec-csp-discovery-table"><thead><tr><th>' . esc_html__( 'Directive', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Origin', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Classification', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Evidence', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Decision', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
            foreach ( $discovery as $hash => $item ) {
                $service_key = YSEC_Security_Headers::classify_service( (string) ( $item['origin'] ?? '' ) );
                $service_label = $service_key && isset( $catalog[ $service_key ] ) ? (string) $catalog[ $service_key ]['label'] : __( 'Custom / unclassified', 'yablonsky-security' );
                $decision = sanitize_key( (string) ( $decisions[ $hash ] ?? '' ) );
                $decision_label = 'allow' === $decision ? __( 'Allowed', 'yablonsky-security' ) : ( 'block' === $decision ? __( 'Blocked', 'yablonsky-security' ) : ( 'ignore' === $decision ? __( 'Ignored', 'yablonsky-security' ) : __( 'Unresolved', 'yablonsky-security' ) ) );
                echo '<tr><td><code>' . esc_html( (string) ( $item['directive'] ?? '' ) ) . '</code></td><td><code>' . esc_html( (string) ( $item['origin'] ?? '' ) ) . '</code></td><td>' . esc_html( $service_label ) . '</td><td>' . esc_html( number_format_i18n( absint( $item['count'] ?? 0 ) ) ) . '<br><small>' . esc_html( (string) ( $item['last_seen'] ?? '' ) ) . '</small></td><td><strong>' . esc_html( $decision_label ) . '</strong><form method="post" class="ysec-csp-decision-form">';
                wp_nonce_field( 'ysec_csp_decision_' . $hash );
                echo '<input type="hidden" name="csp_hash" value="' . esc_attr( $hash ) . '"><input type="hidden" name="ysec_csp_discovery_action" value="1"><button class="button button-small" name="csp_decision" value="allow" type="submit">' . esc_html__( 'Allow', 'yablonsky-security' ) . '</button> <button class="button button-small" name="csp_decision" value="block" type="submit">' . esc_html__( 'Block', 'yablonsky-security' ) . '</button> <button class="button button-small" name="csp_decision" value="ignore" type="submit">' . esc_html__( 'Ignore', 'yablonsky-security' ) . '</button> <button class="button button-small" name="csp_decision" value="reset" type="submit">' . esc_html__( 'Reset', 'yablonsky-security' ) . '</button></form></td></tr>';
            }
            echo '</tbody></table></div>';
        } else {
            echo '<div class="ysec-empty-state"><strong>' . esc_html__( 'No external source evidence yet.', 'yablonsky-security' ) . '</strong><p>' . esc_html__( 'Browse normal public pages to collect WordPress-enqueued origins. Enable Report-Only to collect browser-level CSP violations before enforcement.', 'yablonsky-security' ) . '</p></div>';
        }
        echo '<form method="post" class="ysec-action-row ysec-csp-clear">'; wp_nonce_field( 'ysec_csp_discovery_clear' ); echo '<button class="button" name="ysec_csp_discovery_clear" value="1" onclick="return confirm(this.dataset.confirm);" data-confirm="' . esc_attr__( 'Clear CSP discovery evidence and all source decisions?', 'yablonsky-security' ) . '">' . esc_html__( 'Clear discovery evidence', 'yablonsky-security' ) . '</button></form></div></details></section>';
    }

    private static function headers_checkbox( string $name, string $label, string $description, bool $checked_value ): void {
        echo '<label class="ysec-toggle-row ysec-headers-toggle"><span><strong>' . esc_html( $label ) . '</strong><small>' . esc_html( $description ) . '</small></span><span class="ysec-switch"><input type="checkbox" name="ysec_headers[' . esc_attr( $name ) . ']" value="1" ' . checked( $checked_value, true, false ) . '><i aria-hidden="true"></i></span></label>';
    }

    public static function tab_hardening(): void {
        $findings = YSEC_Hardening::findings();
        $exposure = YSEC_Exposure::audit();
        $database = YSEC_Database_Safety::audit();
        $comment_guard = YSEC_Comment_Guard::summary();
        echo '<div class="ysec-context-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Hardening', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'WordPress hardening review', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Configuration findings are separated from attack evidence so recommendations stay precise and reversible.', 'yablonsky-security' ) . '</p></div></div><div class="ysec-surface"><ul class="ysec-findings">';
        foreach ( $findings as $finding ) {
            echo '<li><span class="ysec-badge ysec-badge-' . esc_attr( sanitize_key( $finding['severity'] ) ) . '">' . esc_html( ucfirst( $finding['severity'] ) ) . '</span><span>' . esc_html( $finding['message'] ) . '</span></li>';
        }
        if ( ! $findings ) {
            echo '<li>' . esc_html__( 'No basic hardening findings.', 'yablonsky-security' ) . '</li>';
        }
        echo '</ul></div>';
        self::render_security_headers_control_plane();
        $technology = YSEC_Technology_Exposure::status();
        $technology_label = 'off' === $technology['mode'] ? __( 'OFF', 'yablonsky-security' ) : ( 'extended' === $technology['mode'] ? __( 'EXTENDED', 'yablonsky-security' ) : __( 'SAFE', 'yablonsky-security' ) );
        echo '<section class="ysec-surface ysec-technology-exposure"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Technology exposure', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Passive fingerprint reduction', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Reduces explicit platform metadata without pretending that a public web application can become perfectly invisible to technology scanners.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( ! empty( $technology['enabled'] ) ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $technology_label ) . '</span></div><div class="ysec-metrics ysec-metrics-4">';
        self::metric( __( 'Version metadata', 'yablonsky-security' ), ! empty( $technology['enabled'] ) ? __( 'Reduced', 'yablonsky-security' ) : __( 'Visible', 'yablonsky-security' ), __( 'WordPress / WooCommerce version hints', 'yablonsky-security' ), ! empty( $technology['enabled'] ) ? 'pass' : 'neutral' );
        self::metric( __( 'Discovery headers', 'yablonsky-security' ), ! empty( $technology['enabled'] ) ? __( 'Reduced', 'yablonsky-security' ) : __( 'Standard', 'yablonsky-security' ), __( 'RSD / REST / shortlink hints', 'yablonsky-security' ), ! empty( $technology['enabled'] ) ? 'pass' : 'neutral' );
        self::metric( __( 'Asset version hints', 'yablonsky-security' ), ! empty( $technology['extended'] ) ? __( 'Reduced', 'yablonsky-security' ) : __( 'Preserved', 'yablonsky-security' ), __( 'Extended mode only', 'yablonsky-security' ), ! empty( $technology['extended'] ) ? 'pass' : 'neutral' );
        self::metric( __( 'Asset-path rewriting', 'yablonsky-security' ), __( 'OFF', 'yablonsky-security' ), __( 'Deliberately excluded from safe runtime', 'yablonsky-security' ), 'neutral' );
        echo '</div><p class="description">' . esc_html( (string) $technology['note'] ) . '</p></section>';
        if ( $exposure['attention'] ) {
            // translators: %d: number of findings needing attention.
            $exposure_badge = sprintf( __( '%d review', 'yablonsky-security' ), $exposure['attention'] );
        } else {
            $exposure_badge = __( 'CLEAR', 'yablonsky-security' );
        }
        echo '<section class="ysec-surface ysec-exposure-audit"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Exposure audit', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Sensitive artifacts & diagnostic leakage', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Read-only checks for common credential, backup and diagnostic artifacts in the WordPress document root. Findings require review; YSec does not delete files automatically.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $exposure['attention'] ? 'ysec-status-attention' : 'ysec-status-pass' ) . '">' . esc_html( $exposure_badge ) . '</span></div><div class="ysec-grid ysec-grid-2">';
        foreach ( $exposure['checks'] as $check ) {
            $needs = 'clear' !== ( $check['state'] ?? '' );
            echo '<div class="ysec-mini-card"><strong>' . esc_html( (string) $check['key'] ) . '</strong><span class="ysec-badge ysec-badge-' . esc_attr( $needs ? 'high' : 'low' ) . '">' . esc_html( $needs ? __( 'Review', 'yablonsky-security' ) : __( 'Clear', 'yablonsky-security' ) ) . '</span><p>' . esc_html( (string) $check['message'] ) . '</p></div>';
        }
        echo '</div></section>';
        echo '<section class="ysec-surface ysec-database-audit"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Database security', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Database & privileged-account safety review', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Read-only checks focus on meaningful exposure and privilege signals. YSec deliberately does not perform destructive live table-prefix rewrites.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $database['attention'] ? 'ysec-status-attention' : 'ysec-status-pass' ) . '">' . esc_html( $database['attention'] ? __( 'REVIEW', 'yablonsky-security' ) : __( 'CLEAR', 'yablonsky-security' ) ) . '</span></div><ul class="ysec-findings">';
        foreach ( $database['checks'] as $check ) {
            $needs = 'attention' === ( $check['state'] ?? '' );
            echo '<li><span class="ysec-badge ysec-badge-' . esc_attr( $needs ? 'medium' : 'info' ) . '">' . esc_html( $needs ? __( 'Review', 'yablonsky-security' ) : __( 'Info', 'yablonsky-security' ) ) . '</span><span>' . esc_html( (string) $check['message'] ) . '</span></li>';
        }
        echo '</ul></section>';
        $spam_firewall_url = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'firewall', 'family'=>'spam_abuse' ), admin_url( 'admin.php' ) );
        $guard_on = ! empty( $comment_guard['proof_enabled'] ) && ! empty( $comment_guard['honeypot_enabled'] );
        echo '<section class="ysec-surface ysec-comment-abuse"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Comment abuse', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Anonymous comment abuse protection', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'A cache-compatible local form proof rejects direct wp-comments-post.php automation that never rendered the site form. The existing honeypot and optional bounded source-rate policy add independent signals. No external account or reputation service is required.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $guard_on ? 'ysec-status-pass' : 'ysec-status-attention' ) . '">' . esc_html( $guard_on ? __( 'LOCAL GUARD ON', 'yablonsky-security' ) : __( 'REVIEW', 'yablonsky-security' ) ) . '</span></div><div class="ysec-metrics ysec-metrics-4">';
        self::metric( __( 'Form proof', 'yablonsky-security' ), $comment_guard['proof_enabled'] ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ), __( 'Blocks unsourced direct POSTs', 'yablonsky-security' ), $comment_guard['proof_enabled'] ? 'pass' : 'attention' );
        self::metric( __( 'Honeypot', 'yablonsky-security' ), $comment_guard['honeypot_enabled'] ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ), __( 'Anonymous comment trap', 'yablonsky-security' ), $comment_guard['honeypot_enabled'] ? 'pass' : 'neutral' );
        self::metric( __( 'Rate policy', 'yablonsky-security' ), $comment_guard['rate_enabled'] ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ), $comment_guard['rate_enabled'] ? sprintf( /* translators: 1: comment count limit, 2: time window in minutes. */ __( '%1$d comments / %2$d min', 'yablonsky-security' ), $comment_guard['rate_limit'], $comment_guard['rate_window'] ) : __( 'Optional enforcement', 'yablonsky-security' ), $comment_guard['rate_enabled'] ? 'pass' : 'neutral' );
        self::metric( __( 'Blocks · 24h', 'yablonsky-security' ), number_format_i18n( $comment_guard['blocked_24h'] ), __( 'Proof + honeypot + rate', 'yablonsky-security' ), $comment_guard['blocked_24h'] ? 'attention' : 'neutral' );
        $comment_abuse_url = add_query_arg( array( 'page'=>'yablonsky-security', 'tab'=>'comment_abuse' ), admin_url( 'admin.php' ) );
        echo '</div><div class="ysec-action-row ysec-comment-abuse-actions"><a class="button button-primary" href="' . esc_url( $comment_abuse_url ) . '">' . esc_html__( 'Manage comment protection', 'yablonsky-security' ) . '</a><a class="button" href="' . esc_url( $spam_firewall_url ) . '">' . esc_html__( 'Open spam-abuse enforcement', 'yablonsky-security' ) . '</a><span>' . esc_html( sprintf( /* translators: 1: form-proof blocks, 2: honeypot blocks, 3: rate-limit blocks. */ __( '24h breakdown: form proof %1$d · honeypot %2$d · rate %3$d', 'yablonsky-security' ), $comment_guard['proof_blocks_24h'], $comment_guard['honeypot_24h'], $comment_guard['rate_limited_24h'] ) ) . '</span></div></section>';
        $recovery_items = YSEC_Recovery::items();
        echo '<section class="ysec-surface ysec-recovery-card"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Recovery', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Encrypted YSec policy checkpoints', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Create a verified local rollback point for YSec-owned settings, firewall policy, Security Headers policy, conditional rules, virtual patches and integrity-review exclusions. This is intentionally not a full WordPress database backup.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-neutral">' . esc_html( sprintf( '%d / 5', count( $recovery_items ) ) ) . '</span></div><form method="post" class="ysec-action-row">';
        wp_nonce_field( 'ysec_recovery_create' );
        echo '<input type="text" name="ysec_recovery_label" maxlength="120" placeholder="' . esc_attr__( 'Before security policy change', 'yablonsky-security' ) . '"><button class="button button-primary" name="ysec_recovery_create" value="1">' . esc_html__( 'Create checkpoint', 'yablonsky-security' ) . '</button></form>';
        if ( $recovery_items ) {
            echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Checkpoint', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Created', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Integrity', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Action', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
            foreach ( $recovery_items as $item ) {
                $rid = (string) ( $item['id'] ?? '' ); $verify = YSEC_Recovery::verify( $rid );
                echo '<tr><td><strong>' . esc_html( (string) ( $item['label'] ?? '' ) ) . '</strong><br><code>' . esc_html( substr( (string) ( $item['sha256'] ?? '' ), 0, 16 ) ) . '…</code></td><td>' . esc_html( self::local_datetime( (string) ( $item['created_at'] ?? '' ) ) ) . '<br><small>v' . esc_html( (string) ( $item['plugin_version'] ?? '' ) ) . '</small></td><td><span class="ysec-badge ysec-badge-' . esc_attr( ! empty( $verify['ok'] ) ? 'low' : 'high' ) . '">' . esc_html( ! empty( $verify['ok'] ) ? __( 'Verified', 'yablonsky-security' ) : __( 'Failed', 'yablonsky-security' ) ) . '</span></td><td><form method="post" class="ysec-inline-form">'; wp_nonce_field( 'ysec_recovery_' . $rid ); echo '<input type="hidden" name="recovery_id" value="' . esc_attr( $rid ) . '"><button class="button button-small" name="ysec_recovery_restore" value="1">' . esc_html__( 'Restore', 'yablonsky-security' ) . '</button> <button class="button button-small button-link-delete" name="ysec_recovery_delete" value="1">' . esc_html__( 'Delete', 'yablonsky-security' ) . '</button></form></td></tr>';
            }
            echo '</tbody></table></div>';
        }
        echo '</section>';
        $lockdown = YSEC_Hardening::lockdown_active();
        $until = YSEC_Hardening::lockdown_until();
        echo '<section class="ysec-surface ysec-emergency-card"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Emergency response', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Visitor lockdown', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Temporarily return HTTP 503 to anonymous front-end visitors while keeping wp-admin, login, cron and REST administration paths available. The mode auto-expires.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . ( $lockdown ? 'ysec-status-attention' : 'ysec-status-neutral' ) . '">' . esc_html( $lockdown ? __( 'ACTIVE', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ) ) . '</span></div><form method="post" class="ysec-action-row">';
        wp_nonce_field( 'ysec_visitor_lockdown' );
        if ( $lockdown ) echo '<span>' . esc_html__( 'Auto-expires:', 'yablonsky-security' ) . ' <strong>' . esc_html( wp_date( 'Y-m-d H:i', $until ) ) . '</strong></span> <button class="button" name="ysec_lockdown_disable" value="1">' . esc_html__( 'Disable lockdown', 'yablonsky-security' ) . '</button>';
        else echo '<label>' . esc_html__( 'Duration', 'yablonsky-security' ) . ' <select name="lockdown_minutes"><option value="30">30 min</option><option value="60" selected>60 min</option><option value="240">4 h</option><option value="720">12 h</option></select></label> <button class="button button-primary" name="ysec_lockdown_enable" value="1" onclick="return confirm(this.dataset.confirm);" data-confirm="' . esc_attr__( 'Enable temporary visitor lockdown for anonymous front-end traffic?', 'yablonsky-security' ) . '">' . esc_html__( 'Enable visitor lockdown', 'yablonsky-security' ) . '</button>';
        echo '</form></section>';
    }

    public static function tab_ai(): void {
        $settings = YSEC_Utils::settings();
        $state = YSEC_AI::state();
        $configured = YSEC_AI::configured();
        $verified = ! empty( $state['connected'] );
        $catalog_stale = ! empty( $state['catalog_stale'] );
        $test = get_transient( 'ysec_last_ai_test' );
        $canary = get_transient( 'ysec_last_ai_canary' );
        $result = get_transient( 'ysec_last_ai' );
        $preview = array( 'event_count'=>0, 'integrity_changes'=>0, 'malware_findings'=>0 );
        $workspace_choices = self::ai_choices( $state['workspaces'] ?? array(), 'workspace' );
        if ( ! $workspace_choices && is_array( $state['workspace'] ?? null ) ) {
            $current_workspace_id = sanitize_text_field( (string) ( $state['workspace']['id'] ?? $state['workspace']['workspace_id'] ?? '' ) );
            if ( '' !== $current_workspace_id ) {
                $workspace_choices[ $current_workspace_id ] = self::ai_state_label( $state['workspace'], $current_workspace_id );
            }
        }
        $model_choices = self::ai_choices( $state['models'] ?? array(), 'model' );
        $workspace_value = (string) ( $settings['ai_workspace_id'] ?? '' );
        $model_value = (string) ( $settings['ai_model_id'] ?? '' );
        $workspace_label = '' !== $workspace_value ? ( $workspace_choices[ $workspace_value ] ?? $workspace_value ) : self::ai_state_label( $state['workspace'] ?? null, __( 'Auto', 'yablonsky-security' ) );
        $writer_default = is_array( $state['model_projection'] ?? null ) ? sanitize_text_field( (string) ( $state['model_projection']['writer_default'] ?? '' ) ) : '';
        $model_label = '' !== $model_value ? ( $model_choices[ $model_value ] ?? $model_value ) : ( '' !== $writer_default ? 'Auto · ' . $writer_default : __( 'Auto', 'yablonsky-security' ) );
        $model_count = count( $model_choices );
        $route_ready = '' !== $writer_default || $model_count > 0;
        $integration_ready = $verified && $route_ready;
        $canary_ok = ! empty( $state['model_canary_ok'] ) && (string) ( $state['model_canary_model'] ?? '' ) === ( '' !== $model_value ? $model_value : $writer_default );
        $catalog_status = ! $route_ready ? __( 'Unavailable', 'yablonsky-security' ) : ( $catalog_stale ? __( 'Last-known-good', 'yablonsky-security' ) : __( 'Current account projection', 'yablonsky-security' ) );
        list( $credit_value, $credit_meta ) = self::ai_credit_label( $state );

        echo '<div class="ysec-context-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Optional paid compute', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'Yablonsky AI Security Analyst', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Protection stays fully local and free. AI is used only when an administrator explicitly requests remote analysis of a bounded evidence bundle.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . ( $integration_ready ? 'ysec-status-pass' : ( $configured ? 'ysec-status-attention' : 'ysec-status-neutral' ) ) . '">' . esc_html( $integration_ready ? __( 'VERIFIED', 'yablonsky-security' ) : ( $verified ? __( 'ACCOUNT VERIFIED', 'yablonsky-security' ) : ( $configured ? __( 'CONFIGURED', 'yablonsky-security' ) : __( 'NOT CONNECTED', 'yablonsky-security' ) ) ) ) . '</span></div>';

        echo '<div class="ysec-ai-steps"><div class="ysec-ai-step ' . ( $configured ? 'is-complete' : 'is-current' ) . '"><b>1</b><div><strong>' . esc_html__( 'Connect account', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Save your Yablonsky AI User API key.', 'yablonsky-security' ) . '</span></div></div><div class="ysec-ai-step ' . ( $verified ? 'is-complete' : ( $configured ? 'is-current' : '' ) ) . '"><b>2</b><div><strong>' . esc_html__( 'Verify access', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Run an explicit bounded connection canary.', 'yablonsky-security' ) . '</span></div></div><div class="ysec-ai-step ' . ( $integration_ready ? 'is-current' : '' ) . '"><b>3</b><div><strong>' . esc_html__( 'Analyze evidence', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Choose scope, review the bundle, then request analysis.', 'yablonsky-security' ) . '</span></div></div></div>';

        echo '<div class="ysec-metrics ysec-metrics-4">';
        self::metric( __( 'Connection', 'yablonsky-security' ), $verified ? __( 'Verified', 'yablonsky-security' ) : ( $configured ? __( 'Configured', 'yablonsky-security' ) : __( 'Not connected', 'yablonsky-security' ) ), $configured ? YSEC_AI::key_hint() : __( 'No API key stored', 'yablonsky-security' ), $verified ? 'pass' : ( $configured ? 'attention' : 'neutral' ) );
        self::metric( __( 'Workspace', 'yablonsky-security' ), $workspace_label, $catalog_stale ? __( 'Last-known-good catalog', 'yablonsky-security' ) : __( 'Account-scoped', 'yablonsky-security' ), $catalog_stale ? 'attention' : 'neutral' );
        self::metric( __( 'Text model', 'yablonsky-security' ), $route_ready ? $model_label : __( 'Unavailable', 'yablonsky-security' ), ! $route_ready ? __( 'No usable text-model route was returned by the connected workspace.', 'yablonsky-security' ) : ( $catalog_stale ? __( 'Cached while catalog refresh is unavailable', 'yablonsky-security' ) : sprintf( /* translators: %d: number of account-scoped text models. */ __( '%d account-scoped text models', 'yablonsky-security' ), $model_count ) ), $canary_ok ? 'pass' : ( ! $route_ready || $catalog_stale ? 'attention' : 'neutral' ) );
        self::metric( __( 'Credits', 'yablonsky-security' ), $credit_value, $credit_meta, 'neutral' );
        echo '</div>';

        if ( is_array( $test ) ) {
            if ( ! empty( $test['error'] ) ) {
                echo '<div class="notice notice-error inline ysec-inline-notice"><p>' . esc_html( (string) $test['error'] ) . '</p></div>';
            } elseif ( ! empty( $test['ok'] ) ) {
                echo '<div class="notice notice-success inline ysec-inline-notice"><p>' . esc_html__( 'Yablonsky AI connection canary completed successfully.', 'yablonsky-security' ) . '</p></div>';
            }
        }

        if ( $verified && ! $route_ready ) {
            $stage = sanitize_key( (string) ( $state['error_stage'] ?? 'model_catalog' ) );
            $http_code = absint( $state['http_code'] ?? 0 );
            $diagnostic = $http_code ? strtoupper( $stage ) . ' · HTTP ' . $http_code : strtoupper( $stage );
            echo '<div class="notice notice-warning inline ysec-inline-notice"><p><strong>' . esc_html__( 'Account access is verified, but model routing is not ready.', 'yablonsky-security' ) . '</strong> ' . esc_html__( 'No Writer default or text-model catalog is available, so model canary and AI analysis are disabled until Refresh account returns a usable route.', 'yablonsky-security' ) . ' <code>' . esc_html( $diagnostic ) . '</code></p></div>';
        }

        if ( is_array( $canary ) ) {
            if ( ! empty( $canary['error'] ) ) {
                echo '<div class="notice notice-error inline ysec-inline-notice"><p>' . esc_html( (string) $canary['error'] ) . '</p></div>';
            } elseif ( ! empty( $canary['ok'] ) ) {
                echo '<div class="notice notice-success inline ysec-inline-notice"><p>' . esc_html__( 'Selected Yablonsky AI text model completed the live canary.', 'yablonsky-security' ) . '</p></div>';
            }
        }

        if ( $configured && ! empty( $state['last_success_at'] ) ) {
            $sync_meta = sprintf(
                /* translators: %s: timestamp of the last successful Yablonsky AI account refresh. */
                __( 'Last successful account sync: %s', 'yablonsky-security' ),
                (string) $state['last_success_at']
            );
            echo '<p class="description ysec-ai-sync-meta">' . esc_html( $sync_meta ) . ( $catalog_stale && $route_ready ? ' · ' . esc_html__( 'Current model/workspace catalog is retained from the last successful refresh.', 'yablonsky-security' ) : '' ) . '</p>';
        }

        echo '<div class="ysec-dashboard-grid ysec-ai-connect-grid"><section class="ysec-surface ysec-surface-primary"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Connection', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Yablonsky AI account', 'yablonsky-security' ) . '</h3></div><span class="ysec-status-badge ' . ( $configured ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $configured ? __( 'Key stored', 'yablonsky-security' ) : __( 'Optional', 'yablonsky-security' ) ) . '</span></div><p>' . esc_html__( 'The key is encrypted with this WordPress installation’s keys and is sent only to Yablonsky AI when you explicitly test or analyze.', 'yablonsky-security' ) . '</p>';
        echo '<form method="post" class="ysec-ai-account-form ysec-ai-axis-form">';
        wp_nonce_field( 'ysec_ai_account' );
        echo '<div class="ysec-ai-key-control"><label for="ysec-ai-api-key">' . esc_html__( 'User API key', 'yablonsky-security' ) . '</label><div class="ysec-ai-key-row"><input id="ysec-ai-api-key" type="password" name="ysec_ai_api_key" autocomplete="new-password" spellcheck="false" placeholder="' . esc_attr( $configured ? YSEC_AI::key_hint() . ' · ' . __( 'leave blank to keep', 'yablonsky-security' ) : __( 'Paste Yablonsky AI User API key', 'yablonsky-security' ) ) . '"><button class="button button-primary" name="ysec_ai_save" value="1">' . esc_html__( 'Save connection', 'yablonsky-security' ) . '</button></div><small>' . esc_html__( 'Saving the key does not make a remote request.', 'yablonsky-security' ) . '</small></div></form>';
        if ( $configured ) {
            echo '<div class="ysec-inline-actions"><form method="post">';
            wp_nonce_field( 'ysec_ai_test' );
            echo '<button class="button" name="ysec_ai_test" value="1">' . esc_html__( 'Refresh account', 'yablonsky-security' ) . '</button></form><form method="post">';
            wp_nonce_field( 'ysec_ai_canary' );
            echo '<button class="button" name="ysec_ai_canary" value="1" ' . disabled( ! $integration_ready, true, false ) . '>' . esc_html__( 'Run model canary', 'yablonsky-security' ) . '</button></form><form method="post">';
            wp_nonce_field( 'ysec_ai_disconnect' );
            echo '<button class="button button-link-delete" name="ysec_ai_disconnect" value="1">' . esc_html__( 'Disconnect', 'yablonsky-security' ) . '</button></form></div>';
        }
        echo '</section>';

        echo '<aside class="ysec-surface ysec-ai-privacy"><div class="ysec-lock-icon"><span class="dashicons dashicons-lock"></span></div><div><span class="ysec-eyebrow">' . esc_html__( 'Authority', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Local-first by default', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'No AI request occurs on activation, page load, firewall decisions, login protection, scanning, event logging or automatic blocking.', 'yablonsky-security' ) . '</p><div class="ysec-chip-row"><span class="ysec-chip">WAF</span><span class="ysec-chip">2FA</span><span class="ysec-chip">Integrity</span><span class="ysec-chip">Malware</span><span class="ysec-chip">Recon</span></div></div></aside></div>';

        echo '<section class="ysec-surface ysec-ai-routing"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Model routing', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Security analysis route', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Auto uses the authenticated workspace Writer model. The selector is populated from the account workspace capability projection; a transient refresh failure keeps the last-known-good catalog.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( ! $route_ready || $catalog_stale ? 'ysec-status-attention' : 'ysec-status-pass' ) . '">' . esc_html( $route_ready ? sprintf( /* translators: %d: number of text models currently available to the connected account. */ __( '%d text models', 'yablonsky-security' ), $model_count ) : __( 'MODEL ROUTE UNAVAILABLE', 'yablonsky-security' ) ) . '</span></div><form method="post" class="ysec-ai-routing-form">';
        wp_nonce_field( 'ysec_ai_account' );
        echo '<div class="ysec-ai-routing-grid"><label class="ysec-field"><span>' . esc_html__( 'Workspace', 'yablonsky-security' ) . '</span><select name="ysec_ai_workspace_id"><option value="">' . esc_html__( 'Current workspace · Auto', 'yablonsky-security' ) . '</option>';
        foreach ( $workspace_choices as $id => $label ) {
            echo '<option value="' . esc_attr( $id ) . '" ' . selected( $workspace_value, (string) $id, false ) . '>' . esc_html( $label ) . '</option>';
        }
        echo '</select></label><div class="ysec-field"><span>' . esc_html__( 'Text model', 'yablonsky-security' ) . '</span>';
        self::model_picker( $model_choices, $model_value, $route_ready );
        echo '<small>' . esc_html__( 'Search is instant inside the model catalog returned by your Yablonsky AI account.', 'yablonsky-security' ) . '</small></div><label class="ysec-field"><span>' . esc_html__( 'Reasoning effort', 'yablonsky-security' ) . '</span><select name="ysec_ai_reasoning">';
        foreach ( array( 'auto' => __( 'Auto', 'yablonsky-security' ), 'minimal' => __( 'Minimal', 'yablonsky-security' ), 'low' => __( 'Low', 'yablonsky-security' ), 'medium' => __( 'Medium', 'yablonsky-security' ), 'high' => __( 'High', 'yablonsky-security' ), 'xhigh' => __( 'Extra high', 'yablonsky-security' ), 'max' => __( 'Max', 'yablonsky-security' ) ) as $value => $label ) {
            echo '<option value="' . esc_attr( $value ) . '" ' . selected( (string) ( $settings['ai_reasoning'] ?? 'auto' ), $value, false ) . '>' . esc_html( $label ) . '</option>';
        }
        $selected_route_label = '' !== $model_value ? ( $model_choices[ $model_value ] ?? $model_value ) : __( 'Auto', 'yablonsky-security' );
        $effective_route = '' !== $model_value ? $model_value : $writer_default;
        echo '</select></label></div><button class="button" name="ysec_ai_save" value="1">' . esc_html__( 'Save routing', 'yablonsky-security' ) . '</button></form><dl class="ysec-kv-list ysec-ai-capability-evidence"><div><dt>' . esc_html__( 'Workspace Writer default (Auto)', 'yablonsky-security' ) . '</dt><dd><code>' . esc_html( '' !== $writer_default ? $writer_default : '—' ) . '</code></dd></div><div><dt>' . esc_html__( 'Saved route', 'yablonsky-security' ) . '</dt><dd><code>' . esc_html( $selected_route_label ) . '</code></dd></div><div><dt>' . esc_html__( 'Effective model', 'yablonsky-security' ) . '</dt><dd><code>' . esc_html( '' !== $effective_route ? $effective_route : '—' ) . '</code></dd></div><div><dt>' . esc_html__( 'Catalog status', 'yablonsky-security' ) . '</dt><dd>' . esc_html( $catalog_status ) . '</dd></div><div><dt>' . esc_html__( 'Compute canary', 'yablonsky-security' ) . '</dt><dd>' . esc_html( $canary_ok ? __( 'PASS for selected route', 'yablonsky-security' ) : ( $route_ready ? __( 'Not yet verified for selected route', 'yablonsky-security' ) : __( 'Unavailable until model routing is ready', 'yablonsky-security' ) ) ) . '</dd></div></dl></section>';

        echo '<section class="ysec-surface ysec-ai-analysis-builder"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Analysis', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Build a bounded evidence review', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Choose the question and scope. Yablonsky Security removes source fingerprints and redacts secret-like fields before transmission.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-neutral">' . esc_html__( 'Explicit request only', 'yablonsky-security' ) . '</span></div>';
        echo '<form method="post" class="ysec-ai-analyze-form" data-ysec-ai-preview-form>';
        wp_nonce_field( 'ysec_ai_analyze' );
        echo '<div class="ysec-ai-analysis-grid"><label class="ysec-field"><span>' . esc_html__( 'Analysis mode', 'yablonsky-security' ) . '</span><select name="ysec_ai_mode"><option value="full_review">' . esc_html__( 'Full security review', 'yablonsky-security' ) . '</option><option value="incident_triage">' . esc_html__( 'Incident triage', 'yablonsky-security' ) . '</option><option value="attack_campaigns">' . esc_html__( 'Attack campaign analysis', 'yablonsky-security' ) . '</option><option value="posture_review">' . esc_html__( 'Security posture review', 'yablonsky-security' ) . '</option><option value="remediation_plan">' . esc_html__( 'Prioritized remediation plan', 'yablonsky-security' ) . '</option></select></label>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'Evidence window', 'yablonsky-security' ) . '</span><select name="ysec_ai_window" data-ysec-ai-window><option value="1">' . esc_html__( 'Last hour', 'yablonsky-security' ) . '</option><option value="6">' . esc_html__( 'Last 6 hours', 'yablonsky-security' ) . '</option><option value="24" selected>' . esc_html__( 'Last 24 hours', 'yablonsky-security' ) . '</option><option value="72">' . esc_html__( 'Last 3 days', 'yablonsky-security' ) . '</option><option value="168">' . esc_html__( 'Last 7 days', 'yablonsky-security' ) . '</option></select></label>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'Maximum events', 'yablonsky-security' ) . '</span><select name="ysec_ai_event_limit" data-ysec-ai-limit><option value="25">25</option><option value="50">50</option><option value="100" selected>100</option></select></label></div>';
        echo '<div class="ysec-ai-evidence-options"><label><input type="checkbox" name="ysec_ai_include_environment" value="1" checked> ' . esc_html__( 'Environment', 'yablonsky-security' ) . '</label><label><input type="checkbox" name="ysec_ai_include_hardening" value="1" checked> ' . esc_html__( 'Hardening findings', 'yablonsky-security' ) . '</label><label><input type="checkbox" name="ysec_ai_include_integrity" value="1" checked> ' . esc_html__( 'Last integrity scan', 'yablonsky-security' ) . '</label><label><input type="checkbox" name="ysec_ai_include_malware" value="1" checked> ' . esc_html__( 'Last malware scan', 'yablonsky-security' ) . '</label><label><input type="checkbox" name="ysec_ai_include_software" value="1" checked> ' . esc_html__( 'Software exposure', 'yablonsky-security' ) . '</label></div>';
        echo '<div class="ysec-ai-preview"><div><span>' . esc_html__( 'Evidence preview', 'yablonsky-security' ) . '</span><strong><span data-ysec-ai-preview-events>' . esc_html( (string) $preview['event_count'] ) . '</span> ' . esc_html__( 'recent events ready', 'yablonsky-security' ) . '</strong></div><div><span>' . esc_html__( 'Local scan context', 'yablonsky-security' ) . '</span><strong><span data-ysec-ai-preview-integrity>' . esc_html( (string) $preview['integrity_changes'] ) . '</span> ' . esc_html__( 'integrity changes', 'yablonsky-security' ) . ' · <span data-ysec-ai-preview-malware>' . esc_html( (string) $preview['malware_findings'] ) . '</span> ' . esc_html__( 'malware findings', 'yablonsky-security' ) . '</strong></div><div><span>' . esc_html__( 'Privacy', 'yablonsky-security' ) . '</span><strong>' . esc_html__( 'Fingerprints removed · secrets redacted', 'yablonsky-security' ) . '</strong></div></div>';
        echo '<div class="ysec-ai-submit-row"><button class="button button-primary button-hero" name="ysec_ai_analyze" value="1" ' . disabled( ! $integration_ready, true, false ) . '>' . esc_html__( 'Analyze with Yablonsky AI', 'yablonsky-security' ) . '</button><span>' . esc_html__( 'This is the only step that sends the selected evidence to the external AI service and may consume AI credits.', 'yablonsky-security' ) . '</span></div></form></section>';

        if ( is_array( $result ) ) {
            self::render_ai_result( $result );
        }
    }

    public static function render_ai_result( array $data, bool $with_header = true ): void {
        if ( isset( $data['error'] ) ) {
            echo '<div class="notice notice-error inline ysec-inline-notice"><p>' . esc_html( (string) $data['error'] ) . '</p></div>';
            return;
        }
        $content = isset( $data['analysis'] ) && is_array( $data['analysis'] ) ? $data['analysis'] : $data;
        $preferred = array( 'why_this_matters', 'what_succeeded', 'what_was_blocked', 'next_safe_actions' );
        $ordered = array();
        foreach ( $preferred as $section_key ) if ( array_key_exists( $section_key, $content ) ) $ordered[$section_key] = $content[$section_key];
        foreach ( $content as $section_key => $section_value ) if ( ! array_key_exists( $section_key, $ordered ) ) $ordered[$section_key] = $section_value;
        $content = $ordered;
        $label_map = array(
            'why_this_matters' => __( 'Analysis', 'yablonsky-security' ),
            'what_succeeded' => __( 'Completed', 'yablonsky-security' ),
            'what_was_blocked' => __( 'Blocked', 'yablonsky-security' ),
            'next_safe_actions' => __( 'Review / repair', 'yablonsky-security' ),
            'summary' => __( 'Analysis', 'yablonsky-security' ),
        );
        if ( $with_header ) {
            echo '<section class="ysec-surface ysec-ai-result"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'AI result', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Security analysis', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'AI output is advisory. Apply security changes only after reviewing evidence and rollback impact.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-attention">' . esc_html__( 'Human review required', 'yablonsky-security' ) . '</span></div>';
        }
        echo '<div class="ysec-ai-result-grid">';
        foreach ( $content as $key => $value ) {
            $label = $label_map[ (string) $key ] ?? ucwords( str_replace( array( '_', '-' ), ' ', (string) $key ) );
            echo '<article class="ysec-ai-section"><h4>' . esc_html( $label ) . '</h4>';
            self::render_human_value( $value );
            echo '</article>';
        }
        echo '</div>';
        if ( $with_header ) echo '</section>';
    }

    public static function ai_context_history( string $surface, int $requested_page = 1 ): array {
        $empty = array( 'rows' => array(), 'total' => 0, 'page' => 1, 'pages' => 1, 'per_page' => 5 );
        if ( ! in_array( $surface, array( 'events', 'recon', 'firewall' ), true ) ) return $empty;
        $history = get_user_meta( get_current_user_id(), 'ysec_ai_context_history_v1', true );
        if ( ! is_array( $history ) ) return $empty;
        $rows = array_values( array_filter( $history, static fn( $row ) => is_array( $row ) && $surface === (string) ( $row['surface'] ?? '' ) ) );
        // Stable ordering for records generated within the same second.
        usort( $rows, static function( $a, $b ) {
            $delta = strcmp( (string) ( $b['created_at'] ?? '' ), (string) ( $a['created_at'] ?? '' ) );
            return $delta ?: strcmp( (string) ( $b['id'] ?? '' ), (string) ( $a['id'] ?? '' ) );
        } );
        $total = count( $rows );
        $pages = max( 1, (int) ceil( $total / 5 ) );
        $page = min( $pages, max( 1, $requested_page ) );
        return array( 'rows' => array_slice( $rows, ( $page - 1 ) * 5, 5 ), 'total' => $total, 'page' => $page, 'pages' => $pages, 'per_page' => 5 );
    }

    private static function store_ai_context_history( string $surface, string $mode, array $result ): void {
        $history = get_user_meta( get_current_user_id(), 'ysec_ai_context_history_v1', true );
        if ( ! is_array( $history ) ) $history = array();
        $history[] = array(
            'id' => wp_generate_uuid4(),
            'surface' => $surface,
            'mode' => $mode,
            'created_at' => current_time( 'mysql' ),
            'analysis' => isset( $result['analysis'] ) && is_array( $result['analysis'] ) ? YSEC_Utils::redact( $result['analysis'] ) : array(),
            'model' => sanitize_text_field( (string) ( $result['model'] ?? '' ) ),
            'workspace_id' => sanitize_text_field( (string) ( $result['workspace_id'] ?? '' ) ),
            'cost' => isset( $result['cost'] ) && is_numeric( $result['cost'] ) ? (float) $result['cost'] : null,
        );
        usort( $history, static fn( $a, $b ) => strcmp( (string) ( $b['created_at'] ?? '' ), (string) ( $a['created_at'] ?? '' ) ) );
        update_user_meta( get_current_user_id(), 'ysec_ai_context_history_v1', array_slice( $history, 0, 60 ) );
    }

    private static function analyze_once_per_user( array $request ) {
        $name = 'ysec_ai_analysis_lock_' . get_current_user_id();
        $now = time();
        // add_option has a unique database key: independent PHP workers cannot both acquire it.
        $acquired = add_option( $name, $now, '', false );
        if ( ! $acquired ) {
            $stamp = (int) get_option( $name, 0 );
            if ( $stamp > 0 && $stamp < $now - 300 ) {
                delete_option( $name );
                $acquired = add_option( $name, $now, '', false );
            }
        }
        if ( ! $acquired ) return new WP_Error( 'ysec_ai_analysis_busy', __( 'Processing…', 'yablonsky-security' ) );
        try {
            return YSEC_AI::analyze( $request );
        } finally {
            delete_option( $name );
        }
    }

    private static function delete_ai_context_history( string $surface, array $ids ): void {
        if ( ! $ids ) return;
        $selected = array_fill_keys( array_map( 'strval', $ids ), true );
        $history = get_user_meta( get_current_user_id(), 'ysec_ai_context_history_v1', true );
        if ( ! is_array( $history ) ) return;
        $history = array_values( array_filter( $history, static function( $row ) use ( $surface, $selected ) {
            if ( ! is_array( $row ) ) return false;
            return ! ( $surface === (string) ( $row['surface'] ?? '' ) && isset( $selected[ (string) ( $row['id'] ?? '' ) ] ) );
        } ) );
        update_user_meta( get_current_user_id(), 'ysec_ai_context_history_v1', array_slice( $history, 0, 60 ) );
    }

    private static function render_human_value( $value ): void {
        if ( is_scalar( $value ) || null === $value ) {
            echo '<p>' . esc_html( is_bool( $value ) ? ( $value ? __( 'Yes', 'yablonsky-security' ) : __( 'No', 'yablonsky-security' ) ) : (string) $value ) . '</p>';
            return;
        }
        if ( ! is_array( $value ) ) {
            echo '<p>' . esc_html( (string) $value ) . '</p>';
            return;
        }
        if ( YSEC_Utils::is_list_array( $value ) ) {
            echo '<ul class="ysec-human-list">';
            foreach ( $value as $item ) {
                echo '<li>';
                self::render_human_value( $item );
                echo '</li>';
            }
            echo '</ul>';
            return;
        }
        echo '<dl class="ysec-kv">';
        foreach ( $value as $key => $item ) {
            echo '<dt>' . esc_html( ucwords( str_replace( array( '_', '-' ), ' ', (string) $key ) ) ) . '</dt><dd>';
            self::render_human_value( $item );
            echo '</dd>';
        }
        echo '</dl>';
    }

    public static function tab_settings(): void {
        $settings = YSEC_Utils::settings();
        $ai_url = add_query_arg( array( 'page' => 'yablonsky-security', 'tab' => 'ai' ), admin_url( 'admin.php' ) );
        $accounts_url = add_query_arg( array( 'page' => 'yablonsky-security', 'tab' => 'accounts' ), admin_url( 'admin.php' ) );
        $export_url = wp_nonce_url( add_query_arg( array( 'action'=>'ysec_policy_export' ), admin_url( 'admin-post.php' ) ), 'ysec_policy_export' );
        $doctor = YSEC_Doctor::report();

        echo '<div class="ysec-context-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Settings', 'yablonsky-security' ) . '</span><h2>' . esc_html__( 'Protection settings', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Manual controls are grouped by outcome. Autopilot remains the recommended path for most sites; these controls are for deliberate customization.', 'yablonsky-security' ) . '</p></div></div>';
        echo '<form method="post" class="ysec-settings-form ysec-settings-form-v2">';
        wp_nonce_field( 'ysec_settings' );
        echo '<div class="ysec-settings-savebar"><div><strong>' . esc_html__( 'Protection settings', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Choose a settings group, adjust it, then save once. Portability remains a separate operation.', 'yablonsky-security' ) . '</span></div><button class="button button-primary" name="ysec_save_settings" value="1">' . esc_html__( 'Save protection settings', 'yablonsky-security' ) . '</button></div>';
        echo '<div class="ysec-settings-section-nav" role="tablist" aria-label="' . esc_attr__( 'Protection settings groups', 'yablonsky-security' ) . '">';
        $settings_tabs = array(
            'traffic'   => __( 'Traffic', 'yablonsky-security' ),
            'accounts'  => __( 'Accounts', 'yablonsky-security' ),
            'hardening' => __( 'Hardening', 'yablonsky-security' ),
            'network'   => __( 'Network', 'yablonsky-security' ),
            'data'      => __( 'Data', 'yablonsky-security' ),
            'alerts'    => __( 'Alerts', 'yablonsky-security' ),
            'ai'        => __( 'AI / Expert', 'yablonsky-security' ),
        );
        foreach ( $settings_tabs as $settings_tab_key => $settings_tab_label ) {
            $is_active = 'traffic' === $settings_tab_key;
            echo '<button type="button" class="ysec-settings-section-tab' . ( $is_active ? ' is-active' : '' ) . '" role="tab" id="ysec-settings-tab-' . esc_attr( $settings_tab_key ) . '" aria-controls="ysec-settings-panel-' . esc_attr( $settings_tab_key ) . '" aria-selected="' . ( $is_active ? 'true' : 'false' ) . '" tabindex="' . ( $is_active ? '0' : '-1' ) . '" data-ysec-settings-tab="' . esc_attr( $settings_tab_key ) . '">' . esc_html( $settings_tab_label ) . '</button>';
        }
        echo '</div>';
        echo '<div class="ysec-settings-panels">';

        echo '<section class="ysec-surface ysec-settings-card ysec-settings-panel" id="ysec-settings-panel-traffic" role="tabpanel" aria-labelledby="ysec-settings-tab-traffic" data-ysec-settings-panel="traffic"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Traffic', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Observation & firewall', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Control what YSec observes, denies and contains at the application layer.', 'yablonsky-security' ) . '</p></div></div>';
        self::toggle( 'observe_requests', __( 'Observe security-relevant requests', 'yablonsky-security' ), __( 'Collect bounded evidence for suspicious request patterns.', 'yablonsky-security' ), $settings );
        self::toggle( 'extended_telemetry', __( 'Extended request evidence', 'yablonsky-security' ), __( 'Also retain benign technical and content 404 observations. Standard mode stores suspicious and WAF evidence only.', 'yablonsky-security' ), $settings );
        self::toggle( 'waf_enabled', __( 'Application firewall', 'yablonsky-security' ), __( 'Block high-confidence exploit patterns at the WordPress application layer.', 'yablonsky-security' ), $settings );
        echo '<label class="ysec-field"><span>' . esc_html__( 'Firewall strength', 'yablonsky-security' ) . '</span><select name="ysec[firewall_profile]">';
        foreach ( YSEC_Firewall_Profiles::profiles() as $key=>$profile ) echo '<option value="' . esc_attr( $key ) . '" ' . selected( $settings['firewall_profile'], $key, false ) . '>' . esc_html( $profile['label'] ) . '</option>';
        echo '</select><small>' . esc_html__( 'Clean-room Yablonsky profiles using familiar 5G–8G-class naming; no third-party firewall code is copied.', 'yablonsky-security' ) . '</small></label>';
        echo '<div class="ysec-settings-subgroup"><div><strong>' . esc_html__( 'Application-resource abuse intelligence', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Classify expensive faceted crawl and state-changing GET patterns before the main WordPress query. Evidence is bounded and query values are never retained.', 'yablonsky-security' ) . '</small></div></div>';
        self::toggle( 'l7_abuse_observe', __( 'Observe L7 application-resource abuse', 'yablonsky-security' ), __( 'Recognize add-to-cart, wishlist, compare and faceted-query families and publish a sanitized request-intent signal for origin-cost correlation.', 'yablonsky-security' ), $settings );
        self::toggle( 'l7_state_action_enforce', __( 'Rate-limit abusive state-changing GET requests', 'yablonsky-security' ), __( 'When a persistent object cache is available, deny anonymous add-to-cart, wishlist and compare GET requests only after one source crosses the bounded threshold. Faceted crawl remains observe-only for YPerf/YSEO coordination.', 'yablonsky-security' ), $settings );
        self::compact_number( 'l7_state_action_threshold', __( 'State-action source threshold', 'yablonsky-security' ), __( 'requests / window', 'yablonsky-security' ), $settings );
        self::compact_number( 'l7_abuse_window_seconds', __( 'L7 abuse window', 'yablonsky-security' ), __( 'seconds', 'yablonsky-security' ), $settings );
        self::toggle( 'adaptive_404_shield', __( 'Adaptive reconnaissance shield', 'yablonsky-security' ), __( 'Correlate many distinct suspicious paths from one source and contain the scanner when guarded automatic response is enabled.', 'yablonsky-security' ), $settings );
        self::compact_number( 'adaptive_recon_threshold', __( 'Adaptive path threshold', 'yablonsky-security' ), __( 'distinct paths', 'yablonsky-security' ), $settings );
        self::compact_number( 'adaptive_recon_window', __( 'Adaptive window', 'yablonsky-security' ), __( 'minutes', 'yablonsky-security' ), $settings );
        self::toggle( 'suspicious_rate_enforce', __( 'Suspicious scanner rate enforcement', 'yablonsky-security' ), __( 'Count only high-confidence probe/attack signals and deny a source only after it crosses the bounded threshold.', 'yablonsky-security' ), $settings );
        self::compact_number( 'suspicious_rate_threshold', __( 'Suspicious probe threshold', 'yablonsky-security' ), __( 'requests', 'yablonsky-security' ), $settings );
        self::compact_number( 'suspicious_rate_window', __( 'Suspicious rate window', 'yablonsky-security' ), __( 'minutes', 'yablonsky-security' ), $settings );
        self::toggle( 'auto_block', __( 'Smart adaptive response', 'yablonsky-security' ), __( 'Escalate only after sustained high-confidence harmful behavior. Single malicious requests are denied without automatically banning the whole IP.', 'yablonsky-security' ), $settings );
        self::toggle( 'preserve_public_discovery', __( 'Preserve safe public discovery during containment', 'yablonsky-security' ), __( 'Keep read-only public content available while risky login, write and privileged surfaces remain restricted. Designed for SEO, GEO and AEO discoverability.', 'yablonsky-security' ), $settings );
        self::compact_number( 'smart_response_window', __( 'Behavior window', 'yablonsky-security' ), __( 'minutes', 'yablonsky-security' ), $settings );
        self::compact_number( 'smart_containment_score', __( 'Threat pressure threshold', 'yablonsky-security' ), __( 'points', 'yablonsky-security' ), $settings );
        self::compact_number( 'smart_containment_families', __( 'Distinct family threshold', 'yablonsky-security' ), __( 'families', 'yablonsky-security' ), $settings );
        self::compact_number( 'smart_containment_attack_hits', __( 'Direct attack threshold', 'yablonsky-security' ), __( 'attacks', 'yablonsky-security' ), $settings );
        self::compact_number( 'block_minutes', __( 'Scoped containment duration', 'yablonsky-security' ), __( 'minutes', 'yablonsky-security' ), $settings );
        self::compact_number( 'recon_block_threshold', __( 'Recon behavior threshold', 'yablonsky-security' ), __( 'requests', 'yablonsky-security' ), $settings );
        self::compact_number( 'recon_block_window', __( 'Recon threshold window', 'yablonsky-security' ), __( 'minutes', 'yablonsky-security' ), $settings );
        self::compact_number( 'campaign_family_threshold', __( 'Multi-family threshold', 'yablonsky-security' ), __( 'families', 'yablonsky-security' ), $settings );
        self::compact_number( 'campaign_hit_threshold', __( 'Campaign hit threshold', 'yablonsky-security' ), __( 'requests', 'yablonsky-security' ), $settings );
        echo '</section>';

        echo '<section class="ysec-surface ysec-settings-card ysec-settings-panel" id="ysec-settings-panel-accounts" role="tabpanel" aria-labelledby="ysec-settings-tab-accounts" data-ysec-settings-panel="accounts" hidden><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Accounts', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Login protection', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Rate limiting, human verification and public-account exposure controls.', 'yablonsky-security' ) . '</p></div></div>';
        self::compact_number( 'login_limit', __( 'Attempt limit', 'yablonsky-security' ), __( 'attempts', 'yablonsky-security' ), $settings );
        self::compact_number( 'login_window', __( 'Login window', 'yablonsky-security' ), __( 'minutes', 'yablonsky-security' ), $settings );
        $private_entry = YSEC_Private_Login::status();
        $private_state = (string) ( $private_entry['state'] ?? 'off' );
        $private_badge = 'active' === $private_state ? 'ysec-status-pass' : ( in_array( $private_state, array( 'standby','test' ), true ) ? 'ysec-status-attention' : 'ysec-status-neutral' );
        $private_label = 'active' === $private_state ? __( 'ENFORCING', 'yablonsky-security' ) : ( 'test' === $private_state ? __( 'TEST MODE', 'yablonsky-security' ) : ( 'standby' === $private_state ? __( 'PATH OWNER CONFLICT', 'yablonsky-security' ) : ( 'permalink_required' === $private_state ? __( 'PERMALINKS REQUIRED', 'yablonsky-security' ) : ( 'recovery_disabled' === $private_state ? __( 'RECOVERY DISABLED', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ) ) ) ) );
        echo '<div class="ysec-private-entry"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Private entry', 'yablonsky-security' ) . '</span><h4>' . esc_html__( 'Private WordPress core login', 'yablonsky-security' ) . '</h4><p>' . esc_html__( 'The secret alias serves WordPress login under the alias itself. TEST mode keeps the standard entry available while you verify the secret URL; ENFORCE mode hides normal unauthenticated wp-login.php/wp-admin entry. WooCommerce My Account stays public.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $private_badge ) . '">' . esc_html( $private_label ) . '</span></div>';
        $private_mode = YSEC_Private_Login::mode();
        echo '<label class="ysec-field"><span>' . esc_html__( 'Private entry mode', 'yablonsky-security' ) . '</span><select name="ysec[private_login_mode]"><option value="off" ' . selected( $private_mode, 'off', false ) . '>' . esc_html__( 'Off — standard WordPress entry only', 'yablonsky-security' ) . '</option><option value="test" ' . selected( $private_mode, 'test', false ) . '>' . esc_html__( 'Test — secret and standard entry both work', 'yablonsky-security' ) . '</option><option value="enforce" ' . selected( $private_mode, 'enforce', false ) . '>' . esc_html__( 'Enforce — secret entry only for unauthenticated core login/admin', 'yablonsky-security' ) . '</option></select><small>' . esc_html__( 'Recommended cutover: Test → verify in another browser/incognito → Enforce. Existing 2.18 private-entry settings upgrade to Test, never directly to lockout-capable enforcement.', 'yablonsky-security' ) . '</small></label>';
        echo '<div class="ysec-grid ysec-grid-2"><label class="ysec-field"><span>' . esc_html__( 'Secret core-login slug', 'yablonsky-security' ) . '</span><input type="text" name="ysec[private_login_slug]" value="' . esc_attr( (string) ( $settings['private_login_slug'] ?? '' ) ) . '" placeholder="gate-random-private-entry"><small>' . esc_html__( 'Canonical secret WordPress login entry. Leave blank when enabling to generate a strong random slug.', 'yablonsky-security' ) . '</small></label><label class="ysec-field"><span>' . esc_html__( 'Optional administrator shortcut', 'yablonsky-security' ) . '</span><input type="text" name="ysec[private_admin_slug]" value="' . esc_attr( (string) ( $settings['private_admin_slug'] ?? '' ) ) . '" placeholder="optional"><small>' . esc_html__( 'Optional convenience alias. Signed-out visitors see the same secret login with redirect-to-admin prepared; signed-in administrators go to native /wp-admin/. Leave blank if one secret URL is enough.', 'yablonsky-security' ) . '</small></label></div>';
        if ( ! empty( $private_entry['configured'] ) ) {
            echo '<div class="ysec-private-entry-urls"><div><span>' . esc_html__( 'Canonical secret login URL', 'yablonsky-security' ) . '</span><div class="ysec-copy-code"><code id="ysec-private-login-url">' . esc_html( (string) ( $private_entry['login_url'] ?? '' ) ) . '</code><button type="button" class="button ysec-copy-icon" data-ysec-copy-target="#ysec-private-login-url" aria-label="' . esc_attr__( 'Copy secret login URL', 'yablonsky-security' ) . '" title="' . esc_attr__( 'Copy', 'yablonsky-security' ) . '"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span><span class="screen-reader-text">' . esc_html__( 'Copy', 'yablonsky-security' ) . '</span></button></div></div>';
            if ( ! empty( $private_entry['admin_url'] ) ) echo '<div><span>' . esc_html__( 'Optional admin shortcut', 'yablonsky-security' ) . '</span><div class="ysec-copy-code"><code id="ysec-private-admin-url">' . esc_html( (string) $private_entry['admin_url'] ) . '</code><button type="button" class="button ysec-copy-icon" data-ysec-copy-target="#ysec-private-admin-url" aria-label="' . esc_attr__( 'Copy administrator shortcut URL', 'yablonsky-security' ) . '" title="' . esc_attr__( 'Copy', 'yablonsky-security' ) . '"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span><span class="screen-reader-text">' . esc_html__( 'Copy', 'yablonsky-security' ) . '</span></button></div></div>';
            echo '</div>';
        }
        if ( 'standby' === $private_state ) echo '<div class="notice notice-warning inline ysec-inline-notice"><p>' . esc_html__( 'Another login-path owner (Hide My WP Ghost) is active, so YSec does not claim the private aliases. Deactivate that owner first, keep YSec in Test mode, verify the secret alias, then switch YSec to Enforce.', 'yablonsky-security' ) . '</p></div>';
        if ( 'test' === $private_state ) echo '<div class="notice notice-info inline ysec-inline-notice"><p>' . esc_html__( 'Test mode: the secret alias is active, but standard wp-login.php/wp-admin entry remains available intentionally. Verify the secret alias in a separate browser/incognito window before selecting Enforce.', 'yablonsky-security' ) . '</p></div>';
        if ( 'active' === $private_state ) echo '<div class="notice notice-success inline ysec-inline-notice"><p>' . esc_html__( 'Enforce mode: normal unauthenticated wp-login.php/wp-admin entry is hidden. Native authenticated /wp-admin/ internals, AJAX and recovery-token flows remain compatible.', 'yablonsky-security' ) . '</p></div>';
        if ( 'permalink_required' === $private_state ) echo '<div class="notice notice-warning inline ysec-inline-notice"><p>' . esc_html__( 'Private entry requires a non-Plain WordPress permalink structure.', 'yablonsky-security' ) . '</p></div>';
        echo '<p class="description">' . esc_html__( 'Emergency recovery: define YSEC_PRIVATE_LOGIN_DISABLE as true in wp-config.php, or run WP-CLI ysec private-entry-disable. Private entry reduces automated discovery; it does not replace strong passwords, 2FA, CAPTCHA or rate limiting.', 'yablonsky-security' ) . '</p></div>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'Human verification provider', 'yablonsky-security' ) . '</span><select name="ysec[captcha_provider]"><option value="none" ' . selected( $settings['captcha_provider'], 'none', false ) . '>' . esc_html__( 'Disabled', 'yablonsky-security' ) . '</option><option value="turnstile" ' . selected( $settings['captcha_provider'], 'turnstile', false ) . '>' . esc_html__( 'Cloudflare Turnstile', 'yablonsky-security' ) . '</option><option value="recaptcha" ' . selected( $settings['captcha_provider'], 'recaptcha', false ) . '>' . esc_html__( 'Google reCAPTCHA', 'yablonsky-security' ) . '</option></select><small>' . esc_html__( 'Verification activates only when a provider, site key and secret key are configured.', 'yablonsky-security' ) . '</small></label>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'CAPTCHA site key', 'yablonsky-security' ) . '</span><input type="text" name="ysec[captcha_site_key]" value="' . esc_attr( (string) $settings['captcha_site_key'] ) . '" autocomplete="off"></label>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'CAPTCHA secret key', 'yablonsky-security' ) . '</span><input type="password" name="ysec[captcha_secret_key]" value="" placeholder="' . esc_attr( ! empty( $settings['captcha_secret_key'] ) ? __( 'Saved securely — leave blank to keep', 'yablonsky-security' ) : __( 'Enter secret key', 'yablonsky-security' ) ) . '" autocomplete="new-password"><span class="ysec-checkbox-line"><input type="checkbox" id="ysec-captcha-clear-secret" name="ysec[captcha_clear_secret]" value="1"><label for="ysec-captcha-clear-secret">' . esc_html__( 'Clear saved secret', 'yablonsky-security' ) . '</label></span></label>';
        self::toggle( 'captcha_wp_login', __( 'WordPress login verification', 'yablonsky-security' ), __( 'Protect wp-login.php login.', 'yablonsky-security' ), $settings );
        self::toggle( 'captcha_wp_register', __( 'WordPress registration verification', 'yablonsky-security' ), __( 'Protect WordPress account registration.', 'yablonsky-security' ), $settings );
        self::toggle( 'captcha_wp_recovery', __( 'WordPress recovery verification', 'yablonsky-security' ), __( 'Protect lost-password and recovery requests.', 'yablonsky-security' ), $settings );
        self::toggle( 'captcha_woo_login', __( 'WooCommerce login verification', 'yablonsky-security' ), __( 'Protect customer-account login forms.', 'yablonsky-security' ), $settings );
        self::toggle( 'captcha_woo_register', __( 'WooCommerce registration verification', 'yablonsky-security' ), __( 'Protect customer registration forms.', 'yablonsky-security' ), $settings );
        self::toggle( 'captcha_woo_recovery', __( 'WooCommerce recovery verification', 'yablonsky-security' ), __( 'Protect customer lost-password requests.', 'yablonsky-security' ), $settings );
        self::toggle( 'reduce_user_enumeration', __( 'Reduce public account enumeration', 'yablonsky-security' ), __( 'Hide anonymous REST user listings, the user sitemap and numeric author probes; use generic login errors.', 'yablonsky-security' ), $settings );
        self::toggle( 'comment_form_proof', __( 'Require local comment form proof', 'yablonsky-security' ), __( 'Reject anonymous submissions sent directly to wp-comments-post.php unless they carry a valid cache-compatible proof rendered with the public comment form. REST, XML-RPC, WP-CLI and authenticated comments are not affected.', 'yablonsky-security' ), $settings );
        self::toggle( 'comment_honeypot', __( 'Anonymous comment honeypot', 'yablonsky-security' ), __( 'Add an invisible field to public WordPress comment forms and reject automated submissions that fill it.', 'yablonsky-security' ), $settings );
        self::toggle( 'comment_rate_enforce', __( 'Anonymous comment rate enforcement', 'yablonsky-security' ), __( 'Bound accepted public comment submissions by stable source identity without affecting logged-in users.', 'yablonsky-security' ), $settings );
        self::compact_number( 'comment_rate_limit', __( 'Comment source limit', 'yablonsky-security' ), __( 'comments', 'yablonsky-security' ), $settings );
        self::compact_number( 'comment_rate_window', __( 'Comment rate window', 'yablonsky-security' ), __( 'minutes', 'yablonsky-security' ), $settings );
        echo '<div class="ysec-settings-callout"><span class="dashicons dashicons-lock"></span><div><strong>' . esc_html__( 'Two-factor authentication', 'yablonsky-security' ) . '</strong><p>' . esc_html__( 'Yablonsky Security TOTP is configured per user. The login security-code field is shown only when at least one account has it enabled.', 'yablonsky-security' ) . '</p><a href="' . esc_url( $accounts_url ) . '">' . esc_html__( 'Manage administrator 2FA', 'yablonsky-security' ) . '</a></div></div>';
        echo '</section>';

        echo '<section class="ysec-surface ysec-settings-card ysec-settings-panel" id="ysec-settings-panel-hardening" role="tabpanel" aria-labelledby="ysec-settings-tab-hardening" data-ysec-settings-panel="hardening" hidden><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Hardening', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'WordPress attack surface', 'yablonsky-security' ) . '</h3></div></div>';
        self::toggle( 'security_headers', __( 'Safe security headers', 'yablonsky-security' ), __( 'Send the four conservative baseline headers. CSP and HSTS are managed separately in the Hardening Security Headers control plane.', 'yablonsky-security' ), $settings );
        self::toggle( 'disable_file_editor', __( 'Disable built-in file editor', 'yablonsky-security' ), __( 'Deny plugin/theme source editing from wp-admin while leaving normal plugin and theme management intact.', 'yablonsky-security' ), $settings );
        self::toggle( 'disable_application_passwords', __( 'Disable API Application Passwords', 'yablonsky-security' ), __( 'Turn off WordPress per-application API credentials only. This does not disable normal user passwords or browser login. Leave this off when REST/XML-RPC integrations, apps or automation need Application Passwords.', 'yablonsky-security' ), $settings );
        echo '<label class="ysec-field"><span>' . esc_html__( 'XML-RPC policy', 'yablonsky-security' ) . '</span><select name="ysec[xmlrpc_mode]"><option value="monitor" ' . selected( $settings['xmlrpc_mode'], 'monitor', false ) . '>' . esc_html__( 'Monitor / allow', 'yablonsky-security' ) . '</option><option value="pingbacks" ' . selected( $settings['xmlrpc_mode'], 'pingbacks', false ) . '>' . esc_html__( 'Block pingbacks only', 'yablonsky-security' ) . '</option><option value="disable" ' . selected( $settings['xmlrpc_mode'], 'disable', false ) . '>' . esc_html__( 'Disable XML-RPC', 'yablonsky-security' ) . '</option></select><small>' . esc_html__( 'Use the least disruptive policy compatible with your integrations.', 'yablonsky-security' ) . '</small></label>';
        echo '<div class="ysec-settings-subgroup"><div><strong>' . esc_html__( 'Technology exposure reduction', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Reduce passive WordPress/WooCommerce fingerprint hints without rewriting wp-content/plugin/theme asset paths. Path rewriting stays out of the safe profile because it can conflict with caches, CDNs and performance plugins.', 'yablonsky-security' ) . '</small></div></div>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'Technology exposure mode', 'yablonsky-security' ) . '</span><select name="ysec[technology_exposure_mode]"><option value="off" ' . selected( (string) ( $settings['technology_exposure_mode'] ?? 'safe' ), 'off', false ) . '>' . esc_html__( 'Off — expose standard platform hints', 'yablonsky-security' ) . '</option><option value="safe" ' . selected( (string) ( $settings['technology_exposure_mode'] ?? 'safe' ), 'safe', false ) . '>' . esc_html__( 'Safe — remove passive metadata hints (recommended)', 'yablonsky-security' ) . '</option><option value="extended" ' . selected( (string) ( $settings['technology_exposure_mode'] ?? 'safe' ), 'extended', false ) . '>' . esc_html__( 'Extended — also remove local asset version query hints', 'yablonsky-security' ) . '</option></select><small>' . esc_html__( 'This reduces easy fingerprinting; it cannot honestly guarantee that WordPress, WooCommerce, frontend libraries or hosting technologies become undetectable from public behavior and asset paths.', 'yablonsky-security' ) . '</small></label>';
        echo '</section>';

        echo '<section class="ysec-surface ysec-settings-card ysec-settings-panel" id="ysec-settings-panel-network" role="tabpanel" aria-labelledby="ysec-settings-tab-network" data-ysec-settings-panel="network" hidden><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Network', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Trusted network context', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Proxy trust and optional country policy remain explicit. Country enforcement uses only Cloudflare country evidence received from a verified Cloudflare peer.', 'yablonsky-security' ) . '</p></div></div><label class="ysec-field"><span>' . esc_html__( 'Trusted proxy IPs or CIDRs', 'yablonsky-security' ) . '</span><textarea rows="7" name="ysec[trusted_proxies]">' . esc_textarea( $settings['trusted_proxies'] ) . '</textarea><small>' . esc_html__( 'One IP or CIDR per line. Forwarded client headers are trusted only when REMOTE_ADDR matches this list.', 'yablonsky-security' ) . '</small></label>';
        self::toggle( 'crawler_feeds_consent', __( 'Update official crawler IP lists', 'yablonsky-security' ), __( 'Optional. Download official crawler IP lists during maintenance. No visitor IPs are sent. Disable to revoke trust.', 'yablonsky-security' ), $settings );
        echo '<div class="ysec-settings-subgroup"><div><strong>' . esc_html__( 'Geo Security', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Country enforcement uses CF-IPCountry only when the direct TCP peer is a verified Cloudflare address. This prevents spoofed country headers from becoming an allow/deny authority.', 'yablonsky-security' ) . '</small></div></div>';
        self::toggle( 'country_block_enabled', __( 'Enable Geo Security country deny policy', 'yablonsky-security' ), __( 'Deny requests from listed countries according to the scope below. Tokenized recovery, REST, cron and WordPress AJAX/admin-post recovery paths remain available.', 'yablonsky-security' ), $settings );
        echo '<label class="ysec-field"><span>' . esc_html__( 'Geo Security scope', 'yablonsky-security' ) . '</span><select name="ysec[country_block_scope]"><option value="auth" ' . selected( (string) ( $settings['country_block_scope'] ?? 'public' ), 'auth', false ) . '>' . esc_html__( 'Authentication / admin entry only', 'yablonsky-security' ) . '</option><option value="public" ' . selected( (string) ( $settings['country_block_scope'] ?? 'public' ), 'public', false ) . '>' . esc_html__( 'Public site only', 'yablonsky-security' ) . '</option><option value="all" ' . selected( (string) ( $settings['country_block_scope'] ?? 'public' ), 'all', false ) . '>' . esc_html__( 'Authentication + public site', 'yablonsky-security' ) . '</option></select><small>' . esc_html__( 'For most stores, “Authentication / admin entry only” is the least disruptive country policy. Public-site blocking can hide catalog content from visitors in those countries.', 'yablonsky-security' ) . '</small></label>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'Country deny list', 'yablonsky-security' ) . '</span><textarea rows="5" name="ysec[country_blocklist]" placeholder="RU&#10;CN">' . esc_textarea( (string) $settings['country_blocklist'] ) . '</textarea><small>' . esc_html__( 'Two-letter ISO country codes, one per line (commas and spaces accepted). YSec does not bundle or query a third-party GeoIP database.', 'yablonsky-security' ) . '</small></label></section>';

        echo '<section class="ysec-surface ysec-settings-card ysec-settings-panel" id="ysec-settings-panel-data" role="tabpanel" aria-labelledby="ysec-settings-tab-data" data-ysec-settings-panel="data" hidden><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Data', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Security data retention', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Keep recent detailed security records for investigation and compact long-term summaries for trends.', 'yablonsky-security' ) . '</p></div></div><div class="ysec-retention-grid">';
        self::compact_number( 'evidence_retention_info', __( 'Info / low records', 'yablonsky-security' ), __( 'days', 'yablonsky-security' ), $settings );
        self::compact_number( 'evidence_retention_medium', __( 'Medium records', 'yablonsky-security' ), __( 'days', 'yablonsky-security' ), $settings );
        self::compact_number( 'evidence_retention_high', __( 'High records', 'yablonsky-security' ), __( 'days', 'yablonsky-security' ), $settings );
        self::compact_number( 'evidence_retention_critical', __( 'Critical records', 'yablonsky-security' ), __( 'days', 'yablonsky-security' ), $settings );
        self::compact_number( 'rollup_days', __( 'Compact analytics history', 'yablonsky-security' ), __( 'days', 'yablonsky-security' ), $settings );
        self::compact_number( 'retention_days', __( 'Operational / audit records', 'yablonsky-security' ), __( 'days', 'yablonsky-security' ), $settings );
        self::compact_number( 'event_max_rows', __( 'Emergency record ceiling', 'yablonsky-security' ), __( 'rows', 'yablonsky-security' ), $settings );
        echo '</div></section>';

        echo '<section class="ysec-surface ysec-settings-card ysec-settings-panel" id="ysec-settings-panel-alerts" role="tabpanel" aria-labelledby="ysec-settings-tab-alerts" data-ysec-settings-panel="alerts" hidden><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Alerts', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Security notifications & digest', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Local WordPress email alerts use bounded cooldowns and work directly through the configured site mail delivery.', 'yablonsky-security' ) . '</p></div></div>';
        self::toggle( 'alerts_enabled', __( 'Enable security email alerts', 'yablonsky-security' ), __( 'Use wp_mail to send the selected notifications. Leave disabled if another incident-alerting system owns this responsibility.', 'yablonsky-security' ), $settings );
        echo '<label class="ysec-field"><span>' . esc_html__( 'Alert recipient', 'yablonsky-security' ) . '</span><input type="email" name="ysec[alerts_email]" value="' . esc_attr( (string) ( $settings['alerts_email'] ?? '' ) ) . '" placeholder="' . esc_attr( (string) get_option( 'admin_email', '' ) ) . '"><small>' . esc_html__( 'Leave blank to use the WordPress Administration Email Address.', 'yablonsky-security' ) . '</small></label>';
        self::toggle( 'alerts_admin_changes', __( 'Security-relevant administration changes', 'yablonsky-security' ), __( 'Alert on plugin activation/deactivation/deletion, theme switches and user role changes. Repeated identical events are cooled down.', 'yablonsky-security' ), $settings );
        self::toggle( 'alerts_admin_login', __( 'Administrator login alerts', 'yablonsky-security' ), __( 'Notify when an account with manage_options signs in. Repeated alerts for the same administrator are cooled down.', 'yablonsky-security' ), $settings );
        self::toggle( 'alerts_critical_events', __( 'High-confidence critical security alerts', 'yablonsky-security' ), __( 'Send bounded alerts for selected critical YSec security conditions with cooldown-based aggregation.', 'yablonsky-security' ), $settings );
        self::toggle( 'alerts_daily_digest', __( 'Daily security digest', 'yablonsky-security' ), __( 'Send one compact 24-hour severity summary during the existing daily maintenance cycle.', 'yablonsky-security' ), $settings );
        echo '<p class="ysec-settings-test-action"><button class="button" name="ysec_send_test_alert" value="1">' . esc_html__( 'Send test alert', 'yablonsky-security' ) . '</button><span>' . esc_html__( 'Uses the currently saved recipient. Save settings first if you changed the address above.', 'yablonsky-security' ) . '</span></p></section>';

        echo '<section class="ysec-surface ysec-settings-card ysec-settings-panel" id="ysec-settings-panel-ai" role="tabpanel" aria-labelledby="ysec-settings-tab-ai" data-ysec-settings-panel="ai" hidden><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'AI / Expert', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Yablonsky AI is configured separately', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'The AI account, routing and evidence scope live in the dedicated Yablonsky AI workspace. Local protection runs independently, with AI available for administrator-requested analysis.', 'yablonsky-security' ) . '</p></div><a class="button" href="' . esc_url( $ai_url ) . '">' . esc_html__( 'Open Yablonsky AI', 'yablonsky-security' ) . '</a></div></section>';
        echo '</div>';
        echo '</form>';

        echo '<details class="ysec-surface ysec-security-doctor ysec-settings-utility"><summary class="ysec-settings-utility-summary"><div><span class="ysec-eyebrow">' . esc_html__( 'Security Doctor', 'yablonsky-security' ) . '</span><strong>' . esc_html__( 'Passive runtime self-test', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Open the full local runtime, schema, schedule and encryption report.', 'yablonsky-security' ) . '</small></div><span class="ysec-status-badge ' . esc_attr( ! empty( $doctor['ok'] ) ? 'ysec-status-pass' : 'ysec-status-attention' ) . '">' . esc_html( (int) $doctor['passed'] . '/' . (int) $doctor['total'] ) . '</span></summary><div class="ysec-settings-utility-body"><div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Check', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'State', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Observed value', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Meaning', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $doctor['checks'] as $check ) {
            echo '<tr><td><strong>' . esc_html( (string) $check['label'] ) . '</strong></td><td><span class="ysec-badge ysec-badge-' . esc_attr( ! empty( $check['pass'] ) ? 'low' : 'high' ) . '">' . esc_html( ! empty( $check['pass'] ) ? __( 'Pass', 'yablonsky-security' ) : __( 'Review', 'yablonsky-security' ) ) . '</span></td><td><code>' . esc_html( (string) $check['value'] ) . '</code></td><td>' . esc_html( (string) $check['detail'] ) . '</td></tr>';
        }
        $doctor_export_url = wp_nonce_url( add_query_arg( array( 'action'=>'ysec_doctor_export' ), admin_url( 'admin-post.php' ) ), 'ysec_doctor_export' );
        echo '</tbody></table></div><div class="ysec-settings-utility-footer"><p class="description">' . esc_html__( 'This self-test reports local configuration, runtime, schema, schedule and encryption health. Penetration testing and compromise assessment remain dedicated verification activities.', 'yablonsky-security' ) . '</p><p class="ysec-settings-utility-actions"><a class="button" href="' . esc_url( $doctor_export_url ) . '">' . esc_html__( 'Export Security Doctor JSON', 'yablonsky-security' ) . '</a></p></div></div></details>';

        echo '<details class="ysec-surface ysec-portability-card ysec-settings-utility"><summary class="ysec-settings-utility-summary"><div><span class="ysec-eyebrow">' . esc_html__( 'Portability', 'yablonsky-security' ) . '</span><strong>' . esc_html__( 'Verified security policy transfer', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Export, validate, preview, apply or roll back policy without moving site-local secrets.', 'yablonsky-security' ) . '</small></div><span class="ysec-status-badge ysec-status-neutral">' . esc_html__( 'Advanced', 'yablonsky-security' ) . '</span></summary><div class="ysec-settings-utility-body"><p class="ysec-settings-utility-actions"><a class="button" href="' . esc_url( $export_url ) . '">' . esc_html__( 'Export policy JSON', 'yablonsky-security' ) . '</a></p><form method="post">';
        wp_nonce_field( 'ysec_policy_import' );
        echo '<label class="ysec-field"><span>' . esc_html__( 'Import policy JSON', 'yablonsky-security' ) . '</span><textarea rows="8" name="ysec_policy_json" placeholder="{ &quot;schema&quot;: &quot;yablonsky.security.policy.v2&quot;, ... }"></textarea><small>' . esc_html__( 'Validation makes no state change. Applying a validated preview creates a one-step rollback snapshot first.', 'yablonsky-security' ) . '</small></label><p><button class="button button-primary" name="ysec_policy_preview" value="1">' . esc_html__( 'Validate & preview', 'yablonsky-security' ) . '</button></p></form>';
        $policy_preview = get_transient( 'ysec_policy_preview_' . get_current_user_id() );
        if ( is_array( $policy_preview ) ) {
            $summary = is_array( $policy_preview['summary'] ?? null ) ? $policy_preview['summary'] : array();
            echo '<div class="ysec-grid ysec-grid-4">';
            self::metric( __( 'Protection changes', 'yablonsky-security' ), (string) absint( $summary['settings_changes'] ?? 0 ), __( 'validated fields', 'yablonsky-security' ), 'neutral' );
            self::metric( __( 'Firewall changes', 'yablonsky-security' ), (string) absint( $summary['firewall_changes'] ?? 0 ), __( 'validated fields', 'yablonsky-security' ), 'neutral' );
            self::metric( __( 'Conditional rules', 'yablonsky-security' ), (string) absint( $summary['conditional_rules'] ?? 0 ), ! empty( $summary['conditional_rules_changed'] ) ? __( 'catalog changes', 'yablonsky-security' ) : __( 'unchanged', 'yablonsky-security' ), 'neutral' );
            self::metric( __( 'Security Headers changes', 'yablonsky-security' ), (string) absint( $summary['security_headers_changes'] ?? 0 ), __( 'CSP / HSTS policy fields', 'yablonsky-security' ), 'neutral' );
            self::metric( __( 'Secrets preserved', 'yablonsky-security' ), (string) absint( $summary['secrets_preserved'] ?? 0 ), __( 'site-local fields', 'yablonsky-security' ), 'pass' );
            echo '</div><form method="post" class="ysec-action-row">'; wp_nonce_field( 'ysec_policy_apply' ); echo '<input type="hidden" name="preview_digest" value="' . esc_attr( (string) ( $policy_preview['digest'] ?? '' ) ) . '"><button class="button button-primary" name="ysec_policy_apply" value="1">' . esc_html__( 'Apply validated preview', 'yablonsky-security' ) . '</button><code>' . esc_html( substr( (string) ( $policy_preview['digest'] ?? '' ), 0, 16 ) ) . '…</code></form>';
        }
        if ( YSEC_Policy_Portability::has_rollback() ) {
            echo '<form method="post" class="ysec-action-row">'; wp_nonce_field( 'ysec_policy_rollback' ); echo '<button class="button" name="ysec_policy_rollback" value="1">' . esc_html__( 'Rollback last policy import', 'yablonsky-security' ) . '</button><span>' . esc_html__( 'Restores the policy state captured immediately before the last applied import.', 'yablonsky-security' ) . '</span></form>';
        }
        echo '</div></details>';
    }

    private static function metric( string $label, string $value, string $meta, string $state ): void {
        echo '<div class="ysec-metric ysec-metric-' . esc_attr( sanitize_key( $state ) ) . '"><span>' . esc_html( $label ) . '</span><strong>' . esc_html( $value ) . '</strong><small>' . esc_html( $meta ) . '</small></div>';
    }

    private static function layer_row( string $label, bool $enabled, string $meta ): void {
        echo '<div class="ysec-layer-row"><div><strong>' . esc_html( $label ) . '</strong><span>' . esc_html( $meta ) . '</span></div><span class="ysec-status-badge ' . ( $enabled ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $enabled ? __( 'ON', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ) ) . '</span></div>';
    }

    private static function toggle( string $key, string $label, string $description, array $settings ): void {
        echo '<label class="ysec-toggle-row"><span><strong>' . esc_html( $label ) . '</strong><small>' . esc_html( $description ) . '</small></span><span class="ysec-switch"><input type="checkbox" name="ysec[' . esc_attr( $key ) . ']" value="1" ' . checked( ! empty( $settings[ $key ] ), true, false ) . '><i aria-hidden="true"></i></span></label>';
    }

    private static function compact_number( string $key, string $label, string $suffix, array $settings ): void {
        $value = isset( $settings[ $key ] ) && is_scalar( $settings[ $key ] ) ? (string) $settings[ $key ] : '';
        echo '<label class="ysec-inline-number"><span>' . esc_html( $label ) . '</span><span><input type="number" min="1" name="ysec[' . esc_attr( $key ) . ']" value="' . esc_attr( $value ) . '"><small>' . esc_html( $suffix ) . '</small></span></label>';
    }

    private static function model_picker( array $choices, string $selected, bool $route_ready = true ): void {
        if ( ! $route_ready ) {
            echo '<div class="ysec-model-picker"><input type="hidden" name="ysec_ai_model_id" value=""><button type="button" class="ysec-model-picker-button" disabled><span>' . esc_html__( 'Connect or refresh the model catalog', 'yablonsky-security' ) . '</span></button></div>';
            return;
        }
        $current = '' !== $selected && isset( $choices[ $selected ] ) ? $choices[ $selected ] : __( 'Auto · Security Analyst', 'yablonsky-security' );
        echo '<div class="ysec-model-picker" data-ysec-model-picker><input type="hidden" name="ysec_ai_model_id" value="' . esc_attr( $selected ) . '" data-ysec-model-value><button type="button" class="ysec-model-picker-button" data-ysec-model-toggle aria-haspopup="listbox" aria-expanded="false"><span data-ysec-model-current>' . esc_html( $current ) . '</span><span class="dashicons dashicons-arrow-down-alt2" aria-hidden="true"></span></button><div class="ysec-model-picker-popover" data-ysec-model-popover hidden><label class="ysec-model-picker-search"><span class="screen-reader-text">' . esc_html__( 'Search text models', 'yablonsky-security' ) . '</span><input type="search" placeholder="' . esc_attr__( 'Search text models…', 'yablonsky-security' ) . '" autocomplete="off" data-ysec-model-search></label><div class="ysec-model-picker-list" role="listbox" data-ysec-model-list>';
        self::model_picker_option( '', __( 'Auto · Security Analyst', 'yablonsky-security' ), $selected );
        foreach ( $choices as $id => $label ) {
            self::model_picker_option( (string) $id, (string) $label, $selected );
        }
        echo '<div class="ysec-model-picker-empty" data-ysec-model-empty hidden>' . esc_html__( 'Try another model search.', 'yablonsky-security' ) . '</div></div></div></div>';
    }

    private static function model_picker_option( string $id, string $label, string $selected ): void {
        $is_selected = $id === $selected;
        $search = strtolower( $label . ' ' . $id );
        echo '<button type="button" role="option" class="ysec-model-picker-option' . ( $is_selected ? ' is-selected' : '' ) . '" data-ysec-model-option data-model-id="' . esc_attr( $id ) . '" data-model-label="' . esc_attr( $label ) . '" data-model-search="' . esc_attr( $search ) . '" aria-selected="' . ( $is_selected ? 'true' : 'false' ) . '"><strong>' . esc_html( $label ) . '</strong>' . ( '' !== $id ? '<small>' . esc_html( $id ) . '</small>' : '' ) . '</button>';
    }

    private static function ai_choices( $raw, string $kind ): array {
        if ( ! is_array( $raw ) ) {
            return array();
        }
        if ( 'model' === $kind ) {
            foreach ( array( 'text', 'text_models', 'models' ) as $bucket ) {
                if ( isset( $raw[ $bucket ] ) && is_array( $raw[ $bucket ] ) ) {
                    $raw = $raw[ $bucket ];
                    break;
                }
            }
        }
        $choices = array();
        foreach ( $raw as $key => $item ) {
            if ( is_string( $item ) ) {
                $id = is_string( $key ) ? $key : $item;
                $choices[ $id ] = $item;
                continue;
            }
            if ( ! is_array( $item ) ) {
                continue;
            }
            $id = (string) ( $item['id'] ?? $item['workspace_id'] ?? $item['model_id'] ?? '' );
            if ( '' === $id ) {
                continue;
            }
            $label = (string) ( $item['name'] ?? $item['label'] ?? $item['display_name'] ?? $id );
            if ( 'workspace' === $kind && ! empty( $item['plan'] ) ) {
                $label .= ' · ' . sanitize_text_field( (string) $item['plan'] );
            }
            $choices[ $id ] = $label;
        }
        return $choices;
    }

    private static function ai_state_label( $value, string $fallback ): string {
        if ( is_scalar( $value ) ) {
            $text = trim( sanitize_text_field( (string) $value ) );
            return '' !== $text ? $text : $fallback;
        }
        if ( is_array( $value ) ) {
            foreach ( array( 'name', 'label', 'display_name', 'id', 'workspace_id', 'model_id' ) as $key ) {
                if ( isset( $value[ $key ] ) && is_scalar( $value[ $key ] ) ) {
                    $text = trim( sanitize_text_field( (string) $value[ $key ] ) );
                    if ( '' !== $text ) {
                        return $text;
                    }
                }
            }
        }
        return $fallback;
    }

    private static function ai_credit_label( array $state ): array {
        $credits = $state['credits'] ?? null;
        if ( is_numeric( $credits ) ) {
            return array( number_format_i18n( (float) $credits, 2 ), __( 'Available AI credits', 'yablonsky-security' ) );
        }
        if ( is_array( $credits ) ) {
            $available = $credits['available'] ?? $credits['remaining'] ?? $credits['balance'] ?? null;
            $total = $credits['total'] ?? $credits['limit'] ?? null;
            if ( is_numeric( $available ) ) {
                /* translators: %s: total AI credit allowance. */
                $meta = is_numeric( $total ) ? sprintf( __( 'of %s total', 'yablonsky-security' ), number_format_i18n( (float) $total, 2 ) ) : __( 'Available AI credits', 'yablonsky-security' );
                return array( number_format_i18n( (float) $available, 2 ), $meta );
            }
        }
        return array( __( 'Unknown', 'yablonsky-security' ), __( 'Refresh account to check', 'yablonsky-security' ) );
    }

    private static function local_datetime( string $iso ): string {
        $iso = trim( $iso );
        if ( '' === $iso ) {
            return '—';
        }
        $timestamp = strtotime( $iso );
        if ( ! $timestamp ) {
            return $iso;
        }
        return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp );
    }

    private static function format_duration_compact( int $seconds ): string {
        $seconds = max( 0, $seconds );
        $hours = intdiv( $seconds, HOUR_IN_SECONDS );
        $minutes = intdiv( $seconds % HOUR_IN_SECONDS, MINUTE_IN_SECONDS );
        $secs = $seconds % MINUTE_IN_SECONDS;
        if ( $hours > 0 ) return sprintf( '%d:%02d:%02d', $hours, $minutes, $secs );
        return sprintf( '%d:%02d', $minutes, $secs );
    }

    private static function short_time( string $iso ): string {
        $timestamp = strtotime( $iso );
        if ( ! $timestamp ) {
            return __( 'Unknown', 'yablonsky-security' );
        }
        return wp_date( 'Y-m-d H:i', $timestamp );
    }
}
