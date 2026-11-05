<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class YSEC_Admin_Tables {
    public static function boot(): void {
        add_action( 'wp_ajax_ysec_table', array( __CLASS__, 'ajax_table' ) );
        add_action( 'wp_ajax_ysec_filter_options', array( __CLASS__, 'ajax_filter_options' ) );
    }

    public static function ajax_table(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'You are not allowed to view security data.', 'yablonsky-security' ) ), 403 );
        }
        check_ajax_referer( 'ysec_admin_tables', 'nonce' );
        $request = map_deep( wp_unslash( $_POST ), 'sanitize_text_field' );
        $dataset = isset( $request['dataset'] ) ? sanitize_key( $request['dataset'] ) : '';
        $args    = self::request_args( $request );
        $html    = self::result_html( $dataset, $args );
        if ( '' === $html ) {
            wp_send_json_error( array( 'message' => __( 'Unknown security data view.', 'yablonsky-security' ) ), 400 );
        }
        wp_send_json_success( array( 'html' => $html ) );
    }

    public static function ajax_filter_options(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'You are not allowed to view security data.', 'yablonsky-security' ) ), 403 );
        }
        check_ajax_referer( 'ysec_admin_tables', 'nonce' );
        $request = map_deep( wp_unslash( $_POST ), 'sanitize_text_field' );
        $dataset = isset( $request['dataset'] ) ? sanitize_key( $request['dataset'] ) : '';
        $field   = isset( $request['field'] ) ? sanitize_key( $request['field'] ) : '';
        $query   = isset( $request['q'] ) ? trim( sanitize_text_field( (string) $request['q'] ) ) : '';

        if ( ! in_array( $dataset, array( 'events', 'recon', 'firewall_actions' ), true ) || 'family' !== $field ) {
            wp_send_json_error( array( 'message' => __( 'Unknown security data view.', 'yablonsky-security' ) ), 400 );
        }

        $options = YSEC_Events::filter_options();
        $values  = is_array( $options['families'] ?? null ) ? $options['families'] : array();
        $results = array();
        foreach ( $values as $value ) {
            $value = sanitize_key( (string) $value );
            if ( '' === $value ) {
                continue;
            }
            $label = self::human_label( $value );
            if ( '' !== $query && false === stripos( $label . ' ' . $value, $query ) ) {
                continue;
            }
            $results[] = array(
                'value' => $value,
                'label' => $label,
            );
            if ( count( $results ) >= 30 ) {
                break;
            }
        }

        wp_send_json_success( array( 'results' => $results ) );
    }

    public static function request_args( array $request ): array {
        $allowed = array( 'page', 'per_page', 'search', 'severity', 'family', 'state', 'date_from', 'date_to', 'orderby', 'order', 'type', 'status', 'rule', 'record_status', 'role', 'session_status', 'two_factor', 'account_state', 'enforcement_only' );
        $out     = array();
        foreach ( $allowed as $key ) {
            if ( ! isset( $request[ $key ] ) ) {
                continue;
            }
            $value = $request[ $key ];
            if ( is_array( $value ) || is_object( $value ) ) {
                continue;
            }
            if ( in_array( $key, array( 'page', 'per_page' ), true ) ) {
                $out[ $key ] = absint( $value );
            } elseif ( in_array( $key, array( 'date_from', 'date_to' ), true ) ) {
                $out[ $key ] = preg_replace( '/[^0-9\-]/', '', (string) $value );
            } elseif ( 'search' === $key ) {
                $out[ $key ] = sanitize_text_field( (string) $value );
            } else {
                $out[ $key ] = sanitize_key( (string) $value );
            }
        }
        return $out;
    }

    public static function events(): void {
        $opts = YSEC_Events::filter_options();
        $storage = YSEC_Events::storage_summary();
        self::shell_start( 'events' );
        echo '<div class="ysec-section-intro ysec-monitor-intro"><h2>' . esc_html__( 'Security events', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Events are evidence records. Blocking is a separate response action: suspicious sources can be temporarily blocked, while reviewed evidence can be archived or deleted without changing protection rules.', 'yablonsky-security' ) . '</p></div>';
        self::evidence_view_guide( 'events' );
        echo '<div class="ysec-grid ysec-grid-4 ysec-event-storage ysec-monitor-summary">';
        // A failed summary read is an unavailable measurement, never zero evidence.
        $summary_valid = ! empty( $storage['valid'] );
        self::stat_card( __( 'Active records', 'yablonsky-security' ), $summary_valid ? $storage['active'] : '—' );
        self::stat_card( __( 'Evidence hits', 'yablonsky-security' ), $summary_valid ? $storage['hits'] : '—' );
        self::stat_card( __( 'Compressed repeats', 'yablonsky-security' ), $summary_valid ? $storage['compressed'] : '—' );
        /* translators: 1: shortest raw evidence retention days, 2: longest critical evidence retention days. */
        $retention_label = sprintf( __( '%1$d–%2$d days hot', 'yablonsky-security' ), absint( YSEC_Utils::option( 'evidence_retention_info', 1 ) ), absint( YSEC_Utils::option( 'evidence_retention_critical', 30 ) ) );
        self::stat_card( __( 'Bounded retention', 'yablonsky-security' ), $retention_label, true );
        echo '</div>';
        $storage_health = YSEC_DB::storage_health();
        $storage_valid = ! empty( $storage_health['valid'] );
        $pressure_class = $storage_valid && (float) $storage_health['pressure_percent'] < 80 ? 'ysec-status-pass' : 'ysec-status-attention';
        $pressure_label = $storage_valid
            ? number_format_i18n( (float) $storage_health['pressure_percent'], 1 ) . '% ' . __( 'of ceiling', 'yablonsky-security' )
            : __( 'Review required', 'yablonsky-security' );
        echo '<section class="ysec-surface ysec-storage-health"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Storage health', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Bounded evidence warehouse', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'This shows physical hot rows separately from logical evidence hits and compact rollups. The emergency ceiling is a safety backstop, not a retention target.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $pressure_class ) . '">' . esc_html( $pressure_label ) . '</span></div>';
        if ( $storage_valid ) {
            echo '<div class="ysec-storage-meter"><i style="--w:' . esc_attr( (string) min( 100, (float) $storage_health['pressure_percent'] ) ) . '%"></i></div>';
        }
        echo '<div class="ysec-grid ysec-grid-4">';
        self::stat_card( __( 'Hot rows', 'yablonsky-security' ), $storage_valid ? (int) $storage_health['event_rows'] : '—' );
        self::stat_card( __( 'Logical evidence hits', 'yablonsky-security' ), $storage_valid ? (int) $storage_health['event_hits'] : '—' );
        self::stat_card( __( 'Rollup rows', 'yablonsky-security' ), $storage_valid ? (int) $storage_health['rollup_rows'] : '—' );
        self::stat_card( __( 'Active background jobs', 'yablonsky-security' ), $storage_valid ? (int) $storage_health['active_jobs'] : '—' );
        $last_cycle = YSEC_DB::last_retention_cycle();
        // Show the numeric limit as well as the true (possibly >100%) pressure.
        if ( $storage_valid && (int) $storage_health['event_rows'] > (int) $storage_health['row_ceiling'] ) {
            echo '<p class="description"><strong>' . esc_html__( 'Data maintenance', 'yablonsky-security' ) . ': ' . esc_html__( 'Review required', 'yablonsky-security' ) . '</strong> · ' . esc_html__( 'Hot rows', 'yablonsky-security' ) . ': ' . esc_html( number_format_i18n( (int) $storage_health['event_rows'] ) ) . ' / ' . esc_html( number_format_i18n( (int) $storage_health['row_ceiling'] ) ) . '</p>';
        }
        if ( $storage_valid ) {
            echo '</div><p class="description">' . esc_html__( 'Oldest hot evidence:', 'yablonsky-security' ) . ' <strong>' . esc_html( $storage_health['oldest_event'] ? self::local_datetime( (string)$storage_health['oldest_event'] ) : __( 'none', 'yablonsky-security' ) ) . '</strong> · ' . esc_html__( 'Oldest compact rollup:', 'yablonsky-security' ) . ' <strong>' . esc_html( $storage_health['oldest_rollup'] ?: __( 'none', 'yablonsky-security' ) ) . '</strong></p>';
        } else {
            echo '</div><p class="description"><strong>' . esc_html__( 'Data maintenance', 'yablonsky-security' ) . ': ' . esc_html__( 'Review required', 'yablonsky-security' ) . '</strong></p>';
        }
        $retention_error = get_option( 'ysec_last_retention_error', array() );
        if ( is_array( $retention_error ) && ! empty( $retention_error['at'] ) ) {
            echo '<p class="description"><strong>' . esc_html__( 'Data maintenance', 'yablonsky-security' ) . ': ' . esc_html__( 'Review required', 'yablonsky-security' ) . '</strong> · ' . esc_html( self::local_datetime( (string) $retention_error['at'] ) ) . '</p>';
        }
        if ( $last_cycle ) {
            /* translators: 1: UTC maintenance time, 2: number of physical rows removed. */
            echo '<p class="description">' . esc_html( sprintf( __( 'Last retention cycle: %1$s · %2$d physical rows removed.', 'yablonsky-security' ), self::local_datetime( (string) ( $last_cycle['ran_at'] ?? '' ) ), (int) ( $last_cycle['rows_removed'] ?? 0 ) ) ) . '</p>';
        }
        echo '</section>';
        echo '<div class="ysec-data-maintenance"><div><strong>' . esc_html__( 'Data maintenance', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'Hot request evidence expires by security value while compact daily rollups preserve long-term analytics. You can still archive or delete reviewed evidence manually.', 'yablonsky-security' ) . '</span></div><form method="post">';
        wp_nonce_field( 'ysec_event_maintenance' );
        echo '<input type="date" name="ysec_archive_date" value="' . esc_attr( wp_date( 'Y-m-d', time() - 7 * DAY_IN_SECONDS ) ) . '"><button class="button" name="ysec_archive_before" value="1">' . esc_html__( 'Archive older than date', 'yablonsky-security' ) . '</button><button class="button" name="ysec_run_retention" value="1">' . esc_html__( 'Run retention now', 'yablonsky-security' ) . '</button><button class="button ysec-confirm-action" data-confirm="' . esc_attr__( 'Delete all archived security events? This cannot be undone.', 'yablonsky-security' ) . '" name="ysec_delete_archived" value="1">' . esc_html__( 'Delete archived', 'yablonsky-security' ) . '</button></form></div>';
        self::monitor_filters( 'events', $opts );
        self::hidden_sort( 'observed_at', 'DESC' );
        echo '<div class="ysec-table-result ysec-lazy-result ysec-monitor-result" data-ysec-initial-load="1"><div class="ysec-inline-loader"><span class="spinner is-active"></span><span>' . esc_html__( 'Loading event evidence…', 'yablonsky-security' ) . '</span></div></div>';
        self::export_zone( 'events' );
        self::ai_context_panel( 'events' );
        self::shell_end();
    }

    public static function recon(): void {
        $opts = YSEC_Events::filter_options();
        self::shell_start( 'recon' );
        echo '<div class="ysec-section-intro ysec-monitor-intro"><h2>' . esc_html__( 'Reconnaissance campaigns', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'This is a derived view of suspicious events, not a second log. Requests from the same source fingerprint and probe family are grouped into one campaign. Risk reflects the strongest observed signal in that campaign.', 'yablonsky-security' ) . '</p></div>';
        self::evidence_view_guide( 'recon' );
        echo '<div class="ysec-risk-legend"><span><b class="ysec-dot ysec-dot-critical"></b>' . esc_html__( 'Critical — exploit-like payload or severe probe', 'yablonsky-security' ) . '</span><span><b class="ysec-dot ysec-dot-high"></b>' . esc_html__( 'High — credentials, webshell or traversal probing', 'yablonsky-security' ) . '</span><span><b class="ysec-dot ysec-dot-medium"></b>' . esc_html__( 'Medium — repeated reconnaissance', 'yablonsky-security' ) . '</span></div>';
        $recon_summary = YSEC_Events::recon_summary( 24 );
        echo '<div class="ysec-grid ysec-grid-4 ysec-recon-summary ysec-monitor-summary">';
        self::stat_card( __( 'Campaigns · 24h', 'yablonsky-security' ), $recon_summary['campaigns'] );
        self::stat_card( __( 'Requests · 24h', 'yablonsky-security' ), $recon_summary['requests'] );
        self::stat_card( __( 'Distinct sources · 24h', 'yablonsky-security' ), $recon_summary['sources'] );
        self::stat_card( __( 'Critical campaigns · 24h', 'yablonsky-security' ), $recon_summary['critical_campaigns'] );
        echo '</div>';
        $crawler_claims = YSEC_Events::crawler_claim_security_summary( 24 );
        if ( ! empty( $crawler_claims['hits'] ) ) {
            $claim_parts = array();
            foreach ( (array) $crawler_claims['agents'] as $agent => $hits ) $claim_parts[] = $agent . ': ' . number_format_i18n( (int) $hits );
            echo '<div class="ysec-policy-strip ysec-crawler-claim-strip"><span class="ysec-status-badge ysec-status-attention">' . esc_html( number_format_i18n( (int) $crawler_claims['hits'] ) . ' ' . __( 'crawler-claimed security hits · 24h', 'yablonsky-security' ) ) . '</span><span>' . esc_html__( 'These are User-Agent claims seen in suspicious or denied requests, not verified crawler identities.', 'yablonsky-security' ) . ( $claim_parts ? '<br><small>' . esc_html( implode( ' · ', $claim_parts ) ) . '</small>' : '' ) . '</span></div>';
        }
        self::monitor_filters( 'recon', $opts );
        self::hidden_sort( 'risk', 'DESC' );
        echo '<div class="ysec-table-result ysec-lazy-result ysec-monitor-result" data-ysec-initial-load="1"><div class="ysec-inline-loader"><span class="spinner is-active"></span><span>' . esc_html__( 'Loading reconnaissance campaigns…', 'yablonsky-security' ) . '</span></div></div>';
        self::export_zone( 'recon' );
        self::ai_context_panel( 'recon' );
        self::shell_end();
    }

    public static function firewall( $after_monitor = null ): void {
        self::shell_start( 'firewall_actions' );
        $auto = (bool) YSEC_Utils::option( 'auto_block', 0 );
        $profile_key = YSEC_Firewall_Profiles::current();
        $profiles = YSEC_Firewall_Profiles::profiles();
        $profile = $profiles[ $profile_key ];
        $blocks = YSEC_Firewall::query_blocks( array( 'page'=>1, 'per_page'=>10 ) );
        echo '<div class="ysec-section-intro ysec-monitor-intro"><h2>' . esc_html__( 'Firewall control plane', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Firewall makes request-level enforcement decisions. Events preserve compact evidence, Reconnaissance groups related evidence into campaigns, and Active blocks provide full-source containment when required.', 'yablonsky-security' ) . '</p></div>';
        self::evidence_view_guide( 'firewall' );
        $decision_summary = YSEC_Events::firewall_decision_summary( 24 );
        echo '<div class="ysec-grid ysec-grid-4 ysec-monitor-summary">';
        self::stat_card( __( 'Profile', 'yablonsky-security' ), $profile['label'], true );
        self::stat_card( __( 'Denied requests · 24h', 'yablonsky-security' ), (int) ( $decision_summary['request_denies'] ?? 0 ) );
        self::stat_card( __( 'Suspicious observed · 24h', 'yablonsky-security' ), (int) ( $decision_summary['states']['suspicious'] ?? 0 ) );
        self::stat_card( __( 'Explicit source blocks', 'yablonsky-security' ), (int) $blocks['total'] );
        echo '</div>';
        echo '<div class="ysec-policy-strip"><span class="ysec-status-badge ysec-status-pass">' . esc_html( $profile['label'] ) . '</span><span>' . esc_html( $profile['description'] ) . '</span></div>';
        self::monitor_filters( 'firewall_actions', YSEC_Events::filter_options() );
        echo '<input type="hidden" name="enforcement_only" value="1">';
        self::hidden_sort( 'observed_at', 'DESC' );
        echo '<div class="ysec-table-result ysec-lazy-result ysec-monitor-result" data-ysec-initial-load="1"><div class="ysec-inline-loader"><span class="spinner is-active"></span><span>' . esc_html__( 'Loading firewall analytics and enforcement evidence…', 'yablonsky-security' ) . '</span></div></div>';
        self::export_zone( 'firewall_actions' );
        self::ai_context_panel( 'firewall' );
        if ( is_callable( $after_monitor ) ) {
            call_user_func( $after_monitor );
        }
        echo '<div class="ysec-section-intro ysec-monitor-secondary-intro"><h3>' . esc_html__( 'Verification & origin response', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Evidence and actions stay above. The panels below verify enforcement and tune origin-response behavior while policy controls and event evidence remain in distinct operational lanes.', 'yablonsky-security' ) . '</p></div>';
        $firewall_proof = YSEC_Firewall_Proof::last();
        $engine_proof = is_array( $firewall_proof['engine'] ?? null ) ? $firewall_proof['engine'] : array();
        $live_proof = is_array( $firewall_proof['live'] ?? null ) ? $firewall_proof['live'] : array();
        echo '<section id="ysec-firewall-proof" class="ysec-surface ysec-firewall-proof"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Firewall proof', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Prove the selected profile with live evidence', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Runs a deterministic rule-engine canary and a same-site HTTP loopback canary. PASS requires a YSec one-time proof marker from the live request path.', 'yablonsky-security' ) . '</p></div>';
        if ( $firewall_proof ) echo '<span class="ysec-status-badge ' . esc_attr( ! empty( $firewall_proof['ok'] ) ? 'ysec-status-pass' : 'ysec-status-attention' ) . '">' . esc_html( ! empty( $firewall_proof['ok'] ) ? __( 'PROVED', 'yablonsky-security' ) : __( 'REVIEW', 'yablonsky-security' ) ) . '</span>';
        echo '</div>';
        if ( $firewall_proof ) {
            $engine_state = ! empty( $engine_proof['ok'] ) ? __( 'PASS', 'yablonsky-security' ) : __( 'FAIL', 'yablonsky-security' );
            $live_state = ! empty( $live_proof['ok'] ) ? __( 'PASS', 'yablonsky-security' ) : ( ! empty( $live_proof['unavailable'] ) ? __( 'READY TO RETRY', 'yablonsky-security' ) : __( 'REVIEW', 'yablonsky-security' ) );
            echo '<div class="ysec-grid ysec-grid-3">';
            self::stat_card( __( 'Profile under test', 'yablonsky-security' ), (string) ( $firewall_proof['label'] ?? $profile['label'] ), true );
            self::stat_card( __( 'Rule engine', 'yablonsky-security' ), $engine_state, true );
            self::stat_card( __( 'Live enforcement', 'yablonsky-security' ), $live_state, true );
            $code_note = isset( $live_proof['code'] ) ? ( ! empty( $live_proof['ok'] ) && 403 === (int) $live_proof['code'] ? __( 'HTTP 403 — expected deny', 'yablonsky-security' ) : sprintf( 'HTTP %d', (int) $live_proof['code'] ) ) : '';
            echo '</div><div class="ysec-proof-details"><p><strong>' . esc_html__( 'Engine:', 'yablonsky-security' ) . '</strong> ' . esc_html( (string) ( $engine_proof['message'] ?? '' ) ) . '</p><p><strong>' . esc_html__( 'Live:', 'yablonsky-security' ) . '</strong> ' . esc_html( (string) ( $live_proof['message'] ?? '' ) ) . ( '' !== $code_note ? ' <code>' . esc_html( $code_note ) . '</code>' : '' ) . '</p><p><small>' . esc_html( (string) ( $firewall_proof['checked_at'] ?? '' ) ) . '</small></p></div>';
        }
        $proof_url = wp_nonce_url( add_query_arg( array( 'action'=>'ysec_firewall_proof_export' ), admin_url( 'admin-post.php' ) ), 'ysec_firewall_proof_export' );
        $proof_action = admin_url( 'admin-post.php' );
        echo '<div class="ysec-firewall-proof-toolbar"><form method="post" action="' . esc_url( $proof_action ) . '" class="ysec-action-row ysec-firewall-proof-form">';
        wp_nonce_field( 'ysec_firewall_proof' );
        echo '<input type="hidden" name="action" value="ysec_firewall_proof_run"><button class="button button-primary ysec-firewall-proof-run" type="submit">' . esc_html__( 'Run firewall proof', 'yablonsky-security' ) . '</button><span>' . esc_html__( 'Safe synthetic requests preserve the current configuration. PASS with HTTP 403 confirms that YSec denied its own canary through the selected enforcement path.', 'yablonsky-security' ) . '</span></form><div class="ysec-firewall-proof-export">';
        if ( $firewall_proof ) {
            echo '<a class="button" href="' . esc_url( $proof_url ) . '">' . esc_html__( 'Download proof JSON', 'yablonsky-security' ) . '</a>';
        } else {
            echo '<button type="button" class="button" disabled>' . esc_html__( 'Download proof JSON', 'yablonsky-security' ) . '</button><small>' . esc_html__( 'Run the proof once to create a downloadable receipt.', 'yablonsky-security' ) . '</small>';
        }
        echo '</div></div>';
        echo '</section>';
        $l7 = YSEC_L7_Abuse::admin_state();
        echo '<section class="ysec-surface ysec-l7-origin"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Origin abuse intelligence', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Classify public load and authentication abuse on separate security paths', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'YSec recognizes state-changing GET and faceted-crawl request families before the main WordPress query, persists only bounded samples, and publishes a sanitized signal for YPerf origin-cost correlation.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( ! empty( $l7['observe'] ) ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( ! empty( $l7['observe'] ) ? __( 'OBSERVING', 'yablonsky-security' ) : __( 'OFF', 'yablonsky-security' ) ) . '</span></div><div class="ysec-grid ysec-grid-3">';
        self::stat_card( __( 'Fast counters', 'yablonsky-security' ), ! empty( $l7['persistent_cache'] ) ? __( 'Persistent cache', 'yablonsky-security' ) : __( 'Sample-only fallback', 'yablonsky-security' ), true );
        $shield_state = empty( $l7['state_enforce'] ) ? __( 'Standby', 'yablonsky-security' ) : ( ! empty( $l7['effective_state_enforce'] ) ? __( 'Enforcing', 'yablonsky-security' ) : __( 'Observe only', 'yablonsky-security' ) );
        self::stat_card( __( 'State-action shield', 'yablonsky-security' ), $shield_state, true );
        self::stat_card( __( 'Per-source threshold', 'yablonsky-security' ), (int) $l7['threshold'] . ' / ' . (int) $l7['window_seconds'] . 's', true );
        echo '</div>';
        if ( ! empty( $l7['state_enforce'] ) && empty( $l7['persistent_cache'] ) ) {
            echo '<div class="notice notice-warning inline ysec-inline-notice"><p>' . esc_html__( 'State-action protection is currently in Observe mode. Persistent object-cache counters activate the constant-cost enforcement path; the current site uses bounded sampling to keep origin pressure predictable.', 'yablonsky-security' ) . '</p></div>';
        }
        echo '<p class="description">' . esc_html__( 'Faceted crawl follows the shared authority model: YSEO owns discovery policy, YPerf owns origin cost and backpressure, and YSec contributes abuse classification plus security response.', 'yablonsky-security' ) . '</p></section>';
        $durable = YSEC_Firewall_Policy::settings();
        $allow_count = count( array_filter( preg_split( '/[\r\n,]+/', (string) $durable['allowlist'] ) ?: array() ) );
        $block_count = count( array_filter( preg_split( '/[\r\n,]+/', (string) $durable['blocklist'] ) ?: array() ) );
        $request_exception_count = count( array_filter( preg_split( '/[\r\n]+/', (string) ( $durable['request_allowlist'] ?? '' ) ) ?: array() ) );
        echo '<details class="ysec-surface ysec-firewall-policy"><summary><strong>' . esc_html__( 'Manual durable policy', 'yablonsky-security' ) . '</strong> — ' . esc_html( number_format_i18n( $allow_count ) . ' ' . __( 'source allow', 'yablonsky-security' ) . ' · ' . number_format_i18n( $block_count ) . ' ' . __( 'permanent block', 'yablonsky-security' ) . ' · ' . number_format_i18n( $request_exception_count ) . ' ' . __( 'request exceptions', 'yablonsky-security' ) ) . '</summary><p>' . esc_html__( 'Administrator-managed durable policy. Source allow entries provide explicit trusted access, permanent block entries stop the source before WordPress routing, and exact request exceptions scope automatic profile matching. Smart adaptive response stays in its adaptive layer, while this section remains fully administrator-controlled with self-lockout protection.', 'yablonsky-security' ) . '</p><form method="post">';
        wp_nonce_field( 'ysec_firewall_policy' );
        echo '<input type="hidden" name="policy_scope" value="firewall"><div class="ysec-rule-grid"><label><span>' . esc_html__( 'Allowlist IPs / CIDRs', 'yablonsky-security' ) . '</span><textarea rows="7" name="ysec_policy[allowlist]">' . esc_textarea( (string) $durable['allowlist'] ) . '</textarea><small>' . esc_html__( 'IPv4, IPv6 and CIDR networks are supported. Add one trusted source or network per line.', 'yablonsky-security' ) . '</small></label><label><span>' . esc_html__( 'Permanent block IPs / CIDRs', 'yablonsky-security' ) . '</span><textarea rows="7" name="ysec_policy[blocklist]">' . esc_textarea( (string) $durable['blocklist'] ) . '</textarea><small>' . esc_html__( 'IPv4, IPv6 and CIDR networks are supported. Add one source or network per line.', 'yablonsky-security' ) . '</small></label></div><label class="ysec-field"><span>' . esc_html__( 'Exact request exceptions', 'yablonsky-security' ) . '</span><textarea rows="5" name="ysec_policy[request_allowlist]">' . esc_textarea( (string) ( $durable['request_allowlist'] ?? '' ) ) . '</textarea><small>' . esc_html__( 'One exact METHOD + path per line, for example GET /known-safe-endpoint. These exceptions bypass automatic firewall-profile matching only; explicit source blocks, Geo Security, rate containment, virtual patches and manual deny rules still take precedence. Up to 100 exceptions.', 'yablonsky-security' ) . '</small></label><label class="ysec-field"><span>' . esc_html__( 'Custom path denies', 'yablonsky-security' ) . '</span><textarea rows="5" name="ysec_policy[path_blocklist]">' . esc_textarea( (string) $durable['path_blocklist'] ) . '</textarea><small>' . esc_html__( 'One absolute path per line. A trailing * means prefix match, for example /private-export/*. Up to 100 rules.', 'yablonsky-security' ) . '</small></label><p><button class="button button-primary" name="ysec_save_firewall_policy" value="1">' . esc_html__( 'Save durable firewall policy', 'yablonsky-security' ) . '</button></p></form></details>';
        $conditional_rules = YSEC_Conditional_Rules::all();
        $enabled_conditional = count( array_filter( $conditional_rules, static fn( $rule ) => ! empty( $rule['enabled'] ) ) );
        echo '<section class="ysec-surface ysec-conditional-rules"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Conditional policy', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Bounded custom deny rules', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Compose explicit request-deny rules by method, path, authentication state and optional source network. Allow and bypass authority stays in the dedicated durable-policy controls.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-neutral">' . esc_html( sprintf( '%d / %d', $enabled_conditional, count( $conditional_rules ) ) ) . '</span></div><form method="post" class="ysec-conditional-rule-form">';
        wp_nonce_field( 'ysec_conditional_rule_add' );
        echo '<div class="ysec-filter-grid ysec-conditional-form-grid"><label class="ysec-field"><span>' . esc_html__( 'Rule label', 'yablonsky-security' ) . '</span><input type="text" name="ysec_conditional_rule[label]" maxlength="100" required></label><label class="ysec-field"><span>' . esc_html__( 'Method', 'yablonsky-security' ) . '</span><select name="ysec_conditional_rule[method]"><option>ANY</option><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select></label><label class="ysec-field"><span>' . esc_html__( 'Path match', 'yablonsky-security' ) . '</span><select name="ysec_conditional_rule[path_mode]"><option value="exact">' . esc_html__( 'Exact', 'yablonsky-security' ) . '</option><option value="prefix">' . esc_html__( 'Prefix', 'yablonsky-security' ) . '</option></select></label><label class="ysec-field"><span>' . esc_html__( 'Request path', 'yablonsky-security' ) . '</span><input type="text" name="ysec_conditional_rule[path]" placeholder="/private-endpoint" required></label><label class="ysec-field"><span>' . esc_html__( 'Authentication', 'yablonsky-security' ) . '</span><select name="ysec_conditional_rule[auth]"><option value="any">' . esc_html__( 'Any', 'yablonsky-security' ) . '</option><option value="anonymous">' . esc_html__( 'Anonymous only', 'yablonsky-security' ) . '</option><option value="authenticated">' . esc_html__( 'Authenticated only', 'yablonsky-security' ) . '</option></select></label><label class="ysec-field"><span>' . esc_html__( 'Source IP / CIDR', 'yablonsky-security' ) . '</span><input type="text" name="ysec_conditional_rule[source_network]" placeholder="optional"></label></div><input type="hidden" name="ysec_conditional_rule[enabled]" value="1"><p><button class="button button-primary" name="ysec_conditional_rule_add" value="1">' . esc_html__( 'Add deny rule', 'yablonsky-security' ) . '</button></p></form>';
        if ( $conditional_rules ) {
            echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Rule', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Condition', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'State', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Action', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
            foreach ( $conditional_rules as $rule ) {
                $rid = (string) ( $rule['id'] ?? '' ); $enabled = ! empty( $rule['enabled'] );
                $condition = (string) ( $rule['method'] ?? 'ANY' ) . ' · ' . (string) ( $rule['path_mode'] ?? 'exact' ) . ' ' . (string) ( $rule['path'] ?? '/' );
                if ( 'any' !== (string) ( $rule['auth'] ?? 'any' ) ) $condition .= ' · ' . (string) $rule['auth'];
                if ( ! empty( $rule['source_network'] ) ) $condition .= ' · ' . (string) $rule['source_network'];
                echo '<tr><td><strong>' . esc_html( (string) ( $rule['label'] ?? '' ) ) . '</strong></td><td><code>' . esc_html( $condition ) . '</code></td><td><span class="ysec-badge ysec-badge-' . esc_attr( $enabled ? 'low' : 'info' ) . '">' . esc_html( $enabled ? __( 'Enabled', 'yablonsky-security' ) : __( 'Off', 'yablonsky-security' ) ) . '</span></td><td><form method="post" class="ysec-inline-form">';
                wp_nonce_field( 'ysec_conditional_rule_' . $rid );
                echo '<input type="hidden" name="rule_id" value="' . esc_attr( $rid ) . '"><input type="hidden" name="enabled" value="' . esc_attr( $enabled ? '0' : '1' ) . '"><button class="button button-small" name="ysec_conditional_rule_toggle" value="1">' . esc_html( $enabled ? __( 'Disable', 'yablonsky-security' ) : __( 'Enable', 'yablonsky-security' ) ) . '</button> <button class="button button-small button-link-delete" name="ysec_conditional_rule_delete" value="1">' . esc_html__( 'Delete', 'yablonsky-security' ) . '</button></form></td></tr>';
            }
            echo '</tbody></table></div>';
        }
        echo '</section>';
        $rules = YSEC_Firewall_Profiles::generate_fast_path_rules();
        $fast_verify = get_transient( 'ysec_fastpath_verify_result' );
        $fast_export = wp_nonce_url( admin_url( 'admin-post.php?action=ysec_fastpath_export' ), 'ysec_fastpath_export' );
        $environment = YSEC_Environment::detect();
        $debug_log_present = is_file( WP_CONTENT_DIR . '/debug.log' );
        $server_label = (string) ( $environment['server'] ?? 'Generic' );
        echo '<details class="ysec-surface ysec-fast-path"><summary><strong>' . esc_html__( 'Optional server fast path', 'yablonsky-security' ) . '</strong> — ' . esc_html__( 'stop obvious probes before WordPress/PHP', 'yablonsky-security' ) . '</summary><p>' . esc_html__( 'Choose the snippet for your web server. Deployment stays administrator-reviewed. The rules stop high-confidence secret/config probes, VCS metadata, common database dumps and diagnostic artifacts before PHP while preserving normal public discovery.', 'yablonsky-security' ) . '</p>';
        echo '<div class="ysec-policy-strip ysec-fastpath-site-state"><span class="ysec-status-badge ysec-status-neutral">' . esc_html( $server_label ) . '</span><span><strong>' . esc_html__( 'Public diagnostic-file shield:', 'yablonsky-security' ) . '</strong> ' . esc_html( $debug_log_present ? __( 'wp-content/debug.log is present. The generated server rule shields this path before PHP after deployment.', 'yablonsky-security' ) : __( 'wp-content/debug.log is clear from the public content tree.', 'yablonsky-security' ) ) . '</span></div>';
        if ( is_array( $fast_verify ) ) echo '<p><span class="ysec-status-badge ' . esc_attr( ! empty( $fast_verify['ok'] ) ? 'ysec-status-pass' : 'ysec-status-attention' ) . '">' . esc_html( ! empty( $fast_verify['ok'] ) ? __( 'VERIFIED', 'yablonsky-security' ) : __( 'READY TO VERIFY', 'yablonsky-security' ) ) . '</span> <small>' . esc_html( (string) ( $fast_verify['checked_at'] ?? '' ) ) . ' · HTTP ' . esc_html( (string) ( $fast_verify['code'] ?? 0 ) ) . '</small></p>';
        echo '<div class="ysec-fastpath-grid"><article class="ysec-fastpath-engine"><div class="ysec-fastpath-engine-head"><div><strong>Nginx</strong><small>' . esc_html__( 'Use this snippet on Nginx servers.', 'yablonsky-security' ) . '</small></div><button type="button" class="button button-small" data-ysec-copy-target="#ysec-fastpath-nginx"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span> ' . esc_html__( 'Copy', 'yablonsky-security' ) . '</button></div><textarea id="ysec-fastpath-nginx" readonly rows="9">' . esc_textarea( $rules['nginx'] ) . '</textarea></article>';
        echo '<article class="ysec-fastpath-engine"><div class="ysec-fastpath-engine-head"><div><strong>' . esc_html__( 'Apache / LiteSpeed', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Use this snippet on Apache or LiteSpeed servers.', 'yablonsky-security' ) . '</small></div><button type="button" class="button button-small" data-ysec-copy-target="#ysec-fastpath-apache"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span> ' . esc_html__( 'Copy', 'yablonsky-security' ) . '</button></div><textarea id="ysec-fastpath-apache" readonly rows="9">' . esc_textarea( $rules['apache'] ) . '</textarea></article></div>';
        echo '<div class="ysec-fastpath-actions"><div><strong>' . esc_html__( 'Deployment tools', 'yablonsky-security' ) . '</strong><span>' . esc_html__( 'The bundle contains both server variants plus instructions. Verify deployment checks the shared marker URL, regardless of which supported server snippet you deployed.', 'yablonsky-security' ) . '</span></div><div class="ysec-fastpath-buttons"><a class="button" href="' . esc_url( $fast_export ) . '">' . esc_html__( 'Download both-server bundle', 'yablonsky-security' ) . '</a><form method="post" class="ysec-inline-form">';
        wp_nonce_field( 'ysec_fastpath_verify' );
        echo '<button class="button button-primary" name="ysec_fastpath_verify" value="1">' . esc_html__( 'Verify deployed fast path', 'yablonsky-security' ) . '</button></form></div></div></details>';
        echo '<details class="ysec-surface ysec-emergency-recovery"><summary><strong>' . esc_html__( 'Emergency access recovery', 'yablonsky-security' ) . '</strong> — ' . esc_html__( 'outside wp-admin', 'yablonsky-security' ) . '</summary><p>' . esc_html__( 'Three server-owner recovery paths preserve access from outside wp-admin.', 'yablonsky-security' ) . '</p><ol class="ysec-recovery-steps"><li><strong>WP-CLI</strong><div class="ysec-recovery-command"><code>wp ysec emergency-unblock --all</code></div></li><li><strong>wp-config.php</strong><div class="ysec-recovery-command"><code>define( &apos;YSEC_EMERGENCY_BYPASS&apos;, true );</code></div><small>' . esc_html__( 'This switch bypasses YSec MU and WordPress firewall enforcement. Clear the source block or add the trusted source, then remove the switch.', 'yablonsky-security' ) . '</small></li><li><strong>' . esc_html__( 'Filesystem fallback', 'yablonsky-security' ) . '</strong><div class="ysec-recovery-command"><code>wp-content/plugins/yablonsky-security → yablonsky-security.disabled</code></div><small>' . esc_html__( 'Renaming the canonical plugin folder places the managed MU loader in standby and restores access for recovery.', 'yablonsky-security' ) . '</small></li></ol><p class="description">' . esc_html__( 'Dynamic source blocks live in YSec. Manually deployed Nginx/Apache Fast Path rules contain static probe protections and remain a separate server layer.', 'yablonsky-security' ) . '</p></details>';
        self::shell_start( 'firewall_blocks', false );
        echo '<div class="ysec-section-intro ysec-monitor-secondary-intro"><h3>' . esc_html__( 'Active source blocks', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'This list contains explicit full-source temporary blocks. In the default smart model, YSec can deny a harmful request while preserving safe public access from the same source, so an empty list can coexist with active request-level protection.', 'yablonsky-security' ) . '</p></div>';
        echo '<div class="ysec-filter-grid">';
        self::search_control( __( 'Search blocks', 'yablonsky-security' ) );
        self::reset_control();
        echo '</div>';
        self::hidden_sort( 'expires_at', 'ASC' );
        echo '<div class="ysec-table-result ysec-lazy-result" data-ysec-initial-load="1"><div class="ysec-inline-loader"><span class="spinner is-active"></span><span>' . esc_html__( 'Loading active blocks…', 'yablonsky-security' ) . '</span></div></div>';
        self::shell_end( false );
        self::shell_end();
    }

    public static function vulnerabilities(): void {
        self::shell_start( 'vulnerabilities' );
        $inventory = YSEC_Vulnerabilities::inventory();
        $flat      = self::flatten_inventory( $inventory );
        $updates   = count( array_filter( $flat, static fn( $row ) => 'update' === $row['status'] ) );
        echo '<div class="ysec-section-intro ysec-monitor-intro"><h2>' . esc_html__( 'Software exposure', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'Nothing on this screen needs to be copied or pasted. It is an inventory of the WordPress core, plugins and themes installed on this site, showing installed versions and available updates. Security advisory data can be added by a compatible vulnerability intelligence provider without changing the core engine.', 'yablonsky-security' ) . '</p></div>';
        echo '<div class="ysec-grid ysec-grid-3 ysec-monitor-summary">';
        self::stat_card( __( 'Components', 'yablonsky-security' ), count( $flat ) );
        self::stat_card( __( 'Updates available', 'yablonsky-security' ), $updates );
        self::stat_card( __( 'Intelligence source', 'yablonsky-security' ), __( 'Local inventory', 'yablonsky-security' ), true );
        echo '</div>';
        echo '<div class="notice notice-info inline ysec-inline-notice"><p>' . esc_html__( 'An available update is exposure information, not proof that a component is vulnerable or compromised. Known-vulnerability status is shown only when an intelligence provider supplies evidence.', 'yablonsky-security' ) . '</p></div>';
        $local_advisories = YSEC_Advisories::items();
        // translators: %d: local advisory records.
        $local_advisory_count = sprintf( __( '%d validated records', 'yablonsky-security' ), count( $local_advisories ) );
        echo '<details class="ysec-surface ysec-advisory-store"><summary><strong>' . esc_html__( 'Local vulnerability intelligence', 'yablonsky-security' ) . '</strong> — ' . esc_html( $local_advisory_count ) . '</summary><form method="post">';
        wp_nonce_field( 'ysec_advisory_store' );
        echo '<label class="ysec-field"><span>' . esc_html__( 'Advisory JSON', 'yablonsky-security' ) . '</span><textarea rows="8" name="ysec_advisory_json" placeholder="{ &quot;advisories&quot;: [ ... ] }"></textarea><small>' . esc_html__( 'Import a schema-validated local advisory feed without making YSec depend on an external service. Existing records are replaced only after validation.', 'yablonsky-security' ) . '</small></label><p><button class="button button-primary" name="ysec_advisory_import" value="1">' . esc_html__( 'Validate & import advisories', 'yablonsky-security' ) . '</button> <button class="button" name="ysec_advisory_clear" value="1">' . esc_html__( 'Clear local intelligence', 'yablonsky-security' ) . '</button></p></form></details>';
        $enabled_patches = YSEC_Virtual_Patches::enabled();
        if ( $local_advisories ) {
            echo '<section class="ysec-surface"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Guarded virtual patching', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Advisory-linked request containment', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Only exact-path or path-prefix rules from the validated local advisory store are eligible. Enabling a patch is an explicit administrator action and can be reversed.', 'yablonsky-security' ) . '</p></div></div><div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Advisory', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Severity', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Patch rule', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'State', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Action', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
            foreach ( $local_advisories as $advisory ) {
                $id = (string) ( $advisory['id'] ?? '' );
                $patch = is_array( $advisory['virtual_patch'] ?? null ) ? $advisory['virtual_patch'] : array();
                $enabled = isset( $enabled_patches[$id] );
                echo '<tr><td><strong>' . esc_html( $id ) . '</strong><br><small>' . esc_html( (string) ( $advisory['title'] ?? '' ) ) . '</small></td><td>' . wp_kses_post( self::badge( (string) ( $advisory['severity'] ?? 'info' ) ) ) . '</td><td>' . ( $patch ? '<code>' . esc_html( (string)$patch['mode'] . ': ' . (string)$patch['path'] ) . '</code>' : '<span class="ysec-muted">' . esc_html__( 'No safe request rule', 'yablonsky-security' ) . '</span>' ) . '</td><td><span class="ysec-badge ysec-badge-' . esc_attr( $enabled ? 'low' : 'info' ) . '">' . esc_html( $enabled ? __( 'Enabled', 'yablonsky-security' ) : __( 'Off', 'yablonsky-security' ) ) . '</span></td><td>';
                if ( $patch ) {
                    echo '<form method="post" class="ysec-inline-form">'; wp_nonce_field( 'ysec_virtual_patch_' . $id ); echo '<input type="hidden" name="advisory_id" value="' . esc_attr( $id ) . '"><button class="button button-small" name="' . esc_attr( $enabled ? 'ysec_virtual_patch_disable' : 'ysec_virtual_patch_enable' ) . '" value="1">' . esc_html( $enabled ? __( 'Disable patch', 'yablonsky-security' ) : __( 'Enable patch', 'yablonsky-security' ) ) . '</button></form>';
                }
                echo '</td></tr>';
            }
            echo '</tbody></table></div></section>';
        }
        echo '<div class="ysec-filter-grid ysec-monitor-controls">';
        self::search_control( __( 'Search components', 'yablonsky-security' ) );
        self::select_control( 'type', __( 'Component type', 'yablonsky-security' ), array( '' => __( 'All types', 'yablonsky-security' ), 'core' => __( 'WordPress core', 'yablonsky-security' ), 'plugin' => __( 'Plugin', 'yablonsky-security' ), 'theme' => __( 'Theme', 'yablonsky-security' ) ) );
        self::select_control( 'status', __( 'Update status', 'yablonsky-security' ), array( '' => __( 'All statuses', 'yablonsky-security' ), 'update' => __( 'Update available', 'yablonsky-security' ), 'current' => __( 'No update reported', 'yablonsky-security' ) ) );
        self::reset_control();
        echo '</div>';
        self::hidden_sort( 'name', 'ASC' );
        echo '<div class="ysec-table-result ysec-lazy-result ysec-monitor-result" data-ysec-initial-load="1"><div class="ysec-inline-loader"><span class="spinner is-active"></span><span>' . esc_html__( 'Loading software inventory…', 'yablonsky-security' ) . '</span></div></div>';
        self::shell_end();
    }

    public static function accounts(): void {
        self::shell_start( 'accounts' );
        $enabled_2fa = YSEC_Login::enabled_count();
        $auth = YSEC_Login::auth_summary( 24 );
        $profile_url = get_edit_profile_url( get_current_user_id() );
        echo '<div class="ysec-section-intro ysec-monitor-intro"><h2>' . esc_html__( 'Account & session security', 'yablonsky-security' ) . '</h2><p>' . esc_html__( 'The login-page security-code field belongs to Yablonsky Security TOTP two-factor authentication. It is shown only while at least one account has Yablonsky Security 2FA enabled. Setup, recovery codes and disable/regenerate controls live in the WordPress user profile.', 'yablonsky-security' ) . '</p></div>';
        /* translators: %d: number of WordPress accounts with Yablonsky Security 2FA enabled. */
        $protected_accounts_label = sprintf( __( '%d account(s) protected by Yablonsky 2FA', 'yablonsky-security' ), $enabled_2fa );
        echo '<div class="ysec-policy-strip"><span class="ysec-status-badge ' . ( $enabled_2fa ? 'ysec-status-pass' : 'ysec-status-neutral' ) . '">' . esc_html( $protected_accounts_label ) . '</span><a class="button" href="' . esc_url( $profile_url ) . '#ysec-two-factor-authentication">' . esc_html__( 'Configure my 2FA', 'yablonsky-security' ) . '</a></div>';
        echo '<div class="ysec-grid ysec-grid-4 ysec-auth-summary ysec-monitor-summary">';
        self::stat_card( __( 'Successful logins · 24h', 'yablonsky-security' ), $auth['success'] );
        self::stat_card( __( 'Failed verification · 24h', 'yablonsky-security' ), $auth['failed'] );
        self::stat_card( __( 'Rate-limited · 24h', 'yablonsky-security' ), $auth['rate_limited'] );
        self::stat_card( __( '2FA failures · 24h', 'yablonsky-security' ), $auth['second_factor_failed'] );
        echo '</div>';
        $access = YSEC_Firewall_Policy::settings();
        echo '<details class="ysec-surface ysec-access-policy-card"><summary><strong>' . esc_html__( 'Access policy', 'yablonsky-security' ) . '</strong> — ' . esc_html__( 'trusted login networks, honeypot and registration approval', 'yablonsky-security' ) . '</summary><form method="post">';
        wp_nonce_field( 'ysec_firewall_policy' );
        echo '<input type="hidden" name="policy_scope" value="access"><label class="ysec-toggle-row"><span><strong>' . esc_html__( 'Restrict logins to trusted networks', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'When enabled, wp-login/Woo authentication is accepted only from the IPs or CIDRs below. Current administrator self-lockout is rejected when saving.', 'yablonsky-security' ) . '</small></span><span class="ysec-switch"><input type="checkbox" name="ysec_policy[login_allowlist_enabled]" value="1" ' . checked( ! empty( $access['login_allowlist_enabled'] ), true, false ) . '><i aria-hidden="true"></i></span></label><label class="ysec-field"><span>' . esc_html__( 'Trusted login IPs / CIDRs', 'yablonsky-security' ) . '</span><textarea rows="5" name="ysec_policy[login_allowlist]">' . esc_textarea( (string) $access['login_allowlist'] ) . '</textarea></label><label class="ysec-toggle-row"><span><strong>' . esc_html__( 'Login & registration honeypot', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'Add an off-screen bot trap to WordPress and WooCommerce authentication/registration forms.', 'yablonsky-security' ) . '</small></span><span class="ysec-switch"><input type="checkbox" name="ysec_policy[login_honeypot]" value="1" ' . checked( ! empty( $access['login_honeypot'] ), true, false ) . '><i aria-hidden="true"></i></span></label><label class="ysec-toggle-row"><span><strong>' . esc_html__( 'Require approval for public registrations', 'yablonsky-security' ) . '</strong><small>' . esc_html__( 'New public accounts remain unable to authenticate until an administrator approves them in this Accounts table.', 'yablonsky-security' ) . '</small></span><span class="ysec-switch"><input type="checkbox" name="ysec_policy[registration_approval]" value="1" ' . checked( ! empty( $access['registration_approval'] ), true, false ) . '><i aria-hidden="true"></i></span></label><p><button class="button button-primary" name="ysec_save_firewall_policy" value="1">' . esc_html__( 'Save access policy', 'yablonsky-security' ) . '</button></p></form></details>';
        echo '<div class="ysec-section-intro ysec-account-directory-intro ysec-monitor-secondary-intro"><h3>' . esc_html__( 'User directory', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Filter WordPress accounts by role, active-session presence, two-factor protection and containment state. Review signals are advisory only: an unusual username by itself never locks or labels an account as malicious.', 'yablonsky-security' ) . '</p></div>';
        self::job_panel();
        $role_options = array( '' => __( 'All roles', 'yablonsky-security' ) );
        foreach ( wp_roles()->roles as $role_key => $role_data ) {
            $role_options[ (string) $role_key ] = translate_user_role( (string) ( $role_data['name'] ?? $role_key ) );
        }
        echo '<div class="ysec-filter-grid ysec-monitor-controls">';
        self::search_control( __( 'Search users', 'yablonsky-security' ) );
        self::select_control( 'role', __( 'Role', 'yablonsky-security' ), $role_options );
        self::select_control( 'session_status', __( 'Session status', 'yablonsky-security' ), array( '' => __( 'All sessions', 'yablonsky-security' ), 'active' => __( 'Has active session', 'yablonsky-security' ), 'none' => __( 'No active sessions', 'yablonsky-security' ) ) );
        self::select_control( 'two_factor', __( '2FA', 'yablonsky-security' ), array( '' => __( 'Any 2FA state', 'yablonsky-security' ), 'enabled' => __( '2FA enabled', 'yablonsky-security' ), 'disabled' => __( '2FA disabled', 'yablonsky-security' ) ) );
        self::select_control( 'account_state', __( 'Account state', 'yablonsky-security' ), array( '' => __( 'All account states', 'yablonsky-security' ), 'active' => __( 'Active', 'yablonsky-security' ), 'locked' => __( 'Locked', 'yablonsky-security' ), 'pending' => __( 'Awaiting approval', 'yablonsky-security' ) ) );
        self::reset_control();
        echo '</div>';
        self::hidden_sort( 'display_name', 'ASC' );
        self::account_bulk_toolbar();
        echo '<div class="ysec-table-result ysec-lazy-result ysec-monitor-result" data-ysec-initial-load="1"><div class="ysec-inline-loader"><span class="spinner is-active"></span><span>' . esc_html__( 'Loading WordPress accounts and sessions…', 'yablonsky-security' ) . '</span></div></div>';
        self::shell_end();
    }

    public static function integrity_result(): void {
        $result = get_transient( 'ysec_last_integrity' );
        $baseline = get_option( 'ysec_integrity_baseline', array() );
        $baseline_files = isset( $baseline['files'] ) && is_array( $baseline['files'] ) ? count( $baseline['files'] ) : 0;
        $baseline_created = (string) ( $baseline['created_at'] ?? '' );
        echo '<section class="ysec-surface ysec-integrity-subpanel"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Integrity state', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Trusted baseline & latest comparison', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'The baseline is the trusted reference. A scan compares current executable/application files against that reference and reports only drift.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $baseline_files ? 'ysec-status-pass' : 'ysec-status-attention' ) . '">' . esc_html( $baseline_files ? __( 'BASELINE READY', 'yablonsky-security' ) : __( 'BASELINE NEEDED', 'yablonsky-security' ) ) . '</span></div><div class="ysec-grid ysec-grid-3">';
        self::stat_card( __( 'Baseline files', 'yablonsky-security' ), $baseline_files );
        self::stat_card( __( 'Baseline created', 'yablonsky-security' ), $baseline_created ? self::local_datetime( $baseline_created ) : __( 'Not created', 'yablonsky-security' ), true );
        self::stat_card( __( 'Latest scan', 'yablonsky-security' ), is_array( $result ) && ! empty( $result['scanned_at'] ) ? self::local_datetime( (string) $result['scanned_at'] ) : __( 'Not run', 'yablonsky-security' ), true );
        echo '</div></section>';
        if ( ! is_array( $result ) ) {
            echo '<div class="ysec-empty-state ysec-integrity-empty"><h3>' . esc_html__( 'No integrity comparison yet', 'yablonsky-security' ) . '</h3><p>' . esc_html( $baseline_files ? __( 'The trusted baseline exists. Run an integrity scan when you want to compare current files against it.', 'yablonsky-security' ) : __( 'Create a trusted baseline after reviewing the site, then run a scan to find added, modified or missing files.', 'yablonsky-security' ) ) . '</p></div>';
            return;
        }
        if ( ! empty( $result['maintenance'] ) ) {
            echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Integrity scanning is temporarily paused while a software update is being reconciled.', 'yablonsky-security' ) . '</p></div>';
            return;
        }
        if ( ! empty( $result['needs_baseline'] ) ) {
            echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'No integrity baseline exists yet. Create a baseline before running comparisons.', 'yablonsky-security' ) . '</p></div>';
            return;
        }
        $changes = isset( $result['changes'] ) && is_array( $result['changes'] ) ? $result['changes'] : array();
        echo '<section class="ysec-surface ysec-integrity-subpanel"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Latest comparison', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Integrity scan result', 'yablonsky-security' ) . '</h3></div><span class="ysec-status-badge ' . esc_attr( $changes ? 'ysec-status-attention' : 'ysec-status-pass' ) . '">' . esc_html( $changes ? __( 'REVIEW DRIFT', 'yablonsky-security' ) : __( 'NO DRIFT', 'yablonsky-security' ) ) . '</span></div><div class="ysec-grid ysec-grid-3">';
        self::stat_card( __( 'Files checked', 'yablonsky-security' ), (int) ( $result['checked'] ?? 0 ) );
        self::stat_card( __( 'Changes found', 'yablonsky-security' ), count( $changes ) );
        self::stat_card( __( 'Scan state', 'yablonsky-security' ), $changes ? __( 'Review required', 'yablonsky-security' ) : __( 'No drift detected', 'yablonsky-security' ), true );
        echo '</div></section>';
        if ( ! $changes ) return;
        self::shell_start( 'integrity', false );
        echo '<div class="ysec-filter-grid ysec-monitor-controls">';
        self::search_control( __( 'Search changed files', 'yablonsky-security' ) );
        self::select_control( 'state', __( 'State', 'yablonsky-security' ), array( '' => __( 'All states', 'yablonsky-security' ), 'added' => __( 'Added', 'yablonsky-security' ), 'modified' => __( 'Modified', 'yablonsky-security' ), 'missing' => __( 'Missing', 'yablonsky-security' ) ) );
        self::reset_control();
        echo '</div>';
        self::hidden_sort( 'path', 'ASC' );
        echo '<div class="ysec-table-result ysec-monitor-result">' . self::result_html( 'integrity', array() ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        self::shell_end( false );
    }

    public static function malware_result(): void {
        $result = YSEC_Malware::latest_result();
        if ( ! is_array( $result ) || ! $result ) {
            echo '<div class="ysec-malware-findings-empty"><strong>' . esc_html__( 'Findings will appear here after the first completed scan.', 'yablonsky-security' ) . '</strong></div>';
            return;
        }
        if ( ! YSEC_Malware::result_has_current_coverage( $result ) ) {
            echo '<div class="notice notice-warning inline ysec-inline-notice"><p>' . esc_html__( 'This stored result came from the earlier bounded scanner. Run the current resumable scan to refresh the full wp-content scope.', 'yablonsky-security' ) . '</p></div>';
            echo '<div class="ysec-malware-findings-empty"><strong>' . esc_html__( 'Findings will appear here after the first completed scan.', 'yablonsky-security' ) . '</strong></div>';
            return;
        }

        $result = YSEC_Malware::normalize_result( $result );
        $findings = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
        $finding_count = (int) ( $result['finding_count'] ?? count( $findings ) );
        $confirmed_count = (int) ( $result['confirmed_count'] ?? 0 );
        $review_count = (int) ( $result['review_count'] ?? max( 0, $finding_count - $confirmed_count ) );
        $trusted_artifacts = isset( $result['trusted_artifacts'] ) && is_array( $result['trusted_artifacts'] ) ? $result['trusted_artifacts'] : array();
        $trusted_count = count( $trusted_artifacts );

        echo '<div class="ysec-section-intro ysec-malware-findings-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Response center', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Detection, review & containment', 'yablonsky-security' ) . '</h3>';
        if ( $finding_count > 0 ) {
            $finding_summary = sprintf( /* translators: 1: confirmed-malware count, 2: review-item count, 3: verified runtime-artifact count. */ __( '%1$d confirmed malware item(s); %2$d item(s) need origin review; %3$d verified runtime artifact(s) were excluded from malware response.', 'yablonsky-security' ), $confirmed_count, $review_count, $trusted_count );
            $finding_badge = $confirmed_count > 0 ? sprintf( /* translators: %d: confirmed malware count. */ __( '%d CONFIRMED', 'yablonsky-security' ), $confirmed_count ) : sprintf( /* translators: %d: review item count. */ __( '%d REVIEW', 'yablonsky-security' ), $review_count );
            echo '<p>' . esc_html( $finding_summary ) . '</p></div><span class="ysec-status-badge ysec-status-attention">' . esc_html( $finding_badge ) . '</span></div>';
        } elseif ( $trusted_count > 0 ) {
            echo '<p>' . esc_html( sprintf( /* translators: %d: verified runtime-artifact count. */ __( 'No malware findings remain. %d plugin-managed runtime artifact(s) matched a bounded safe format.', 'yablonsky-security' ), $trusted_count ) ) . '</p></div><span class="ysec-status-badge ysec-status-pass">' . esc_html__( 'VERIFIED', 'yablonsky-security' ) . '</span></div>';
        } else {
            echo '<p>' . esc_html__( 'The latest completed scan reports a clear wp-content scope across the active scanner layers.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-pass">' . esc_html__( 'CLEAR', 'yablonsky-security' ) . '</span></div>';
        }

        if ( ! empty( $result['truncated'] ) ) {
            echo '<div class="notice notice-warning inline ysec-inline-notice"><p>' . esc_html__( 'This stored result came from the earlier bounded scanner. Run the current resumable scan to refresh the full wp-content scope.', 'yablonsky-security' ) . '</p></div>';
        }
        if ( $trusted_artifacts ) {
            echo '<details class="ysec-verified-artifacts"><summary><strong>' . esc_html( sprintf( /* translators: %d: verified runtime-artifact count. */ __( 'Verified runtime artifacts (%d)', 'yablonsky-security' ), $trusted_count ) ) . '</strong> — ' . esc_html__( 'recognized by path plus bounded inert/runtime structure', 'yablonsky-security' ) . '</summary><div class="ysec-table-scroll ysec-bounded-record-list"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Path', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Owner', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Kind', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
            foreach ( array_slice( $trusted_artifacts, 0, 25 ) as $artifact ) {
                echo '<tr><td><code>' . esc_html( (string) ( $artifact['path'] ?? '' ) ) . '</code></td><td>' . esc_html( (string) ( $artifact['owner'] ?? '—' ) ) . '</td><td>' . esc_html( self::human_label( (string) ( $artifact['kind'] ?? 'verified_runtime' ) ) ) . '</td></tr>';
            }
            echo '</tbody></table></div>';
            if ( $trusted_count > 25 ) echo '<p class="description">' . esc_html( sprintf( /* translators: 1: visible artifact count, 2: total artifact count. */ __( 'Showing the first %1$d of %2$d verified artifacts. The full scan JSON remains the authority record.', 'yablonsky-security' ), 25, $trusted_count ) ) . '</p>';
            echo '</details>';
        }
        if ( 0 === $finding_count ) return;

        self::shell_start( 'malware', false );
        echo '<div class="ysec-filter-grid ysec-monitor-controls">';
        self::search_control( __( 'Search findings', 'yablonsky-security' ) );
        self::select_control( 'classification', __( 'Classification', 'yablonsky-security' ), array( '' => __( 'All classifications', 'yablonsky-security' ), 'confirmed' => __( 'Confirmed malware', 'yablonsky-security' ), 'review' => __( 'Needs review', 'yablonsky-security' ) ) );
        self::select_control( 'severity', __( 'Severity', 'yablonsky-security' ), array( '' => __( 'All severities', 'yablonsky-security' ), 'critical' => __( 'Critical', 'yablonsky-security' ), 'high' => __( 'High', 'yablonsky-security' ), 'medium' => __( 'Medium', 'yablonsky-security' ), 'low' => __( 'Low', 'yablonsky-security' ) ) );
        self::reset_control();
        echo '</div>';
        self::hidden_sort( 'severity', 'DESC' );
        echo '<div class="ysec-table-result ysec-monitor-result">' . self::result_html( 'malware', array() ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        self::shell_end( false );
    }

    public static function result_html( string $dataset, array $args ): string {
        ob_start();
        switch ( $dataset ) {
            case 'events': self::events_result( $args ); break;
            case 'recon': self::recon_result( $args ); break;
            case 'firewall_actions': self::firewall_actions_result( $args ); break;
            case 'firewall_blocks': self::firewall_blocks_result( $args ); break;
            case 'firewall_analytics': self::firewall_analytics_result( $args ); break;
            case 'vulnerabilities': self::vulnerabilities_result( $args ); break;
            case 'integrity': self::integrity_table_result( $args ); break;
            case 'malware': self::malware_table_result( $args ); break;
            case 'accounts': self::accounts_result( $args ); break;
            default: return '';
        }
        return (string) ob_get_clean();
    }

    /**
     * The three monitor surfaces have independent, invariant column geometry.
     * Native <details> expansion must only change row height, not redistribute
     * table columns. The containing .ysec-table-scroll owns horizontal overflow.
     * Each declared width totals the matching CSS minimum width.
     */
    private static function fixed_evidence_cols( string $surface ): void {
        $widths = array(
            'events'           => array( 38, 136, 142, 58, 100, 150, 105, 460, 88, 180 ),
            'recon'            => array( 38, 94, 136, 90, 100, 136, 136, 250, 290, 170 ),
            'firewall_actions' => array( 38, 136, 112, 165, 60, 70, 470, 94, 230 ),
        );
        if ( ! isset( $widths[ $surface ] ) ) {
            return;
        }
        echo '<colgroup>';
        foreach ( $widths[ $surface ] as $width ) {
            echo '<col style="width:' . esc_attr( (string) $width ) . 'px">';
        }
        echo '</colgroup>';
    }

    private static function events_result( array $args ): void {
        self::threat_analytics( YSEC_Events::analytics_range( $args, 'events' ), __( 'Event activity', 'yablonsky-security' ) );
        $r = YSEC_Events::query( $args );
        self::result_meta( $r['total'], $r['page'], $r['per_page'] );
        self::pagination( $r['total'], $r['page'], $r['per_page'], true );
        self::bulk_toolbar( 'events' );
        $blocked_hashes=YSEC_Firewall::blocked_hashes(array_column($r['rows'],'source_hash'));
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table ysec-evidence-fixed ysec-evidence-events">';
        self::fixed_evidence_cols( 'events' );
        echo '<thead><tr><th class="check-column"><input type="checkbox" data-ysec-select-all></th>';
        self::th( __( 'Time', 'yablonsky-security' ), 'observed_at', $args, 'events' );
        self::th( __( 'Event', 'yablonsky-security' ), 'type', $args, 'events' );
        self::th( __( 'Hits', 'yablonsky-security' ), 'hit_count', $args, 'events' );
        self::th( __( 'Severity', 'yablonsky-security' ), 'severity', $args, 'events' );
        self::th( __( 'Family', 'yablonsky-security' ), 'family', $args, 'events' );
        self::th( __( 'State', 'yablonsky-security' ), 'state', $args, 'events' );
        echo '<th>' . esc_html__( 'Source / forensics', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Evidence', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Response', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $r['rows'] as $row ) {
            $evidence = ! empty( $row['archived'] ) ? __( 'Archived', 'yablonsky-security' ) : ( ! empty( $row['reviewed'] ) ? __( 'Reviewed', 'yablonsky-security' ) : __( 'Open', 'yablonsky-security' ) );
            $can_respond = ! empty( $row['source_hash'] ) && in_array( $row['state'], array( 'suspicious', 'blocked' ), true );
            $is_blocked=$can_respond && isset($blocked_hashes[$row['source_hash']]);
            $response=$can_respond ? '<button type="button" class="button button-small ' . ( $is_blocked ? 'ysec-unblock-source' : 'button-primary ysec-block-source' ) . '" data-source-hash="' . esc_attr( $row['source_hash'] ) . '" data-family="' . esc_attr( $row['family'] ) . '">' . esc_html( $is_blocked ? __( 'Unblock source', 'yablonsky-security' ) : __( 'Full block source', 'yablonsky-security' ) ) . '</button>' : '—';
            echo '<tr><th class="check-column"><input type="checkbox" value="' . esc_attr( (string) $row['id'] ) . '" data-ysec-event-id></th><td>' . esc_html( self::local_datetime( $row['observed_at'] ) ) . '</td><td>' . esc_html( self::human_label( $row['type'] ) ) . '</td><td>' . esc_html( (string) max( 1, (int) ( $row['hit_count'] ?? 1 ) ) ) . '</td><td>' . wp_kses_post( self::badge( $row['severity'] ) ) . '</td><td>' . esc_html( self::human_label( $row['family'] ) ) . '</td><td>' . wp_kses_post( self::badge( $row['state'] ) ) . '</td><td>' . wp_kses_post( self::forensic_details( $row ) ) . '</td><td>' . esc_html( $evidence ) . '</td><td>' . wp_kses_post( $response ) . '</td></tr>';
        }
        if ( ! $r['rows'] ) echo '<tr><td colspan="10" class="ysec-empty-cell">' . esc_html__( 'No security events match these filters.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        self::pagination( $r['total'], $r['page'], $r['per_page'] );
    }

    private static function recon_result( array $args ): void {
        if ( empty( $args['date_from'] ) ) $args['date_from'] = wp_date( 'Y-m-d', time() - 6 * DAY_IN_SECONDS );
        if ( empty( $args['date_to'] ) ) $args['date_to'] = wp_date( 'Y-m-d' );
        self::threat_analytics( YSEC_Events::analytics_range( $args, 'recon' ), __( 'Reconnaissance pressure', 'yablonsky-security' ) );
        $r = YSEC_Events::campaigns_query( $args );
        $blocked_hashes=YSEC_Firewall::blocked_hashes(array_column($r['rows'],'source_hash'));
        self::result_meta( $r['total'], $r['page'], $r['per_page'] );
        self::pagination( $r['total'], $r['page'], $r['per_page'], true );
        self::bulk_toolbar( 'recon' );
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table ysec-evidence-fixed ysec-evidence-recon">';
        self::fixed_evidence_cols( 'recon' );
        echo '<thead><tr><th class="manage-column check-column"><input type="checkbox" data-ysec-select-all></th>';
        self::th( __( 'Risk', 'yablonsky-security' ), 'risk', $args, 'recon' );
        self::th( __( 'Family', 'yablonsky-security' ), 'family', $args, 'recon' );
        self::th( __( 'Requests', 'yablonsky-security' ), 'requests', $args, 'recon' );
        self::th( __( 'Unique paths', 'yablonsky-security' ), 'paths', $args, 'recon' );
        self::th( __( 'First seen', 'yablonsky-security' ), 'first_seen', $args, 'recon' );
        self::th( __( 'Last seen', 'yablonsky-security' ), 'last_seen', $args, 'recon' );
        echo '<th>' . esc_html__( 'Source / forensics', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Meaning', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Action', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $r['rows'] as $row ) {
            $risk = self::risk_label( (int) $row['risk'] );$is_blocked=isset($blocked_hashes[$row['source_hash']]);
            $response_label=$is_blocked?__('Unblock source','yablonsky-security'):__('Full block source','yablonsky-security');$response_class=$is_blocked?'ysec-unblock-source':'ysec-block-source';
            echo '<tr><th class="check-column"><input type="checkbox" data-ysec-campaign data-source-hash="' . esc_attr( $row['source_hash'] ) . '" data-family="' . esc_attr( $row['family'] ) . '"></th><td>' . wp_kses_post( self::badge( strtolower( $risk ) ) ) . '</td><td>' . esc_html( self::human_label( $row['family'] ) ) . '</td><td>' . esc_html( (string) $row['requests'] ) . '</td><td>' . esc_html( (string) $row['paths'] ) . '</td><td>' . esc_html( self::local_datetime( $row['first_seen'] ) ) . '</td><td>' . esc_html( self::local_datetime( $row['last_seen'] ) ) . '</td><td>' . wp_kses_post( self::forensic_details( $row, true ) ) . '</td><td>' . esc_html( self::campaign_explanation( (string)$row['family'],(int)$row['risk'] ) ) . '</td><td class="ysec-row-actions"><button type="button" class="button button-small ' . esc_attr( $is_blocked ? $response_class : 'button-primary ' . $response_class ) . '" data-source-hash="' . esc_attr( $row['source_hash'] ) . '" data-family="' . esc_attr( $row['family'] ) . '">' . esc_html($response_label) . '</button><button type="button" class="button button-small ysec-archive-campaign" data-source-hash="' . esc_attr( $row['source_hash'] ) . '" data-family="' . esc_attr( $row['family'] ) . '">' . esc_html__( 'Archive', 'yablonsky-security' ) . '</button></td></tr>';
        }
        if ( ! $r['rows'] ) echo '<tr><td colspan="10" class="ysec-empty-cell">' . esc_html__( 'No reconnaissance campaigns match these filters.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        self::pagination( $r['total'], $r['page'], $r['per_page'] );
    }

    private static function firewall_actions_result( array $args ): void {
        $args['enforcement_only'] = 1;
        if ( empty( $args['date_from'] ) ) $args['date_from'] = wp_date( 'Y-m-d', time() - 6 * DAY_IN_SECONDS );
        if ( empty( $args['date_to'] ) ) $args['date_to'] = wp_date( 'Y-m-d' );

        self::threat_analytics( YSEC_Events::analytics_range( $args, 'firewall' ), __( 'Firewall enforcement', 'yablonsky-security' ) );
        $r = YSEC_Events::query( $args );
        $blocked_hashes = YSEC_Firewall::blocked_hashes( array_column( $r['rows'], 'source_hash' ) );
        self::result_meta( $r['total'], $r['page'], $r['per_page'] );
        self::pagination( $r['total'], $r['page'], $r['per_page'], true );
        self::bulk_toolbar( 'firewall_actions' );
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table ysec-monitor-table ysec-evidence-fixed ysec-evidence-firewall">';
        self::fixed_evidence_cols( 'firewall_actions' );
        echo '<thead><tr><th class="check-column"><input type="checkbox" data-ysec-select-all></th>';
        self::th( __( 'Time', 'yablonsky-security' ), 'observed_at', $args, 'firewall_actions' );
        self::th( __( 'Decision', 'yablonsky-security' ), 'state', $args, 'firewall_actions' );
        self::th( __( 'Family', 'yablonsky-security' ), 'family', $args, 'firewall_actions' );
        self::th( __( 'Hits', 'yablonsky-security' ), 'hit_count', $args, 'firewall_actions' );
        self::th( __( 'HTTP', 'yablonsky-security' ), 'status_code', $args, 'firewall_actions' );
        echo '<th>' . esc_html__( 'Source / forensics', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Evidence', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Response', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $r['rows'] as $row ) {
            $source_hash = (string) ( $row['source_hash'] ?? '' );
            $family = (string) ( $row['family'] ?? '' );
            $is_blocked = '' !== $source_hash && isset( $blocked_hashes[ $source_hash ] );
            $detail_data = ! empty( $row['details'] ) ? json_decode( (string) $row['details'], true ) : array();
            $is_false_positive = is_array( $detail_data ) && 'false_positive' === (string) ( $detail_data['disposition'] ?? '' );
            $evidence = $is_false_positive ? __( 'False positive', 'yablonsky-security' ) : ( ! empty( $row['reviewed'] ) ? __( 'Reviewed', 'yablonsky-security' ) : __( 'Open', 'yablonsky-security' ) );
            // Keep containment distinct from evidence review and narrow request exceptions.
            $response = '<div class="ysec-row-actions ysec-response-actions">';
            if ( '' !== $source_hash ) {
                $response .= '<button type="button" class="button button-small ' . ( $is_blocked ? 'ysec-unblock-source' : 'button-primary ysec-block-source' ) . '" data-source-hash="' . esc_attr( $source_hash ) . '" data-family="' . esc_attr( $family ) . '">' . esc_html( $is_blocked ? __( 'Unblock source', 'yablonsky-security' ) : __( 'Full block source', 'yablonsky-security' ) ) . '</button>';
            }
            $advanced = '';
            $method_for_exception = strtoupper( (string) ( $row['method'] ?? '' ) );
            $path_for_exception = (string) ( $row['path'] ?? '' );
            if ( '' !== $method_for_exception && '' !== $path_for_exception && YSEC_Firewall_Policy::can_except_request( $family, $method_for_exception, $path_for_exception ) ) {
                $exception_active = YSEC_Firewall_Policy::request_exception_active( $method_for_exception, $path_for_exception );
                $advanced .= '<button type="button" class="button button-small ' . ( $exception_active ? 'ysec-remove-request-exception' : 'ysec-allow-request' ) . '" data-event-id="' . esc_attr( (string) $row['id'] ) . '">' . esc_html( $exception_active ? __( 'Remove exception', 'yablonsky-security' ) : __( 'Allow exact request', 'yablonsky-security' ) ) . '</button>';
            }
            if ( ! $is_false_positive ) {
                $advanced .= '<button type="button" class="button button-small ysec-false-positive-event" data-event-id="' . esc_attr( (string) $row['id'] ) . '">' . esc_html__( 'False positive', 'yablonsky-security' ) . '</button>';
            }
            if ( empty( $row['reviewed'] ) ) {
                $advanced .= '<button type="button" class="button button-small ysec-review-event" data-event-id="' . esc_attr( (string) $row['id'] ) . '">' . esc_html__( 'Mark reviewed', 'yablonsky-security' ) . '</button>';
            }
            if ( '' !== $advanced ) {
                $response .= '<details class="ysec-response-advanced"><summary class="button button-small">' . esc_html__( 'Advanced', 'yablonsky-security' ) . '</summary><div class="ysec-response-advanced-body">' . $advanced . '</div></details>';
            }
            $response .= '</div>';
            $status = (int) ( $row['status_code'] ?? 0 );
            echo '<tr><th class="check-column"><input type="checkbox" value="' . esc_attr( (string) $row['id'] ) . '" data-ysec-event-id></th><td>' . esc_html( self::local_datetime( (string) ( $row['last_seen_at'] ?: $row['observed_at'] ) ) ) . '</td><td>' . wp_kses_post( self::badge( (string) $row['state'] ) ) . '</td><td>' . esc_html( self::human_label( $family ) ) . '</td><td>' . esc_html( number_format_i18n( max( 1, (int) ( $row['hit_count'] ?? 1 ) ) ) ) . '</td><td><code>' . esc_html( $status ? (string) $status : '—' ) . '</code></td><td>' . wp_kses_post( self::forensic_details( $row ) ) . '</td><td>' . esc_html( $evidence ) . '</td><td>' . wp_kses_post( $response ) . '</td></tr>';
        }
        if ( ! $r['rows'] ) echo '<tr><td colspan="9" class="ysec-empty-cell">' . esc_html__( 'No denied or contained requests match these filters.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        echo '<p class="description ysec-firewall-decision-footnote">' . esc_html__( 'A historical request denial remains immutable evidence. “Unblock source” removes current full-source containment. “Allow exact request” creates a reversible method+path exception for automatic profile matching only. “False positive” and “Mark reviewed” change evidence disposition without erasing history.', 'yablonsky-security' ) . '</p>';
        self::pagination( $r['total'], $r['page'], $r['per_page'] );
    }

    private static function firewall_analytics_result( array $args ): void {
        if ( empty( $args['date_from'] ) ) $args['date_from'] = wp_date( 'Y-m-d', time() - 6 * DAY_IN_SECONDS );
        if ( empty( $args['date_to'] ) ) $args['date_to'] = wp_date( 'Y-m-d' );
        self::threat_analytics( YSEC_Events::analytics_range( $args, 'firewall' ), __( 'Firewall enforcement', 'yablonsky-security' ) );
    }

    private static function firewall_blocks_result( array $args ): void {
        $r = YSEC_Firewall::query_blocks( $args );
        self::result_meta( $r['total'], $r['page'], $r['per_page'] );
        self::pagination( $r['total'], $r['page'], $r['per_page'], true );
        self::firewall_bulk_toolbar();
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><th class="check-column"><input type="checkbox" data-ysec-select-all></th>';
        self::th( __( 'Source', 'yablonsky-security' ), 'source', $args, 'firewall_blocks' );
        self::th( __( 'Reason', 'yablonsky-security' ), 'reason', $args, 'firewall_blocks' );
        self::th( __( 'Expires', 'yablonsky-security' ), 'expires_at', $args, 'firewall_blocks' );
        echo '<th>' . esc_html__( 'Action', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $r['rows'] as $row ) {
            echo '<tr><th class="check-column"><input type="checkbox" value="' . esc_attr( (string) $row['id'] ) . '" data-ysec-block-id></th><td><code>' . esc_html( YSEC_Firewall::display_source( $row ) ) . '</code></td><td>' . esc_html( $row['reason'] ) . '</td><td>' . esc_html( self::local_datetime( $row['expires_at'] ) ) . '</td><td><form method="post" class="ysec-inline-form">';
            wp_nonce_field( 'ysec_unblock_' . $row['id'] );
            echo '<input type="hidden" name="block_id" value="' . esc_attr( $row['id'] ) . '"><button class="button" name="ysec_unblock" value="1">' . esc_html__( 'Unblock', 'yablonsky-security' ) . '</button></form></td></tr>';
        }
        if ( ! $r['rows'] ) echo '<tr><td colspan="5" class="ysec-empty-cell">' . esc_html__( 'No active blocks match this search.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        self::pagination( $r['total'], $r['page'], $r['per_page'] );
    }

    private static function forensic_details( array $row, bool $campaign = false ): string {
        $ip = '';
        if ( ! empty( $row['source_enc'] ) ) {
            $candidate = YSEC_Utils::decrypt( (string) $row['source_enc'] );
            if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) $ip = $candidate;
        }
        $source = '' !== $ip ? $ip : ( ! empty( $row['source_hash'] ) ? 'source:' . substr( (string) $row['source_hash'], 0, 12 ) : '—' );
        $country = ! empty( $row['country'] ) ? (string) $row['country'] : '—';
        $ua = ! empty( $row['user_agent'] ) ? (string) $row['user_agent'] : '—';
        $path = $campaign ? (string) ( $row['sample_path'] ?? '' ) : (string) ( $row['path'] ?? '' );
        $query = (string) ( $row['query_redacted'] ?? '' );
        $crawler = YSEC_Discovery_Interop::claimed_crawler( '—' === $ua ? '' : $ua );
        $crawler_trust = ! empty( $crawler['claimed'] ) ? 'unverified_claim' : '';
        $crawler_verifier = '';
        if ( ! $campaign && ! empty( $row['details'] ) ) {
            $decoded = json_decode( (string) $row['details'], true );
            if ( is_array( $decoded ) && ! empty( $decoded['crawler_claim'] ) && is_array( $decoded['crawler_claim'] ) ) {
                $crawler = array_merge( $crawler, $decoded['crawler_claim'] );
                $crawler_trust = sanitize_key( (string) ( $decoded['crawler_claim']['trust'] ?? $crawler_trust ) );
                $crawler_verifier = sanitize_key( (string) ( $decoded['crawler_claim']['verifier'] ?? '' ) );
            }
        }
        $crawler_suffix = ! empty( $crawler['claimed'] ) ? ' · ' . (string) $crawler['agent'] : '';
        $html = '<details class="ysec-forensics"><summary><code>' . esc_html( $source ) . '</code>' . ( '—' !== $country ? ' · ' . esc_html( $country ) : '' ) . esc_html( $crawler_suffix ) . '</summary><dl>';
        $html .= '<div><dt>' . esc_html__( 'IP / source', 'yablonsky-security' ) . '</dt><dd><code>' . esc_html( $source ) . '</code></dd></div>';
        $html .= '<div><dt>' . esc_html__( 'Country signal', 'yablonsky-security' ) . '</dt><dd>' . esc_html( $country ) . '</dd></div>';
        $html .= '<div><dt>' . esc_html__( 'User-Agent', 'yablonsky-security' ) . '</dt><dd><code>' . esc_html( $ua ) . '</code></dd></div>';
        if ( ! empty( $crawler['claimed'] ) ) {
            $trust_label = 'verified' === $crawler_trust ? __( 'Verified crawler identity', 'yablonsky-security' ) : __( 'Claimed crawler — not verified', 'yablonsky-security' );
            $verify_note = ( 'verified' === $crawler_trust && '' !== $crawler_verifier ) ? ' · ' . $crawler_verifier : '';
            if ( ! empty( $crawler['status'] ) && 'verified' !== (string) $crawler['status'] ) $verify_note .= ' · ' . sanitize_key( (string) $crawler['status'] );
            if ( ! empty( $crawler['method'] ) && 'none' !== (string) $crawler['method'] ) $verify_note .= ' · ' . sanitize_key( (string) $crawler['method'] );
            if ( ! empty( $crawler['checked_at'] ) ) $verify_note .= ' · ' . sanitize_text_field( (string) $crawler['checked_at'] );
            $html .= '<div><dt>' . esc_html__( 'Crawler identity', 'yablonsky-security' ) . '</dt><dd><strong>' . esc_html( (string) $crawler['agent'] ) . '</strong> · ' . esc_html( $trust_label . $verify_note ) . '<br><small>' . esc_html__( 'Crawler identity never overrides a harmful-request deny.', 'yablonsky-security' ) . '</small></dd></div>';
        }
        if ( '' !== $path ) $html .= '<div><dt>' . esc_html__( 'Path', 'yablonsky-security' ) . '</dt><dd><code>' . esc_html( $path ) . '</code></dd></div>';
        if ( '' !== $query ) $html .= '<div><dt>' . esc_html__( 'Query', 'yablonsky-security' ) . '</dt><dd><code>' . esc_html( $query ) . '</code></dd></div>';
        if ( ! $campaign ) {
            $html .= '<div><dt>' . esc_html__( 'Method / status', 'yablonsky-security' ) . '</dt><dd>' . esc_html( (string) ( $row['method'] ?? '—' ) ) . ' / ' . esc_html( (string) ( $row['status_code'] ?? '0' ) ) . '</dd></div>';
            $html .= '<div><dt>' . esc_html__( 'Request ID', 'yablonsky-security' ) . '</dt><dd><code>' . esc_html( (string) ( $row['request_id'] ?? '—' ) ) . '</code></dd></div>';
            $html .= '<div><dt>' . esc_html__( 'First / last seen', 'yablonsky-security' ) . '</dt><dd>' . esc_html( self::local_datetime( (string) ( $row['first_seen_at'] ?: $row['observed_at'] ) ) ) . ' → ' . esc_html( self::local_datetime( (string) ( $row['last_seen_at'] ?: $row['observed_at'] ) ) ) . '</dd></div>';
        }
        $html .= '</dl></details>';
        return $html;
    }

    public static function permissions_result(): void {
        $result = get_transient( 'ysec_last_permissions' );
        if ( ! is_array( $result ) ) $result = YSEC_Permissions::scan();
        $rows = is_array( $result['rows'] ?? null ) ? $result['rows'] : array();
        /* translators: %d: number of filesystem permission objects checked. */
        $checked_label = sprintf( __( '%d objects checked', 'yablonsky-security' ), (int) ( $result['checked'] ?? count( $rows ) ) );
        echo '<section class="ysec-surface ysec-integrity-subpanel"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Filesystem', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Critical file & directory permissions', 'yablonsky-security' ) . '</h3><p>' . esc_html__( 'Unsafe world-writable or executable file modes are highlighted. Stricter permissions are not weakened just to match a conventional recommendation.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . ( ! empty( $result['unsafe'] ) ? 'ysec-status-attention' : 'ysec-status-pass' ) . '">' . esc_html( $checked_label ) . '</span></div>';
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><th>' . esc_html__( 'Object', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Path', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Current', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Recommended', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Assessment', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $rows as $row ) {
            $unsafe = ! empty( $row['unsafe'] );
            echo '<tr><td><strong>' . esc_html( (string) $row['name'] ) . '</strong></td><td><code>' . esc_html( (string) $row['path'] ) . '</code></td><td><code>' . esc_html( (string) $row['current'] ) . '</code></td><td><code>' . esc_html( (string) $row['recommended'] ) . '</code></td><td><span class="ysec-badge ysec-badge-' . esc_attr( $unsafe ? 'high' : 'low' ) . '">' . esc_html( $unsafe ? __( 'Review / repair', 'yablonsky-security' ) : __( 'No action required', 'yablonsky-security' ) ) . '</span></td></tr>';
        }
        if ( ! $rows ) echo '<tr><td colspan="5">' . esc_html__( 'No filesystem targets are available for permission auditing.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div></section>';
    }

    private static function threat_analytics( array $analytics, string $title ): void {
        $days = is_array( $analytics['days'] ?? null ) ? $analytics['days'] : array();
        $primary_label = (string) ( $analytics['primary_label'] ?? __( 'Security hits', 'yablonsky-security' ) );
        $secondary_label = (string) ( $analytics['secondary_label'] ?? __( 'Blocked / contained', 'yablonsky-security' ) );
        $ratio_label = (string) ( $analytics['ratio_label'] ?? __( 'Response ratio', 'yablonsky-security' ) );
        $period_label = (string) ( $analytics['period_label'] ?? '' );
        $scope = (string) ( $analytics['scope'] ?? 'events' );
        $window_days = max( 1, (int) ( $analytics['window_days'] ?? count( $days ) ) );
        $primary_total = (int) ( $analytics['primary_total'] ?? 0 );
        $secondary_total = (int) ( $analytics['secondary_total'] ?? 0 );
        $ratio = (float) ( $analytics['ratio'] ?? 0.0 );
        $days_label = number_format_i18n( $window_days ) . ' ' . _n( 'day', 'days', $window_days, 'yablonsky-security' );

        $series_defs = array(
            'event-hits' => array(
                'key'    => 'event_hits',
                'label'  => __( 'Security event hits', 'yablonsky-security' ),
                'class'  => 'event-hits',
                'area'   => 'events' === $scope,
                'point'  => true,
                'legend' => 'is-event-hits',
                'active' => 'events' === $scope,
            ),
            'recon-hits' => array(
                'key'    => 'recon_hits',
                'label'  => __( 'Reconnaissance hits', 'yablonsky-security' ),
                'class'  => 'recon-hits',
                'area'   => 'recon' === $scope,
                'point'  => true,
                'legend' => 'is-recon-hits',
                'active' => 'recon' === $scope,
            ),
            'request-denies' => array(
                'key'    => 'request_denies',
                'label'  => __( 'Request denies', 'yablonsky-security' ),
                'class'  => 'request-denies',
                'area'   => 'firewall' === $scope,
                'point'  => true,
                'legend' => 'is-request-denies',
                'active' => 'firewall' === $scope,
            ),
            'source-containment' => array(
                'key'    => 'source_containment',
                'label'  => __( 'Source containment', 'yablonsky-security' ),
                'class'  => 'source-containment',
                'area'   => false,
                'point'  => true,
                'legend' => 'is-source-containment',
                'active' => 'firewall' === $scope,
            ),
        );

        $series_totals = array_fill_keys( array_keys( $series_defs ), 0 );
        $max_value = 1;
        foreach ( $days as $row ) {
            foreach ( $series_defs as $id => $def ) {
                $value = max( 0, (int) ( $row[ $def['key'] ] ?? 0 ) );
                $series_totals[ $id ] += $value;
                if ( ! empty( $def['active'] ) ) $max_value = max( $max_value, $value );
            }
        }
        // Give the visible series a little headroom while keeping low-volume charts readable.
        $scale_max = max( 1.0, $max_value * 1.08 );

        echo '<section class="ysec-threat-analytics ysec-threat-analytics-inline ysec-trend-analytics" data-ysec-chart-scope="' . esc_attr( $scope ) . '"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Threat analytics', 'yablonsky-security' ) . '</span><h3>' . esc_html( $title ) . '</h3><p>' . esc_html__( 'The chart follows date, family, severity and state/decision filters. Free-text search and record status apply to evidence rows only.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ysec-status-neutral">' . esc_html( $period_label ?: $days_label ) . '</span></div>';
        echo '<div class="ysec-threat-summary"><div><span>' . esc_html( $primary_label ) . '</span><strong>' . esc_html( number_format_i18n( $primary_total ) ) . '</strong></div><div><span>' . esc_html( $secondary_label ) . '</span><strong>' . esc_html( number_format_i18n( $secondary_total ) ) . '</strong></div><div><span>' . esc_html( $ratio_label ) . '</span><strong>' . esc_html( number_format_i18n( $ratio, 1 ) ) . '%</strong></div><div><span>' . esc_html__( 'Selected period', 'yablonsky-security' ) . '</span><strong>' . esc_html( $days_label ) . '</strong></div></div>';

        if ( $days ) {
            $left = 18.0;
            $right = 982.0;
            $top = 18.0;
            $baseline = 198.0;
            $plot_height = $baseline - $top;
            $count = count( $days );
            $series_points = array();
            foreach ( $series_defs as $id => $def ) $series_points[ $id ] = array();
            foreach ( $days as $index => $row ) {
                $x = 1 === $count ? ( $left + $right ) / 2 : $left + ( ( $right - $left ) * $index / ( $count - 1 ) );
                foreach ( $series_defs as $id => $def ) {
                    $value = max( 0, (int) ( $row[ $def['key'] ] ?? 0 ) );
                    $y = $baseline - ( $plot_height * $value / $scale_max );
                    $series_points[ $id ][] = array( $x, $y, $value, (string) ( $row['day'] ?? '' ) );
                }
            }

            $curve_tail = static function( array $points ): string {
                $count = count( $points );
                if ( $count < 2 ) return '';
                if ( 2 === $count ) {
                    return 'L ' . number_format( (float) $points[1][0], 2, '.', '' ) . ' ' . number_format( (float) $points[1][1], 2, '.', '' );
                }

                // Keep the graph faithful to the daily samples: use straight segments for
                // almost the entire path and round only a small neighbourhood around each
                // interior vertex. This removes hard angular joins without spline-style
                // flattening or overshoot across multiple days.
                $parts = array();
                for ( $i = 1; $i < $count - 1; $i++ ) {
                    $px = (float) $points[ $i - 1 ][0];
                    $py = (float) $points[ $i - 1 ][1];
                    $cx = (float) $points[ $i ][0];
                    $cy = (float) $points[ $i ][1];
                    $nx = (float) $points[ $i + 1 ][0];
                    $ny = (float) $points[ $i + 1 ][1];

                    $prev_dx = $cx - $px;
                    $prev_dy = $cy - $py;
                    $next_dx = $nx - $cx;
                    $next_dy = $ny - $cy;
                    $prev_len = sqrt( $prev_dx * $prev_dx + $prev_dy * $prev_dy );
                    $next_len = sqrt( $next_dx * $next_dx + $next_dy * $next_dy );
                    if ( $prev_len <= 0.0 || $next_len <= 0.0 ) {
                        $parts[] = 'L ' . number_format( $cx, 2, '.', '' ) . ' ' . number_format( $cy, 2, '.', '' );
                        continue;
                    }

                    $radius = min( 8.0, $prev_len * 0.20, $next_len * 0.20 );
                    $pre_x = $cx - ( $prev_dx / $prev_len ) * $radius;
                    $pre_y = $cy - ( $prev_dy / $prev_len ) * $radius;
                    $post_x = $cx + ( $next_dx / $next_len ) * $radius;
                    $post_y = $cy + ( $next_dy / $next_len ) * $radius;

                    $parts[] = 'L ' . number_format( $pre_x, 2, '.', '' ) . ' ' . number_format( $pre_y, 2, '.', '' );
                    $parts[] = 'Q ' . number_format( $cx, 2, '.', '' ) . ' ' . number_format( $cy, 2, '.', '' ) . ' '
                        . number_format( $post_x, 2, '.', '' ) . ' ' . number_format( $post_y, 2, '.', '' );
                }

                $last = $points[ $count - 1 ];
                $parts[] = 'L ' . number_format( (float) $last[0], 2, '.', '' ) . ' ' . number_format( (float) $last[1], 2, '.', '' );
                return implode( ' ', $parts );
            };
            $to_path = static function( array $points ) use ( $curve_tail ): string {
                if ( ! $points ) return '';
                return 'M ' . number_format( (float) $points[0][0], 2, '.', '' ) . ' ' . number_format( (float) $points[0][1], 2, '.', '' ) . ' ' . $curve_tail( $points );
            };
            $to_area = static function( array $points ) use ( $baseline, $curve_tail ): string {
                if ( ! $points ) return '';
                $last = $points[ count( $points ) - 1 ];
                return 'M ' . number_format( (float) $points[0][0], 2, '.', '' ) . ' ' . number_format( $baseline, 2, '.', '' )
                    . ' L ' . number_format( (float) $points[0][0], 2, '.', '' ) . ' ' . number_format( (float) $points[0][1], 2, '.', '' )
                    . ' ' . $curve_tail( $points )
                    . ' L ' . number_format( (float) $last[0], 2, '.', '' ) . ' ' . number_format( $baseline, 2, '.', '' )
                    . ' Z';
            };

            echo '<div class="ysec-trend-chart"><svg viewBox="0 0 1000 230" preserveAspectRatio="xMidYMid meet" role="img" data-ysec-baseline="198" data-ysec-top="18" aria-label="' . esc_attr( $title ) . '">';
            foreach ( array( 0.25, 0.5, 0.75, 1.0 ) as $fraction ) {
                $y = $baseline - $plot_height * $fraction;
                echo '<line class="ysec-trend-gridline" x1="18" y1="' . esc_attr( number_format( $y, 2, '.', '' ) ) . '" x2="982" y2="' . esc_attr( number_format( $y, 2, '.', '' ) ) . '"></line>';
            }
            foreach ( $series_defs as $id => $def ) {
                if ( empty( $def['area'] ) ) continue;
                $hidden = empty( $def['active'] ) ? ' is-series-hidden' : '';
                echo '<path class="ysec-trend-area ysec-trend-area-' . esc_attr( $def['class'] ) . esc_attr( $hidden ) . '" data-ysec-series="' . esc_attr( $id ) . '" data-ysec-series-role="area" d="' . esc_attr( $to_area( $series_points[ $id ] ) ) . '"></path>';
            }
            foreach ( $series_defs as $id => $def ) {
                $hidden = empty( $def['active'] ) ? ' is-series-hidden' : '';
                echo '<path class="ysec-trend-line ysec-trend-line-' . esc_attr( $def['class'] ) . esc_attr( $hidden ) . '" data-ysec-series="' . esc_attr( $id ) . '" data-ysec-series-role="line" data-ysec-points="' . esc_attr( wp_json_encode( array_map( static function( $point ) { return array( (float) $point[0], (int) $point[2] ); }, $series_points[ $id ] ) ) ) . '" d="' . esc_attr( $to_path( $series_points[ $id ] ) ) . '"></path>';
            }
            if ( $count <= 31 ) {
                foreach ( $series_defs as $id => $def ) {
                    if ( empty( $def['point'] ) ) continue;
                    $hidden = empty( $def['active'] ) ? ' is-series-hidden' : '';
                    foreach ( $series_points[ $id ] as $point ) {
                        $day_label = wp_date( 'M j', strtotime( $point[3] . ' 12:00:00 UTC' ) );
                        echo '<circle class="ysec-trend-point ysec-trend-point-' . esc_attr( $def['class'] ) . esc_attr( $hidden ) . '" data-ysec-series="' . esc_attr( $id ) . '" data-ysec-x="' . esc_attr( number_format( $point[0], 2, '.', '' ) ) . '" data-ysec-value="' . esc_attr( (string) (int) $point[2] ) . '" cx="' . esc_attr( number_format( $point[0], 2, '.', '' ) ) . '" cy="' . esc_attr( number_format( $point[1], 2, '.', '' ) ) . '" r="3"><title>' . esc_html( $day_label . ' · ' . $def['label'] . ': ' . number_format_i18n( $point[2] ) ) . '</title></circle>';
                    }
                }
            }
            echo '</svg><div class="ysec-trend-axis-labels">';
            if ( $count <= 7 ) {
                $label_indexes = range( 0, $count - 1 );
            } else {
                $label_indexes = array_values( array_unique( array( 0, (int) floor( ( $count - 1 ) * 0.25 ), (int) floor( ( $count - 1 ) * 0.5 ), (int) floor( ( $count - 1 ) * 0.75 ), $count - 1 ) ) );
            }
            foreach ( $label_indexes as $index ) {
                $day = (string) ( $days[ $index ]['day'] ?? '' );
                echo '<span>' . esc_html( $day ? wp_date( 'M j', strtotime( $day . ' 12:00:00 UTC' ) ) : '' ) . '</span>';
            }
            echo '</div></div>';
        } else {
            echo '<div class="ysec-empty-cell">' . esc_html__( 'No analytics data is available for the selected period.', 'yablonsky-security' ) . '</div>';
        }
        echo '<div class="ysec-chart-legend">';
        foreach ( $series_defs as $id => $def ) {
            $active = ! empty( $def['active'] );
            $series_total = (int) ( $series_totals[ $id ] ?? 0 );
            echo '<button type="button" class="ysec-chart-legend-item' . ( $active ? ' is-active' : '' ) . '" data-ysec-series-toggle="' . esc_attr( $id ) . '" aria-pressed="' . esc_attr( $active ? 'true' : 'false' ) . '" title="' . esc_attr( $def['label'] . ': ' . number_format_i18n( $series_total ) ) . '"><i class="' . esc_attr( $def['legend'] ) . '"></i><span>' . esc_html( $def['label'] . ' · ' . number_format_i18n( $series_total ) ) . '</span></button>';
        }
        echo '</div>';
        if ( ! empty( $analytics['clamped'] ) ) {
            echo '<p class="description">' . esc_html__( 'The requested period extends beyond retained compact analytics history; the chart starts at the oldest retained analytics day.', 'yablonsky-security' ) . '</p>';
        }
        echo '</section>';
    }

    private static function vulnerabilities_result( array $args ): void {
        $rows = self::flatten_inventory( YSEC_Vulnerabilities::inventory() );
        $search = trim( (string) ( $args['search'] ?? '' ) );
        $type = sanitize_key( (string) ( $args['type'] ?? '' ) );
        $status = sanitize_key( (string) ( $args['status'] ?? '' ) );
        $rows = array_values( array_filter( $rows, static function( $row ) use ( $search, $type, $status ) {
            if ( $type && $row['type'] !== $type ) return false;
            if ( $status && $row['status'] !== $status ) return false;
            if ( $search && false === stripos( $row['name'] . ' ' . $row['slug'] . ' ' . $row['version'] . ' ' . $row['update'], $search ) ) return false;
            return true;
        } ) );
        $order_map = array( 'name' => 'name', 'type' => 'type', 'version' => 'version', 'update' => 'update', 'status' => 'status' );
        $orderby = $order_map[ $args['orderby'] ?? '' ] ?? 'name';
        $order = 'DESC' === strtoupper( (string) ( $args['order'] ?? 'ASC' ) ) ? -1 : 1;
        usort( $rows, static fn( $a, $b ) => $order * strnatcasecmp( (string) $a[ $orderby ], (string) $b[ $orderby ] ) );
        $r = self::paginate_array( $rows, $args );
        self::result_meta( $r['total'], $r['page'], $r['per_page'] );
        self::pagination( $r['total'], $r['page'], $r['per_page'], true );
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr>';
        self::th( __( 'Type', 'yablonsky-security' ), 'type', $args, 'vulnerabilities' );
        self::th( __( 'Component', 'yablonsky-security' ), 'name', $args, 'vulnerabilities' );
        self::th( __( 'Installed version', 'yablonsky-security' ), 'version', $args, 'vulnerabilities' );
        self::th( __( 'Available version', 'yablonsky-security' ), 'update', $args, 'vulnerabilities' );
        self::th( __( 'Update exposure', 'yablonsky-security' ), 'status', $args, 'vulnerabilities' );
        echo '<th>' . esc_html__( 'Advisory evidence', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Site state', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $r['rows'] as $row ) {
            $advisory_markup = '<span class="ysec-muted">' . esc_html__( 'No provider match', 'yablonsky-security' ) . '</span>';
            if ( $row['advisories'] ) {
                /* translators: %d: number of vulnerability advisories matched to this component. */
                $advisory_label = sprintf( _n( '%d advisory', '%d advisories', $row['advisories'], 'yablonsky-security' ), $row['advisories'] );
                $advisory_markup = '<span class="ysec-badge ysec-badge-' . esc_attr( $row['advisory_severity'] ?: 'info' ) . '">' . esc_html( $advisory_label ) . '</span>';
            }
            echo '<tr><td>' . esc_html( self::human_label( $row['type'] ) ) . '</td><td><strong>' . esc_html( $row['name'] ) . '</strong><br><code class="ysec-muted-code">' . esc_html( $row['slug'] ) . '</code></td><td>' . esc_html( $row['version'] ?: '—' ) . '</td><td>' . esc_html( $row['update'] ?: '—' ) . '</td><td>' . ( 'update' === $row['status'] ? '<span class="ysec-badge ysec-badge-medium">' . esc_html__( 'Update available', 'yablonsky-security' ) . '</span>' : '<span class="ysec-badge ysec-badge-info">' . esc_html__( 'No update reported', 'yablonsky-security' ) . '</span>' ) . '</td><td>' . wp_kses_post( $advisory_markup ) . '</td><td>' . esc_html( $row['active'] ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static badge markup is escaped or sanitized above.
        }
        if ( ! $r['rows'] ) echo '<tr><td colspan="7" class="ysec-empty-cell">' . esc_html__( 'No components match these filters.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        self::pagination( $r['total'], $r['page'], $r['per_page'] );
    }

    private static function integrity_table_result( array $args ): void {
        $result = get_transient( 'ysec_last_integrity' );
        $rows = is_array( $result ) && isset( $result['changes'] ) && is_array( $result['changes'] ) ? $result['changes'] : array();
        $search = trim( (string) ( $args['search'] ?? '' ) );
        $state = sanitize_key( (string) ( $args['state'] ?? '' ) );
        $rows = array_values( array_filter( $rows, static function( $row ) use ( $search, $state ) {
            if ( $state && ( $row['state'] ?? '' ) !== $state ) return false;
            return ! $search || false !== stripos( (string) ( $row['path'] ?? '' ), $search );
        } ) );
        $order = 'DESC' === strtoupper( (string) ( $args['order'] ?? 'ASC' ) ) ? -1 : 1;
        usort( $rows, static fn( $a, $b ) => $order * strnatcasecmp( (string) ( $a['path'] ?? '' ), (string) ( $b['path'] ?? '' ) ) );
        $r = self::paginate_array( $rows, $args );
        self::result_meta( $r['total'], $r['page'], $r['per_page'] );
        self::pagination( $r['total'], $r['page'], $r['per_page'], true );
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr>';
        self::th( __( 'Path', 'yablonsky-security' ), 'path', $args, 'integrity' );
        echo '<th>' . esc_html__( 'State', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $r['rows'] as $row ) echo '<tr><td class="ysec-path"><code>' . esc_html( $row['path'] ) . '</code></td><td>' . wp_kses_post( self::badge( $row['state'] ) ) . '</td></tr>';
        if ( ! $r['rows'] ) echo '<tr><td colspan="2" class="ysec-empty-cell">' . esc_html__( 'No integrity changes match these filters.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        self::pagination( $r['total'], $r['page'], $r['per_page'] );
    }

    private static function malware_table_result( array $args ): void {
        $result = YSEC_Malware::latest_result();
        $rows = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
        $search = trim( (string) ( $args['search'] ?? '' ) );
        $severity = sanitize_key( (string) ( $args['severity'] ?? '' ) );
        $classification = sanitize_key( (string) ( $args['classification'] ?? '' ) );
        $rows = array_values( array_filter( $rows, static function( $row ) use ( $search, $severity, $classification ) {
            $row = is_array( $row ) ? YSEC_Malware::normalize_finding( $row ) : array();
            if ( $severity && ( $row['severity'] ?? '' ) !== $severity ) return false;
            if ( $classification && ( $row['classification'] ?? '' ) !== $classification ) return false;
            return ! $search || false !== stripos( (string) ( $row['path'] ?? '' ) . ' ' . (string) ( $row['rule'] ?? '' ) . ' ' . (string) ( $row['classification'] ?? '' ), $search );
        } ) );
        $rank = array( 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, 'info' => 0 );
        $orderby = sanitize_key( (string) ( $args['orderby'] ?? 'severity' ) );
        $order = 'ASC' === strtoupper( (string) ( $args['order'] ?? 'DESC' ) ) ? 1 : -1;
        usort( $rows, static function( $a, $b ) use ( $rank, $orderby, $order ) {
            if ( 'path' === $orderby ) return $order * strnatcasecmp( (string) $a['path'], (string) $b['path'] );
            if ( 'rule' === $orderby ) return $order * strnatcasecmp( (string) $a['rule'], (string) $b['rule'] );
            return $order * ( ( $rank[ $a['severity'] ] ?? 0 ) <=> ( $rank[ $b['severity'] ] ?? 0 ) );
        } );
        $r = self::paginate_array( $rows, $args );
        self::result_meta( $r['total'], $r['page'], $r['per_page'] );
        self::pagination( $r['total'], $r['page'], $r['per_page'], true );
        echo '<div class="ysec-table-scroll ysec-malware-findings-scroll"><table class="widefat striped ysec-data-table"><thead><tr>';
        echo '<th>' . esc_html__( 'Classification', 'yablonsky-security' ) . '</th>';
        self::th( __( 'Severity', 'yablonsky-security' ), 'severity', $args, 'malware' );
        self::th( __( 'Detection rule', 'yablonsky-security' ), 'rule', $args, 'malware' );
        self::th( __( 'Path', 'yablonsky-security' ), 'path', $args, 'malware' );
        echo '<th>' . esc_html__( 'Evidence', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Response', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $r['rows'] as $row ) {
            $row = YSEC_Malware::normalize_finding( $row );
            $class = (string) ( $row['classification'] ?? 'review' );
            $class_badge = 'confirmed' === $class ? '<span class="ysec-badge ysec-badge-high">' . esc_html__( 'Confirmed', 'yablonsky-security' ) . '</span>' : '<span class="ysec-badge ysec-badge-medium">' . esc_html__( 'Review', 'yablonsky-security' ) . '</span>';
            echo '<tr><td>' . wp_kses_post( $class_badge ) . '</td><td>' . wp_kses_post( self::badge( $row['severity'] ) ) . '</td><td>' . esc_html( self::human_label( $row['rule'] ) ) . '</td><td class="ysec-path"><code>' . esc_html( $row['path'] ) . '</code></td><td><small>' . esc_html( (string) ( $row['reason'] ?? '' ) ) . '</small><br><code>' . esc_html( substr( (string) ( $row['sha256'] ?? '' ), 0, 16 ) ) . '…</code><br><small>' . esc_html( size_format( (int) ( $row['size'] ?? 0 ) ) ) . '</small></td><td>';
            if ( 'confirmed' === $class ) {
                echo '<form method="post" class="ysec-inline-form">';
                wp_nonce_field( 'ysec_quarantine_file' );
                echo '<input type="hidden" name="finding_path" value="' . esc_attr( (string) $row['path'] ) . '"><input type="hidden" name="finding_rule" value="' . esc_attr( (string) ( $row['rule'] ?? '' ) ) . '"><input type="hidden" name="finding_reason" value="' . esc_attr( (string) ( $row['reason'] ?? '' ) ) . '"><input type="hidden" name="finding_sha256" value="' . esc_attr( (string) ( $row['sha256'] ?? '' ) ) . '"><button class="button button-small" name="ysec_quarantine_file" value="1" onclick="return confirm(this.dataset.confirm);" data-confirm="' . esc_attr__( 'Encrypt, verify and remove this confirmed file from its current location?', 'yablonsky-security' ) . '">' . esc_html__( 'Quarantine', 'yablonsky-security' ) . '</button></form>';
            } else {
                echo '<span class="ysec-muted">' . esc_html__( 'Review origin before containment', 'yablonsky-security' ) . '</span>';
            }
            echo '</td></tr>';
        }
        if ( ! $r['rows'] ) echo '<tr><td colspan="6" class="ysec-empty-cell">' . esc_html__( 'No malware findings match these filters.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        self::pagination( $r['total'], $r['page'], $r['per_page'] );
    }

    private static function accounts_result( array $args ): void {
        $page = max( 1, absint( $args['page'] ?? 1 ) );
        $per_page = max( 10, min( 100, absint( $args['per_page'] ?? 25 ) ?: 25 ) );
        $search = trim( (string) ( $args['search'] ?? '' ) );
        $role = sanitize_key( (string) ( $args['role'] ?? '' ) );
        $session_status = sanitize_key( (string) ( $args['session_status'] ?? '' ) );
        $two_factor = sanitize_key( (string) ( $args['two_factor'] ?? '' ) );
        $account_state = sanitize_key( (string) ( $args['account_state'] ?? '' ) );
        $orderby = in_array( $args['orderby'] ?? '', array( 'display_name', 'user_login', 'ID' ), true ) ? $args['orderby'] : 'display_name';
        $order = 'DESC' === strtoupper( (string) ( $args['order'] ?? 'ASC' ) ) ? 'DESC' : 'ASC';

        $account_filters = array(
            'search'=>$search,
            'role'=>$role,
            'session_status'=>$session_status,
            'two_factor'=>$two_factor,
            'account_state'=>$account_state,
            'orderby'=>$orderby,
            'order'=>$order,
        );
        $page_data = YSEC_Accounts::query_page( $account_filters, $page, $per_page );
        $total = (int) ( $page_data['total'] ?? 0 );
        $pages = max( 1, (int) ceil( $total / $per_page ) );
        $page = min( $page, $pages );
        if ( $page > 1 && empty( $page_data['ids'] ) && $total > 0 ) {
            $page_data = YSEC_Accounts::query_page( $account_filters, $page, $per_page );
        }
        $page_ids = (array) ( $page_data['ids'] ?? array() );
        $rows = array_values( array_filter( array_map( 'get_userdata', $page_ids ), static fn( $user ) => $user instanceof WP_User ) );

        self::result_meta( $total, $page, $per_page );
        self::pagination( $total, $page, $per_page, true );
        echo '<div class="ysec-table-scroll"><table class="widefat striped ysec-data-table"><thead><tr><td class="check-column"><input type="checkbox" data-ysec-select-all aria-label="' . esc_attr__( 'Select all visible users', 'yablonsky-security' ) . '"></td>';
        self::th( __( 'User', 'yablonsky-security' ), 'display_name', $args, 'accounts' );
        echo '<th>' . esc_html__( 'Roles', 'yablonsky-security' ) . '</th><th>' . esc_html__( '2FA', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Account state', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Review signal', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Sessions', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Latest session', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Last successful login', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Source / User-Agent', 'yablonsky-security' ) . '</th><th>' . esc_html__( 'Action', 'yablonsky-security' ) . '</th></tr></thead><tbody>';
        foreach ( $rows as $user ) {
            $enabled = (bool) get_user_meta( $user->ID, 'ysec_totp_secret', true );
            $sessions = self::active_sessions( $user->ID );
            $latest = array();
            foreach ( $sessions as $session ) if ( empty( $latest ) || (int) ( $session['login'] ?? 0 ) > (int) ( $latest['login'] ?? 0 ) ) $latest = $session;
            $roles = $user->roles ? implode( ', ', array_map( static fn( $r ) => ucwords( str_replace( '_', ' ', (string) $r ) ), $user->roles ) ) : '—';
            $latest_time = ! empty( $latest['login'] ) ? wp_date( 'Y-m-d H:i:s', (int) $latest['login'] ) : '—';
            $latest_ip = ! empty( $latest['ip'] ) ? YSEC_Utils::masked_ip( (string) $latest['ip'] ) : '—';
            $latest_ua = ! empty( $latest['ua'] ) ? YSEC_Utils::log_string( (string) $latest['ua'], 160 ) : '—';
            $last_login_at = absint( get_user_meta( $user->ID, 'ysec_last_login_at', true ) );
            $last_login_ip_enc = (string) get_user_meta( $user->ID, 'ysec_last_login_source', true );
            $last_login_ip = $last_login_ip_enc ? YSEC_Utils::masked_ip( YSEC_Utils::decrypt( $last_login_ip_enc ) ) : '—';
            $last_login_label = $last_login_at ? wp_date( 'Y-m-d H:i:s', $last_login_at ) : '—';
            $review_signal = self::account_review_signal( $user, $enabled, $last_login_at );
            $locked_until = absint( get_user_meta( $user->ID, 'ysec_account_locked_until', true ) );
            if ( $locked_until && $locked_until <= time() ) { delete_user_meta( $user->ID, 'ysec_account_locked_until' ); $locked_until = 0; }
            $pending_approval = (bool) get_user_meta( $user->ID, 'ysec_registration_pending', true );
            if ( $pending_approval ) $state_html = '<span class="ysec-badge ysec-badge-medium">' . esc_html__( 'Awaiting approval', 'yablonsky-security' ) . '</span>';
            elseif ( $locked_until ) $state_html = '<span class="ysec-badge ysec-badge-high">' . esc_html__( 'Locked', 'yablonsky-security' ) . '</span><br><small>' . esc_html( wp_date( 'Y-m-d H:i:s', $locked_until ) ) . '</small>';
            else $state_html = '<span class="ysec-badge ysec-badge-low">' . esc_html__( 'Active', 'yablonsky-security' ) . '</span>';
            // translators: %s: WordPress user display name.
            echo '<tr><th class="check-column"><input type="checkbox" value="' . esc_attr( (string) $user->ID ) . '" data-ysec-user-id aria-label="' . esc_attr( sprintf( __( 'Select %s', 'yablonsky-security' ), $user->display_name ) ) . '"></th><td><strong>' . esc_html( $user->display_name ) . '</strong><br><code>#' . esc_html( (string) $user->ID ) . ' · ' . esc_html( $user->user_login ) . '</code></td><td>' . esc_html( $roles ) . '</td><td>' . ( $enabled ? '<span class="ysec-badge ysec-badge-low">' . esc_html__( 'Enabled', 'yablonsky-security' ) . '</span>' : '<span class="ysec-badge ysec-badge-medium">' . esc_html__( 'Standby', 'yablonsky-security' ) . '</span>' ) . '</td><td>' . wp_kses_post( $state_html ) . '</td><td>' . wp_kses_post( $review_signal ) . '</td><td>' . esc_html( (string) count( $sessions ) ) . '</td><td>' . esc_html( $latest_time ) . '</td><td>' . esc_html( $last_login_label ) . '<br><code>' . esc_html( $last_login_ip ) . '</code></td><td><code>' . esc_html( $latest_ip ) . '</code><br><small>' . esc_html( $latest_ua ) . '</small></td><td><div class="ysec-inline-actions">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Review/badge markup is generated locally; all user/session data is escaped.
            $manage_url = get_edit_user_link( $user->ID );
            echo '<a class="button button-small" href="' . esc_url( $manage_url ) . '#ysec-two-factor-authentication">' . esc_html__( 'Manage 2FA', 'yablonsky-security' ) . '</a>';
            echo '<form method="post" class="ysec-inline-form">'; wp_nonce_field( 'ysec_revoke_sessions_' . $user->ID ); echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $user->ID ) . '"><button class="button button-small" name="ysec_revoke_sessions" value="1">' . esc_html__( 'Revoke sessions', 'yablonsky-security' ) . '</button></form>';
            if ( $pending_approval ) {
                echo '<form method="post" class="ysec-inline-form">'; wp_nonce_field( 'ysec_approve_registration_' . $user->ID ); echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $user->ID ) . '"><button class="button button-small button-primary" name="ysec_approve_registration" value="1">' . esc_html__( 'Approve', 'yablonsky-security' ) . '</button></form>';
            }
            if ( $locked_until ) {
                echo '<form method="post" class="ysec-inline-form">'; wp_nonce_field( 'ysec_account_unlock_' . $user->ID ); echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $user->ID ) . '"><button class="button button-small" name="ysec_unlock_account" value="1">' . esc_html__( 'Unlock', 'yablonsky-security' ) . '</button></form>';
            } elseif ( $user->ID !== get_current_user_id() ) {
                echo '<form method="post" class="ysec-inline-form">'; wp_nonce_field( 'ysec_account_lock_' . $user->ID ); echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $user->ID ) . '"><input type="hidden" name="lock_minutes" value="60"><button class="button button-small" name="ysec_lock_account" value="1">' . esc_html__( 'Lock 60m', 'yablonsky-security' ) . '</button></form>';
            }
            echo '</div></td></tr>';
        }
        if ( ! $rows ) echo '<tr><td colspan="11" class="ysec-empty-cell">' . esc_html__( 'No users match these filters.', 'yablonsky-security' ) . '</td></tr>';
        echo '</tbody></table></div>';
        self::pagination( $total, $page, $per_page );
    }

    private static function active_sessions( int $user_id ): array {
        $sessions = WP_Session_Tokens::get_instance( $user_id )->get_all();
        $now = time();
        return array_values( array_filter( $sessions, static fn( $session ) => ! empty( $session['expiration'] ) && (int) $session['expiration'] > $now ) );
    }

    private static function account_review_signal( WP_User $user, bool $two_factor, int $last_login_at ): string {
        if ( user_can( $user, 'manage_options' ) && ! $two_factor ) {
            return '<span class="ysec-badge ysec-badge-high">' . esc_html__( 'Review', 'yablonsky-security' ) . '</span><br><small>' . esc_html__( 'Privileged account without YSec 2FA.', 'yablonsky-security' ) . '</small>';
        }
        $login = (string) $user->user_login;
        $separator_count = preg_match_all( '/[._-]/', $login, $matches );
        if ( strlen( $login ) >= 16 && false !== $separator_count && $separator_count >= 5 ) {
            return '<span class="ysec-badge ysec-badge-info">' . esc_html__( 'Weak signal', 'yablonsky-security' ) . '</span><br><small>' . esc_html__( 'Unusual identifier pattern; review context before taking action.', 'yablonsky-security' ) . '</small>';
        }
        if ( 0 === $last_login_at && strtotime( (string) $user->user_registered ) >= time() - 7 * DAY_IN_SECONDS ) {
            return '<span class="ysec-badge ysec-badge-info">' . esc_html__( 'New account', 'yablonsky-security' ) . '</span><br><small>' . esc_html__( 'No successful login recorded yet.', 'yablonsky-security' ) . '</small>';
        }
        return '<span class="ysec-muted">' . esc_html__( 'No review signal', 'yablonsky-security' ) . '</span>';
    }

    private static function export_zone( string $dataset ): void {
        echo '<section class="ysec-export-zone">';
        self::dataset_actions( $dataset );
        self::job_panel();
        echo '</section>';
    }

    private static function dataset_actions( string $dataset ): void {
        echo '<div class="ysec-dataset-actions"><div><button type="button" class="button ysec-export-data" data-format="csv" data-dataset="' . esc_attr( $dataset ) . '">' . esc_html__( 'Export CSV', 'yablonsky-security' ) . '</button><button type="button" class="button ysec-export-data" data-format="json" data-dataset="' . esc_attr( $dataset ) . '">' . esc_html__( 'Export JSON', 'yablonsky-security' ) . '</button></div><span>' . esc_html__( 'Exports use the current filters and remove source fingerprints.', 'yablonsky-security' ) . '</span></div>';
    }

    private static function evidence_view_guide( string $current ): void {
        $items = array(
            'events'   => array( __( 'Events', 'yablonsky-security' ), __( 'Observe', 'yablonsky-security' ), __( 'Security records', 'yablonsky-security' ) ),
            'recon'    => array( __( 'Reconnaissance', 'yablonsky-security' ), __( 'Correlate', 'yablonsky-security' ), __( 'Related campaigns', 'yablonsky-security' ) ),
            'firewall' => array( __( 'Firewall', 'yablonsky-security' ), __( 'Respond', 'yablonsky-security' ), __( 'Denies and containment', 'yablonsky-security' ) ),
        );
        echo '<div class="ysec-evidence-flow" aria-label="' . esc_attr__( 'Security evidence flow', 'yablonsky-security' ) . '">';
        $index = 0;
        foreach ( $items as $key => $item ) {
            if ( $index > 0 ) echo '<span class="ysec-evidence-flow-arrow" aria-hidden="true">→</span>';
            echo '<div class="ysec-evidence-flow-step ' . esc_attr( $current === $key ? 'is-current' : '' ) . '"><span class="ysec-evidence-flow-kicker">' . esc_html( $item[1] ) . '</span><strong>' . esc_html( $item[0] ) . '</strong><small>' . esc_html( $item[2] ) . '</small></div>';
            $index++;
        }
        echo '</div>';
    }
    private static function job_panel(): void {
        echo '<div class="ysec-job-panel" data-ysec-job-panel hidden><div class="ysec-job-head"><strong data-ysec-job-label>' . esc_html__( 'Background job', 'yablonsky-security' ) . '</strong><span data-ysec-job-percent>0%</span></div><div class="ysec-job-track"><i data-ysec-job-bar style="width:0%"></i></div><div class="ysec-job-meta"><span data-ysec-job-count>0 / 0</span><span data-ysec-job-changed></span><span data-ysec-job-status></span></div><div class="ysec-job-actions"><button type="button" class="button button-small ysec-job-pause">' . esc_html__( 'Pause', 'yablonsky-security' ) . '</button><button type="button" class="button button-small ysec-job-resume" hidden>' . esc_html__( 'Resume', 'yablonsky-security' ) . '</button><button type="button" class="button button-small ysec-job-cancel" hidden>' . esc_html__( 'Cancel', 'yablonsky-security' ) . '</button><button type="button" class="button button-small ysec-job-dismiss" hidden>' . esc_html__( 'Dismiss', 'yablonsky-security' ) . '</button><a class="button button-primary button-small ysec-job-download" hidden>' . esc_html__( 'Download', 'yablonsky-security' ) . '</a></div></div>';
    }

    private static function bulk_toolbar( string $dataset='events' ): void {
        $block_label = 'firewall_actions' === $dataset ? __( 'Full-block selected sources', 'yablonsky-security' ) : __( 'Full-block suspicious sources', 'yablonsky-security' );
        echo '<div class="ysec-bulk-toolbar" data-ysec-bulk-dataset="' . esc_attr( $dataset ) . '"><select data-ysec-bulk-action><option value="">' . esc_html__( 'Bulk actions', 'yablonsky-security' ) . '</option><option value="block_sources">' . esc_html( $block_label ) . '</option><option value="unblock_sources">' . esc_html__( 'Unblock sources', 'yablonsky-security' ) . '</option>';
        if ( in_array( $dataset, array( 'events', 'firewall_actions' ), true ) ) echo '<option value="review">' . esc_html__( 'Mark reviewed', 'yablonsky-security' ) . '</option>';
        if ( 'firewall_actions' === $dataset ) echo '<option value="false_positive">' . esc_html__( 'Mark false positive', 'yablonsky-security' ) . '</option>';
        if ( 'events' === $dataset ) echo '<option value="archive">' . esc_html__( 'Archive', 'yablonsky-security' ) . '</option><option value="delete">' . esc_html__( 'Delete permanently', 'yablonsky-security' ) . '</option>';
        echo '</select><select data-ysec-bulk-scope><option value="selected">' . esc_html__( 'Selected rows', 'yablonsky-security' ) . '</option><option value="filtered">' . esc_html__( 'All matching results', 'yablonsky-security' ) . '</option></select><button type="button" class="button ysec-apply-bulk">' . esc_html__( 'Apply', 'yablonsky-security' ) . '</button><span class="ysec-whole-scope-actions"><button type="button" class="button button-primary ysec-protect-all">' . esc_html__( 'Full-block all matching sources', 'yablonsky-security' ) . '</button><button type="button" class="button ysec-unblock-all">' . esc_html__( 'Unblock all matching sources', 'yablonsky-security' ) . '</button></span><span class="description ysec-bulk-response-note">' . esc_html__( 'Full-source containment is an explicit administrator action. YSec preserves the current administrator source and durable allowlist, with server-owner recovery through WP-CLI, wp-config.php or the filesystem.', 'yablonsky-security' ) . '</span></div>';
    }
    private static function firewall_bulk_toolbar(): void {
        echo '<div class="ysec-bulk-toolbar ysec-firewall-bulk-toolbar" data-ysec-bulk-dataset="firewall_blocks"><select data-ysec-bulk-action><option value="">' . esc_html__( 'Bulk actions', 'yablonsky-security' ) . '</option><option value="unblock">' . esc_html__( 'Unblock selected', 'yablonsky-security' ) . '</option></select><button type="button" class="button ysec-apply-bulk">' . esc_html__( 'Apply', 'yablonsky-security' ) . '</button><span class="description">' . esc_html__( 'Bulk actions apply to selected active source-block rows only.', 'yablonsky-security' ) . '</span></div>';
    }

    private static function account_bulk_toolbar(): void {
        echo '<div class="ysec-bulk-toolbar ysec-account-bulk-toolbar" data-ysec-account-bulk><select data-ysec-account-action><option value="">' . esc_html__( 'Account bulk actions', 'yablonsky-security' ) . '</option>';
        foreach ( array( 'revoke_sessions','lock_60','lock_240','lock_1440','unlock','approve' ) as $action ) {
            echo '<option value="' . esc_attr( $action ) . '">' . esc_html( YSEC_Accounts::label_for_action( $action ) ) . '</option>';
        }
        echo '</select><select data-ysec-account-scope><option value="selected">' . esc_html__( 'Selected users', 'yablonsky-security' ) . '</option><option value="filtered">' . esc_html__( 'All matching users', 'yablonsky-security' ) . '</option></select><button type="button" class="button button-primary ysec-apply-account-bulk">' . esc_html__( 'Apply', 'yablonsky-security' ) . '</button><span class="description">' . esc_html__( 'Bulk locks never lock the administrator running the action. All-matching actions use a resumable background job.', 'yablonsky-security' ) . '</span></div>';
    }

    private static function risk_label( int $risk ): string {
        if($risk>=4)return 'Critical';
        if($risk>=3)return 'High';
        if($risk>=2)return 'Medium';
        return 'Low';
    }
    private static function campaign_explanation(string $family,int $risk): string {
        $map=array(
            'credentials_secrets'=>__('Likely target: environment files, credentials or secrets. Observed outcome: probing only unless a successful response is separately verified.','yablonsky-security'),
            'path_traversal'=>__('Likely target: files outside the public path. Observed outcome: exploit-like traversal request; a block does not prove file access.','yablonsky-security'),
            'rfi_lfi'=>__('Likely target: local/remote file inclusion surface. Observed outcome: exploit-like request; compromise is not inferred.','yablonsky-security'),
            'command_injection'=>__('Likely target: command execution surface. Observed outcome: exploit-like payload; execution is not inferred.','yablonsky-security'),
            'webshell_probe'=>__('Likely target: known webshell paths. Observed outcome: discovery probing, not proof a shell exists.','yablonsky-security'),
            'framework_probe'=>__('Likely target: framework/development endpoints. Observed outcome: reconnaissance.','yablonsky-security'),
            'reconnaissance'=>__('Likely target: administrative or application surface discovery. Observed outcome: reconnaissance.','yablonsky-security'),
        );
        return $map[$family]??self::risk_meaning($risk);
    }

    private static function risk_meaning( int $risk ): string {
        if($risk>=4)return __( 'Exploit-like payload or a signal severe enough for immediate blocking.', 'yablonsky-security' );
        if($risk>=3)return __( 'High-confidence probing for credentials, webshells, traversal or similarly sensitive surfaces.', 'yablonsky-security' );
        if($risk>=2)return __( 'Repeated high-confidence reconnaissance that has not demonstrated successful exploitation.', 'yablonsky-security' );
        return __( 'Low-confidence or low-impact suspicious activity.', 'yablonsky-security' );
    }

    private static function flatten_inventory( array $inventory ): array {
        $rows = array();
        $core = $inventory['core'] ?? array();
        $rows[] = array( 'type' => 'core', 'name' => 'WordPress', 'slug' => 'wordpress', 'version' => (string) ( $core['version'] ?? '' ), 'update' => (string) ( $core['update'] ?? '' ), 'status' => ! empty( $core['update'] ) ? 'update' : 'current', 'active' => __( 'Active', 'yablonsky-security' ) );
        foreach ( $inventory['plugins'] ?? array() as $item ) {
            $rows[] = array( 'type' => 'plugin', 'name' => (string) ( $item['name'] ?? $item['file'] ?? '' ), 'slug' => (string) ( $item['file'] ?? '' ), 'version' => (string) ( $item['version'] ?? '' ), 'update' => (string) ( $item['update'] ?? '' ), 'status' => ! empty( $item['update'] ) ? 'update' : 'current', 'active' => ! empty( $item['active'] ) ? __( 'Active', 'yablonsky-security' ) : __( 'Inactive', 'yablonsky-security' ) );
        }
        foreach ( $inventory['themes'] ?? array() as $item ) {
            $rows[] = array( 'type' => 'theme', 'name' => (string) ( $item['name'] ?? $item['slug'] ?? '' ), 'slug' => (string) ( $item['slug'] ?? '' ), 'version' => (string) ( $item['version'] ?? '' ), 'update' => (string) ( $item['update'] ?? '' ), 'status' => ! empty( $item['update'] ) ? 'update' : 'current', 'active' => ! empty( $item['active'] ) ? __( 'Active', 'yablonsky-security' ) : __( 'Inactive', 'yablonsky-security' ) );
        }
        $advisories = isset( $inventory['advisories'] ) && is_array( $inventory['advisories'] ) ? $inventory['advisories'] : array();
        foreach ( $rows as &$row ) {
            $row['advisories'] = 0;
            $row['advisory_severity'] = '';
            $rank = array( 'critical'=>4, 'high'=>3, 'medium'=>2, 'low'=>1, 'info'=>0 );
            foreach ( $advisories as $advisory ) {
                $component = (string) ( $advisory['component'] ?? $advisory['slug'] ?? '' );
                if ( '' === $component || ( $component !== $row['slug'] && $component !== $row['name'] ) ) continue;
                $row['advisories']++;
                $sev = sanitize_key( (string) ( $advisory['severity'] ?? 'info' ) );
                if ( ( $rank[$sev] ?? 0 ) > ( $rank[$row['advisory_severity']] ?? -1 ) ) $row['advisory_severity'] = $sev;
            }
        }
        unset( $row );
        return $rows;
    }

    private static function paginate_array( array $rows, array $args ): array {
        $page = max( 1, absint( $args['page'] ?? 1 ) );
        $per_page = max( 10, min( 100, absint( $args['per_page'] ?? 25 ) ?: 25 ) );
        $total = count( $rows );
        $max = max( 1, (int) ceil( $total / $per_page ) );
        if ( $page > $max ) $page = $max;
        return array( 'rows' => array_slice( $rows, ( $page - 1 ) * $per_page, $per_page ), 'total' => $total, 'page' => $page, 'per_page' => $per_page );
    }

    private static function ai_context_panel( string $surface ): void {
        if ( ! in_array( $surface, array( 'events', 'recon', 'firewall' ), true ) ) return;
        $readiness = YSEC_AI::analysis_readiness();
        $ready = ! empty( $readiness['route_ready'] );
        $titles = array(
            'events'   => __( 'Security events', 'yablonsky-security' ),
            'recon'    => __( 'Reconnaissance campaigns', 'yablonsky-security' ),
            'firewall' => __( 'Firewall enforcement', 'yablonsky-security' ),
        );
        $modes = array(
            'events'   => __( 'Incident triage', 'yablonsky-security' ),
            'recon'    => __( 'Attack campaign analysis', 'yablonsky-security' ),
            'firewall' => __( 'Prioritized remediation plan', 'yablonsky-security' ),
        );
        echo '<section class="ysec-surface ysec-ai-analysis-builder ysec-ai-context-analysis"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Yablonsky AI', 'yablonsky-security' ) . '</span><h3>' . esc_html( $titles[ $surface ] ) . '</h3><p>' . esc_html__( 'Choose the question and scope. Yablonsky Security removes source fingerprints and redacts secret-like fields before transmission.', 'yablonsky-security' ) . '</p></div><span class="ysec-status-badge ' . esc_attr( $ready ? 'ysec-status-neutral' : 'ysec-status-attention' ) . '">' . esc_html( $ready ? __( 'Explicit request only', 'yablonsky-security' ) : __( 'MODEL ROUTE UNAVAILABLE', 'yablonsky-security' ) ) . '</span></div>';
        echo '<form method="post" class="ysec-ai-analyze-form ysec-ai-context-form">';
        wp_nonce_field( 'ysec_ai_context_' . $surface );
        echo '<input type="hidden" name="ysec_ai_surface" value="' . esc_attr( $surface ) . '"><div class="ysec-ai-analysis-grid"><label class="ysec-field"><span>' . esc_html__( 'Analysis mode', 'yablonsky-security' ) . '</span><input type="text" value="' . esc_attr( $modes[ $surface ] ) . '" readonly></label>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'Evidence window', 'yablonsky-security' ) . '</span><select name="ysec_ai_window"><option value="6">' . esc_html__( 'Last 6 hours', 'yablonsky-security' ) . '</option><option value="24" selected>' . esc_html__( 'Last 24 hours', 'yablonsky-security' ) . '</option><option value="72">' . esc_html__( 'Last 3 days', 'yablonsky-security' ) . '</option><option value="168">' . esc_html__( 'Last 7 days', 'yablonsky-security' ) . '</option></select></label>';
        echo '<label class="ysec-field"><span>' . esc_html__( 'Maximum events', 'yablonsky-security' ) . '</span><select name="ysec_ai_event_limit"><option value="25">25</option><option value="50">50</option><option value="100" selected>100</option></select></label></div>';
        echo '<div class="ysec-ai-submit-row"><button class="button button-primary" name="ysec_ai_context_analyze" value="1" ' . disabled( ! $ready, true, false ) . '>' . esc_html__( 'Analyze with Yablonsky AI', 'yablonsky-security' ) . '</button><span>' . esc_html__( 'This is the only step that sends the selected evidence to the external AI service and may consume AI credits.', 'yablonsky-security' ) . '</span></div></form>';
        $result = get_transient( 'ysec_last_ai_context_' . $surface . '_' . get_current_user_id() );
        if ( is_array( $result ) && isset( $result['error'] ) ) YSEC_Admin::render_ai_result( $result );
        $requested_page = isset( $_GET['ysec_ai_history_page'] ) ? max( 1, absint( wp_unslash( $_GET['ysec_ai_history_page'] ) ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display-only navigation.
        $history_page = YSEC_Admin::ai_context_history( $surface, $requested_page );
        $history = $history_page['rows'];
        if ( $history ) {
            echo '<section class="ysec-ai-history" id="ysec-ai-history"><div class="ysec-surface-head"><div><span class="ysec-eyebrow">' . esc_html__( 'Previous', 'yablonsky-security' ) . '</span><h3>' . esc_html__( 'Security analysis', 'yablonsky-security' ) . '</h3></div></div>';
            echo '<form method="post" class="ysec-ai-history-form">';
            wp_nonce_field( 'ysec_ai_history_' . $surface );
            echo '<input type="hidden" name="ysec_ai_surface" value="' . esc_attr( $surface ) . '"><div class="ysec-ai-history-list">';
            foreach ( $history as $index => $row ) {
                $id = (string) ( $row['id'] ?? '' );
                $created = (string) ( $row['created_at'] ?? '' );
                echo '<details class="ysec-ai-history-item"><summary><label class="ysec-ai-history-select"><input type="checkbox" name="ysec_ai_history_ids[]" value="' . esc_attr( $id ) . '"> ' . esc_html__( 'Select', 'yablonsky-security' ) . '</label><span><strong>' . esc_html__( 'Time', 'yablonsky-security' ) . '</strong> ' . esc_html( $created ) . '</span><span><strong>' . esc_html__( 'Analysis mode', 'yablonsky-security' ) . '</strong> ' . esc_html( $modes[ $surface ] ) . '</span></summary><div class="ysec-ai-history-body">';
                YSEC_Admin::render_ai_result( array( 'analysis' => (array) ( $row['analysis'] ?? array() ) ), false );
                echo '</div></details>';
            }
            echo '</div><div class="ysec-action-row ysec-ai-history-actions"><button class="button" name="ysec_ai_history_delete" value="1" onclick="return confirm(this.dataset.confirm);" data-confirm="' . esc_attr__( 'Delete permanently', 'yablonsky-security' ) . '">' . esc_html__( 'Delete permanently', 'yablonsky-security' ) . '</button></div></form>';
            $page = (int) $history_page['page'];
            $pages = (int) $history_page['pages'];
            $total = (int) $history_page['total'];
            $from = ( $page - 1 ) * 5 + 1;
            $to = min( $total, $page * 5 );
            echo '<nav class="ysec-ai-history-pagination" aria-label="' . esc_attr__( 'Table pagination', 'yablonsky-security' ) . '"><span>' . esc_html( sprintf( /* translators: 1: first visible row, 2: last visible row, 3: total matching rows. */ __( 'Showing %1$d–%2$d of %3$d', 'yablonsky-security' ), $from, $to, $total ) ) . '</span><div>';
            if ( $page > 1 ) {
                $url = add_query_arg( array( 'page' => 'yablonsky-security', 'tab' => $surface, 'ysec_ai_history_page' => $page - 1 ), admin_url( 'admin.php' ) );
                echo '<a class="button button-small" href="' . esc_url( $url . '#ysec-ai-history' ) . '">' . esc_html__( 'Previous', 'yablonsky-security' ) . '</a>';
            }
            if ( $page < $pages ) {
                $url = add_query_arg( array( 'page' => 'yablonsky-security', 'tab' => $surface, 'ysec_ai_history_page' => $page + 1 ), admin_url( 'admin.php' ) );
                echo '<a class="button button-small" href="' . esc_url( $url . '#ysec-ai-history' ) . '">' . esc_html__( 'Next', 'yablonsky-security' ) . '</a>';
            }
            echo '</div></nav></section>';
        }
        echo '</section>';
    }

    private static function shell_start( string $dataset, bool $outer = true ): void {
        echo '<div class="ysec-data-view' . ( $outer ? '' : ' ysec-data-view-nested' ) . '" data-dataset="' . esc_attr( $dataset ) . '"><div class="ysec-filters">';
    }
    private static function shell_end( bool $outer = true ): void {
        echo '</div>';
    }
    private static function hidden_sort( string $orderby, string $order ): void {
        echo '<input type="hidden" name="orderby" value="' . esc_attr( $orderby ) . '"><input type="hidden" name="order" value="' . esc_attr( $order ) . '"><input type="hidden" name="page" value="1"></div>';
    }
    private static function monitor_filters( string $dataset, array $opts ): void {
        $dataset = in_array( $dataset, array( 'events', 'recon', 'firewall_actions' ), true ) ? $dataset : 'events';
        $search_label = 'events' === $dataset
            ? __( 'Search events', 'yablonsky-security' )
            : ( 'recon' === $dataset ? __( 'Search campaigns', 'yablonsky-security' ) : __( 'Search firewall actions', 'yablonsky-security' ) );

        $severity_options = array(
            ''         => __( 'All severities', 'yablonsky-security' ),
            'critical' => __( 'Critical', 'yablonsky-security' ),
            'high'     => __( 'High', 'yablonsky-security' ),
            'medium'   => __( 'Medium', 'yablonsky-security' ),
            'low'      => __( 'Low', 'yablonsky-security' ),
            'info'     => __( 'Info', 'yablonsky-security' ),
        );

        $state_label = __( 'State', 'yablonsky-security' );
        if ( 'firewall_actions' === $dataset ) {
            $state_label = __( 'Decision', 'yablonsky-security' );
            $state_options = array(
                ''                   => __( 'All enforcement decisions', 'yablonsky-security' ),
                'blocked'            => __( 'Blocked', 'yablonsky-security' ),
                'request_denied'     => __( 'Request denied', 'yablonsky-security' ),
                'source_blocked'     => __( 'Source contained', 'yablonsky-security' ),
                'campaign_contained' => __( 'Campaign contained', 'yablonsky-security' ),
            );
        } elseif ( 'recon' === $dataset ) {
            $state_options = array(
                ''                   => __( 'All states', 'yablonsky-security' ),
                'suspicious'         => self::human_label( 'suspicious' ),
                'blocked'            => __( 'Blocked', 'yablonsky-security' ),
                'request_denied'     => __( 'Request denied', 'yablonsky-security' ),
                'source_blocked'     => __( 'Source contained', 'yablonsky-security' ),
                'campaign_contained' => __( 'Campaign contained', 'yablonsky-security' ),
            );
        } else {
            $state_options = array( '' => __( 'All states', 'yablonsky-security' ) ) + self::label_options( is_array( $opts['states'] ?? null ) ? $opts['states'] : array() );
        }

        $record_options = array(
            'active'   => __( 'Active records', 'yablonsky-security' ),
            'reviewed' => __( 'Reviewed', 'yablonsky-security' ),
            'archived' => __( 'Archived', 'yablonsky-security' ),
            'all'      => __( 'All records', 'yablonsky-security' ),
        );

        echo '<div class="ysec-filter-grid ysec-monitor-controls ysec-monitor-controls-v2">';
        self::search_control( $search_label );
        $family_options = is_array( $opts['families'] ?? null ) ? $opts['families'] : array();
        self::smart_select_control( 'family', __( 'Family', 'yablonsky-security' ), __( 'All families', 'yablonsky-security' ), $dataset, 'family', $family_options );
        self::select_control( 'severity', __( 'Severity', 'yablonsky-security' ), $severity_options, 'ysec-filter-severity' );
        self::select_control( 'state', $state_label, $state_options, 'ysec-filter-state' );
        self::select_control( 'record_status', __( 'Record status', 'yablonsky-security' ), $record_options, 'ysec-filter-record-status' );
        self::date_control( 'date_from', __( 'From date', 'yablonsky-security' ), wp_date( 'Y-m-d', time() - 6 * DAY_IN_SECONDS ) );
        self::date_control( 'date_to', __( 'To date', 'yablonsky-security' ), wp_date( 'Y-m-d' ) );
        self::timeframe_control( 7 );
        self::reset_control();
        echo '</div>';
    }

    private static function smart_select_control( string $name, string $label, string $default_label, string $dataset, string $field, array $preloaded_options = array() ): void {
        $preloaded_options = array_values( array_unique( array_filter( array_map( 'sanitize_key', $preloaded_options ) ) ) );
        $preloaded_complete = count( $preloaded_options ) < 200;
        echo '<div class="ysec-filter ysec-smart-filter ysec-filter-' . esc_attr( sanitize_html_class( $name ) ) . '" data-ysec-smart-select data-ysec-dataset="' . esc_attr( $dataset ) . '" data-ysec-field="' . esc_attr( $field ) . '" data-ysec-default-label="' . esc_attr( $default_label ) . '" data-ysec-preloaded-complete="' . esc_attr( $preloaded_complete ? '1' : '0' ) . '">';
        echo '<span>' . esc_html( $label ) . '</span>';
        echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="">';
        echo '<button type="button" class="button ysec-smart-select-trigger" aria-label="' . esc_attr( $label ) . '" aria-haspopup="listbox" aria-expanded="false"><span data-ysec-smart-value>' . esc_html( $default_label ) . '</span><span class="ysec-smart-select-chevron" aria-hidden="true"><svg viewBox="0 0 20 20" focusable="false"><path d="M5 7.5 10 12.5 15 7.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span></button>';
        echo '<div class="ysec-smart-select-popover" hidden>';
        echo '<input type="search" class="ysec-smart-select-search" placeholder="' . esc_attr__( 'Type to search…', 'yablonsky-security' ) . '" autocomplete="off">';
        echo '<div class="ysec-smart-select-options" role="listbox"><button type="button" class="ysec-smart-select-option is-selected" data-value="" data-search="' . esc_attr( $default_label ) . '" role="option" aria-selected="true">' . esc_html( $default_label ) . '</button>';
        foreach ( $preloaded_options as $value ) {
            $option_label = self::human_label( $value );
            echo '<button type="button" class="ysec-smart-select-option" data-value="' . esc_attr( $value ) . '" data-search="' . esc_attr( $option_label . ' ' . $value ) . '" role="option" aria-selected="false">' . esc_html( $option_label ) . '</button>';
        }
        echo '<div class="ysec-smart-select-empty" hidden>' . esc_html__( 'No components match these filters.', 'yablonsky-security' ) . '</div>';
        echo '</div></div></div>';
    }

    private static function search_control( string $label ): void {
        echo '<label class="ysec-filter ysec-filter-search"><span>' . esc_html( $label ) . '</span><input type="search" name="search" value="" placeholder="' . esc_attr__( 'Type to search…', 'yablonsky-security' ) . '" autocomplete="off"></label>';
    }
    private static function select_control( string $name, string $label, array $options, string $class = '' ): void {
        $classes = trim( 'ysec-filter ' . $class );
        echo '<label class="' . esc_attr( $classes ) . '"><span>' . esc_html( $label ) . '</span><select name="' . esc_attr( $name ) . '">';
        foreach ( $options as $value => $text ) echo '<option value="' . esc_attr( $value ) . '">' . esc_html( $text ) . '</option>';
        echo '</select></label>';
    }
    private static function date_control( string $name, string $label, string $value = '' ): void {
        echo '<label class="ysec-filter ysec-filter-' . esc_attr( sanitize_html_class( str_replace( '_', '-', $name ) ) ) . '"><span>' . esc_html( $label ) . '</span><input type="date" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '"></label>';
    }
    private static function timeframe_control( int $active_days = 7 ): void {
        echo '<div class="ysec-filter ysec-timeframe-control"><span>' . esc_html__( 'Selected period', 'yablonsky-security' ) . '</span><div class="ysec-timeframe-buttons">';
        foreach ( array( 7, 30, 90 ) as $days ) {
            $label = number_format_i18n( $days ) . ' ' . _n( 'day', 'days', $days, 'yablonsky-security' );
            echo '<button type="button" class="button ysec-timeframe' . ( $days === $active_days ? ' is-active' : '' ) . '" data-ysec-timeframe="' . esc_attr( (string) $days ) . '" aria-pressed="' . esc_attr( $days === $active_days ? 'true' : 'false' ) . '">' . esc_html( $label ) . '</button>';
        }
        echo '</div></div>';
    }
    private static function reset_control(): void {
        echo '<div class="ysec-filter ysec-filter-action"><span>&nbsp;</span><button type="button" class="button ysec-reset">' . esc_html__( 'Reset filters', 'yablonsky-security' ) . '</button></div>';
    }
    private static function label_options( array $values ): array {
        $out = array();
        foreach ( $values as $value ) $out[ $value ] = self::human_label( $value );
        return $out;
    }
    private static function human_label( string $value ): string {
        $map = array(
            'software_updated' => __( 'Software updated', 'yablonsky-security' ),
            'webshell_probe' => __( 'Web shell probe', 'yablonsky-security' ),
            'content_or_unknown' => __( 'Content / unknown', 'yablonsky-security' ),
            'wordpress_or_technical_surface' => __( 'WordPress / technical surface', 'yablonsky-security' ),
            'rfi_lfi' => __( 'Remote/local file inclusion', 'yablonsky-security' ),
            'path_traversal' => __( 'Path traversal', 'yablonsky-security' ),
            'credentials_secrets' => __( 'Credentials / secrets', 'yablonsky-security' ),
        );
        if ( isset( $map[ $value ] ) ) return $map[ $value ];
        return ucwords( str_replace( array( '_', '-' ), ' ', $value ) );
    }
    private static function badge( string $value ): string {
        $safe = sanitize_key( $value );
        return '<span class="ysec-badge ysec-badge-' . esc_attr( $safe ) . '">' . esc_html( self::human_label( $value ) ) . '</span>';
    }
    private static function th( string $label, string $key, array $args, string $dataset ): void {
        $current = sanitize_key( (string) ( $args['orderby'] ?? '' ) );
        $order = 'ASC' === strtoupper( (string) ( $args['order'] ?? '' ) ) ? 'ASC' : 'DESC';
        $next = $current === $key && 'ASC' === $order ? 'DESC' : 'ASC';
        $indicator = $current === $key ? ( 'ASC' === $order ? ' ↑' : ' ↓' ) : '';
        echo '<th><button type="button" class="ysec-sort" data-orderby="' . esc_attr( $key ) . '" data-order="' . esc_attr( $next ) . '">' . esc_html( $label . $indicator ) . '</button></th>';
    }
    private static function result_meta( int $total, int $page, int $per_page ): void {
        return;
    }
    private static function pagination( int $total, int $page, int $per_page, bool $top = false ): void {
        if ( $top || $total <= 0 ) return;
        $pages = max( 1, (int) ceil( $total / $per_page ) );
        $from = $total ? ( $page - 1 ) * $per_page + 1 : 0;
        $to = min( $total, $page * $per_page );
        echo '<nav class="ysec-pagination" aria-label="' . esc_attr__( 'Table pagination', 'yablonsky-security' ) . '">';
        echo '<label class="ysec-pagination-size"><span>' . esc_html__( 'Rows per page', 'yablonsky-security' ) . '</span><select class="ysec-per-page" data-ysec-per-page aria-label="' . esc_attr__( 'Rows per page', 'yablonsky-security' ) . '">';
        foreach ( array( 25, 50, 100 ) as $size ) echo '<option value="' . esc_attr( (string) $size ) . '" ' . selected( $per_page, $size, false ) . '>' . esc_html( (string) $size ) . '</option>';
        echo '</select></label>';
        /* translators: 1: first visible row, 2: last visible row, 3: total matching rows. */
        echo '<div class="ysec-result-meta ysec-result-meta-inline">' . esc_html( sprintf( __( 'Showing %1$d–%2$d of %3$d', 'yablonsky-security' ), $from, $to, $total ) ) . '</div>';
        if ( $pages > 1 ) {
            echo '<div class="ysec-pagination-pages">';
            echo '<button type="button" class="button ysec-page" data-page="' . esc_attr( (string) max( 1, $page - 1 ) ) . '" ' . disabled( $page <= 1, true, false ) . '>&lsaquo; ' . esc_html__( 'Previous', 'yablonsky-security' ) . '</button>';
            $start = max( 1, $page - 2 ); $end = min( $pages, $page + 2 );
            if ( $start > 1 ) echo '<button type="button" class="button ysec-page" data-page="1">1</button><span class="ysec-page-gap">…</span>';
            for ( $i = $start; $i <= $end; $i++ ) echo '<button type="button" class="button ysec-page ' . ( $i === $page ? 'button-primary' : '' ) . '" data-page="' . esc_attr( (string) $i ) . '" ' . disabled( $i === $page, true, false ) . '>' . esc_html( (string) $i ) . '</button>';
            if ( $end < $pages ) echo '<span class="ysec-page-gap">…</span><button type="button" class="button ysec-page" data-page="' . esc_attr( (string) $pages ) . '">' . esc_html( (string) $pages ) . '</button>';
            echo '<button type="button" class="button ysec-page" data-page="' . esc_attr( (string) min( $pages, $page + 1 ) ) . '" ' . disabled( $page >= $pages, true, false ) . '>' . esc_html__( 'Next', 'yablonsky-security' ) . ' &rsaquo;</button>';
            echo '</div>';
        }
        echo '</nav>';
    }
    private static function stat_card( string $label, $value, bool $text = false ): void {
        echo '<div class="ysec-card"><span>' . esc_html( $label ) . '</span><strong class="' . ( $text ? 'ysec-card-text' : '' ) . '">' . esc_html( (string) $value ) . '</strong></div>';
    }
    private static function local_datetime( string $gmt ): string {
        $ts = strtotime( $gmt . ' UTC' );
        return $ts ? wp_date( 'Y-m-d H:i:s', $ts ) : $gmt;
    }
}
