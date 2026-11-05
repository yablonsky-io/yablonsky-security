<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Jobs {
    public static function boot(): void {
        if ( ! is_admin() ) return;
        add_action( 'wp_ajax_ysec_job_start', array( __CLASS__, 'ajax_start' ) );
        add_action( 'wp_ajax_ysec_job_step', array( __CLASS__, 'ajax_step' ) );
        add_action( 'wp_ajax_ysec_job_pause', array( __CLASS__, 'ajax_pause' ) );
        add_action( 'wp_ajax_ysec_job_resume', array( __CLASS__, 'ajax_resume' ) );
        add_action( 'wp_ajax_ysec_job_cancel', array( __CLASS__, 'ajax_cancel' ) );
        add_action( 'wp_ajax_ysec_job_dismiss', array( __CLASS__, 'ajax_dismiss' ) );
        add_action( 'wp_ajax_ysec_job_status', array( __CLASS__, 'ajax_status' ) );
        add_action( 'admin_post_ysec_job_download', array( __CLASS__, 'download' ) );
    }

    private static function table(): string { return YSEC_DB::table( 'jobs' ); }
    private static function parts_table(): string { return YSEC_DB::table( 'job_parts' ); }

    private static function guard(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'Not allowed.', 'yablonsky-security' ) ), 403 );
        }
        check_ajax_referer( 'ysec_jobs', 'nonce' );
    }

    private static function post_value( string $key ): string {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Every AJAX caller invokes self::guard() before reading job request data.
        if ( ! isset( $_POST[ $key ] ) || is_array( $_POST[ $key ] ) ) {
            return '';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Every AJAX caller invokes self::guard() before reading job request data.
        return sanitize_text_field( wp_unslash( $_POST[ $key ] ) );
    }

    private static function filters_from_post(): array {
        $out = array();
        foreach ( array( 'search', 'severity', 'family', 'state', 'date_from', 'date_to', 'record_status', 'role', 'session_status', 'two_factor', 'account_state', 'enforcement_only' ) as $key ) {
            $value = self::post_value( $key );
            if ( '' === $value ) continue;
            $out[ $key ] = in_array( $key, array( 'search', 'date_from', 'date_to' ), true ) ? sanitize_text_field( $value ) : sanitize_key( $value );
        }
        return $out;
    }

    public static function ajax_start(): void {
        self::guard();
        global $wpdb;

        $kind    = sanitize_key( self::post_value( 'kind' ) );
        $dataset = sanitize_key( self::post_value( 'dataset' ) );
        $action  = sanitize_key( self::post_value( 'job_action' ) );
        $format  = sanitize_key( self::post_value( 'format' ) );

        if ( ! in_array( $kind, array( 'export', 'bulk', 'source_scope', 'account_scope' ), true ) || ! in_array( $dataset, array( 'events', 'recon', 'firewall_actions', 'accounts' ), true ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid background job.', 'yablonsky-security' ) ), 400 );
        }
        if ( 'accounts' === $dataset && 'account_scope' !== $kind ) {
            wp_send_json_error( array( 'message' => __( 'Accounts use the account-scope job engine.', 'yablonsky-security' ) ), 400 );
        }
        if ( 'account_scope' === $kind && ( 'accounts' !== $dataset || ! YSEC_Accounts::allowed_bulk_action( $action ) ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid account-scope action.', 'yablonsky-security' ) ), 400 );
        }
        if ( 'export' === $kind && ! in_array( $format, array( 'csv', 'json' ), true ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid export format.', 'yablonsky-security' ) ), 400 );
        }
        if ( 'bulk' === $kind && ! in_array( $action, array( 'block_sources', 'unblock_sources', 'review', 'false_positive', 'archive', 'delete' ), true ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid bulk action.', 'yablonsky-security' ) ), 400 );
        }
        if ( 'recon' === $dataset && 'bulk' === $kind && ! in_array( $action, array( 'block_sources', 'unblock_sources' ), true ) ) {
            wp_send_json_error( array( 'message' => __( 'This campaign bulk action is not supported.', 'yablonsky-security' ) ), 400 );
        }
        if ( 'source_scope' === $kind && ! in_array( $action, array( 'block_sources', 'unblock_sources' ), true ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid all-matching source action.', 'yablonsky-security' ) ), 400 );
        }

        $filters = self::filters_from_post();
        if ( 'firewall_actions' === $dataset ) {
            $filters['enforcement_only'] = 1;
        }
        if ( 'account_scope' === $kind ) {
            // Freeze the exact account scope once when the job starts. This keeps a
            // 10k+ user job deterministic and prevents every step from rescanning all
            // WordPress users / session state again.
            $account_ids = YSEC_Accounts::filtered_ids( $filters );
            $filters['_account_ids'] = array_values( array_map( 'absint', $account_ids ) );
            $max_id = 0;
            $total  = count( $filters['_account_ids'] );
        } elseif ( 'source_scope' === $kind ) {
            $max_id = YSEC_Events::job_source_max_id( $dataset, $filters );
            $total  = YSEC_Events::job_source_count( $dataset, $filters, $max_id );
        } else {
            $event_like = in_array( $dataset, array( 'events', 'firewall_actions' ), true );
            $total  = $event_like ? YSEC_Events::job_event_count( $filters ) : YSEC_Events::job_recon_count( $filters );
            $max_id = $event_like ? YSEC_Events::job_event_max_id( $filters ) : 0;
        }
        $uuid    = wp_generate_uuid4();
        $now     = current_time( 'mysql', true );
        $expires = gmdate( 'Y-m-d H:i:s', time() + 2 * HOUR_IN_SECONDS );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Dedicated resumable job state table; this is the source of truth for the running job.
        $ok = $wpdb->insert(
            self::table(),
            array(
                'job_uuid'       => $uuid,
                'owner_user_id'  => get_current_user_id(),
                'kind'           => $kind,
                'dataset'        => $dataset,
                'action_name'    => $action,
                'format_name'    => $format,
                'status'         => 'running',
                'filters'        => wp_json_encode( $filters ),
                'cursor_value'   => 0,
                'max_id'         => $max_id,
                'total'          => $total,
                'processed'      => 0,
                'changed'        => 0,
                'parts'          => 0,
                'created_at'     => $now,
                'updated_at'     => $now,
                'expires_at'     => $expires,
                'result'         => wp_json_encode( array() ),
            ),
            array( '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%s', '%s', '%s', '%s' )
        );
        if ( false === $ok ) {
            wp_send_json_error( array( 'message' => __( 'Could not create background job.', 'yablonsky-security' ) ), 500 );
        }
        wp_send_json_success( self::public_job( self::get( $uuid ) ) );
    }

    public static function ajax_step(): void {
        self::guard();
        $uuid = self::post_value( 'job' );
        $job  = self::get_owned( $uuid );
        if ( ! $job ) {
            wp_send_json_error( array( 'message' => __( 'Background job not found.', 'yablonsky-security' ) ), 404 );
        }
        if ( in_array( $job['status'], array( 'paused', 'completed', 'downloaded' ), true ) ) {
            wp_send_json_success( self::public_job( $job ) );
        }
        $filters = json_decode( (string) $job['filters'], true );
        if ( ! is_array( $filters ) ) $filters = array();
        try {
            if ( 'export' === $job['kind'] ) self::step_export( $job, $filters );
            elseif ( 'source_scope' === $job['kind'] ) self::step_source_scope( $job, $filters );
            elseif ( 'account_scope' === $job['kind'] ) self::step_account_scope( $job, $filters );
            else self::step_bulk( $job, $filters );
        } catch ( Throwable $e ) {
            self::update( $uuid, array( 'status' => 'failed', 'result' => wp_json_encode( array( 'message' => $e->getMessage() ) ) ) );
        }
        wp_send_json_success( self::public_job( self::get_owned( $uuid ) ) );
    }

    private static function step_export( array $job, array $filters ): void {
        $cursor = (int) $job['cursor_value'];
        $limit  = self::step_size( $job );
        $event_like = in_array( $job['dataset'], array( 'events', 'firewall_actions' ), true );
        $rows   = $event_like
            ? YSEC_Events::job_event_batch( $filters, $cursor, (int) $job['max_id'], $limit, true )
            : YSEC_Events::job_recon_batch( $filters, $cursor, $limit );
        if ( ! $rows ) {
            self::update( $job['job_uuid'], array( 'status' => 'completed', 'processed' => (int) $job['total'] ) );
            return;
        }
        foreach ( $rows as &$row ) {
            unset( $row['source_hash'], $row['source_enc'] );
            if ( isset( $row['details'] ) ) {
                $decoded        = json_decode( (string) $row['details'], true );
                $row['details'] = is_array( $decoded ) ? YSEC_Utils::redact( $decoded ) : array();
            }
        }
        unset( $row );

        $part_no = (int) $job['parts'] + 1;
        $payload = 'json' === $job['format_name'] ? self::json_part( $rows ) : self::csv_part( $rows, 1 === $part_no );
        self::store_part( $job['job_uuid'], $part_no, $payload );
        $processed = min( (int) $job['total'], (int) $job['processed'] + count( $rows ) );
        $last_row  = end( $rows );
        $next      = $event_like ? (int) ( $last_row['id'] ?? $cursor ) : $cursor + count( $rows );
        $status    = $processed >= (int) $job['total'] ? 'completed' : 'running';
        self::update( $job['job_uuid'], array( 'cursor_value' => $next, 'processed' => $processed, 'parts' => $part_no, 'status' => $status ) );
    }

    private static function step_bulk( array $job, array $filters ): void {
        $cursor  = (int) $job['cursor_value'];
        $limit   = self::step_size( $job );
        $changed = 0;

        if ( in_array( $job['dataset'], array( 'events', 'firewall_actions' ), true ) ) {
            $rows = YSEC_Events::job_event_batch( $filters, $cursor, (int) $job['max_id'], $limit, false );
            if ( ! $rows ) {
                self::update( $job['job_uuid'], array( 'status' => 'completed' ) );
                return;
            }
            $ids = array_map( 'intval', array_column( $rows, 'id' ) );
            if ( in_array( $job['action_name'], array( 'review', 'false_positive', 'archive', 'delete' ), true ) ) {
                $changed = 'false_positive' === $job['action_name'] ? YSEC_Events::mark_false_positive( $ids ) : YSEC_Events::bulk_action( $ids, $job['action_name'] );
            } else {
                $sources = array();
                foreach ( $rows as $row ) {
                    $hash = (string) $row['source_hash'];
                    if ( '' !== $hash && ! isset( $sources[ $hash ] ) ) $sources[ $hash ] = (string) $row['family'];
                }
                foreach ( $sources as $hash => $family ) {
                    if ( 'block_sources' === $job['action_name'] ) $changed += YSEC_Firewall::block_hash( $hash, 'Bulk event response: ' . sanitize_key( $family ) ) ? 1 : 0;
                    else $changed += YSEC_Firewall::unblock_hash( $hash );
                }
            }
            $last_row = end( $rows );
            $next     = (int) ( $last_row['id'] ?? $cursor );
        } else {
            $rows = YSEC_Events::job_recon_batch( $filters, $cursor, $limit );
            if ( ! $rows ) {
                self::update( $job['job_uuid'], array( 'status' => 'completed' ) );
                return;
            }
            $sources = array();
            foreach ( $rows as $row ) {
                $hash = (string) $row['source_hash'];
                if ( '' !== $hash && ! isset( $sources[ $hash ] ) ) $sources[ $hash ] = (string) $row['family'];
            }
            foreach ( $sources as $hash => $family ) {
                if ( 'block_sources' === $job['action_name'] ) $changed += YSEC_Firewall::block_hash( $hash, 'Bulk campaign response: ' . sanitize_key( $family ) ) ? 1 : 0;
                else $changed += YSEC_Firewall::unblock_hash( $hash );
            }
            $next = $cursor + count( $rows );
        }

        $processed = min( (int) $job['total'], (int) $job['processed'] + count( $rows ) );
        $status    = $processed >= (int) $job['total'] ? 'completed' : 'running';
        self::update( $job['job_uuid'], array( 'cursor_value' => $next, 'processed' => $processed, 'changed' => (int) $job['changed'] + $changed, 'status' => $status ) );
    }

    private static function step_source_scope( array $job, array $filters ): void {
        $offset = max( 0, (int) $job['cursor_value'] );
        $limit = self::step_size( $job );
        $rows = YSEC_Events::job_source_batch( (string) $job['dataset'], $filters, $offset, (int) $job['max_id'], $limit );
        if ( ! $rows ) {
            self::update( $job['job_uuid'], array( 'status' => 'completed', 'processed' => (int) $job['total'] ) );
            return;
        }
        $changed = 0;
        foreach ( $rows as $row ) {
            $hash = (string) ( $row['source_hash'] ?? '' );
            if ( ! preg_match( '/^[a-f0-9]{64}$/', $hash ) ) continue;
            $family = sanitize_key( (string) ( $row['family'] ?? 'reconnaissance' ) );
            if ( 'block_sources' === $job['action_name'] ) {
                $changed += YSEC_Firewall::block_hash( $hash, 'All-matching source response: ' . $family ) ? 1 : 0;
            } else {
                $changed += YSEC_Firewall::unblock_hash( $hash );
            }
        }
        $processed = min( (int) $job['total'], (int) $job['processed'] + count( $rows ) );
        $next = $offset + count( $rows );
        $status = $processed >= (int) $job['total'] ? 'completed' : 'running';
        self::update( $job['job_uuid'], array( 'cursor_value'=>$next, 'processed'=>$processed, 'changed'=>(int)$job['changed']+$changed, 'status'=>$status ) );
    }


    private static function step_account_scope( array $job, array $filters ): void {
        $offset = max( 0, (int) $job['cursor_value'] );
        $limit = self::step_size( $job );
        $snapshot = array_values( array_filter( array_map( 'absint', (array) ( $filters['_account_ids'] ?? array() ) ) ) );
        $ids = array_slice( $snapshot, $offset, $limit );
        if ( ! $ids ) {
            self::update( $job['job_uuid'], array( 'status'=>'completed', 'processed'=>(int)$job['total'] ) );
            return;
        }
        $changed = 0;
        foreach ( $ids as $user_id ) {
            if ( YSEC_Accounts::apply( absint( $user_id ), (string) $job['action_name'] ) ) $changed++;
        }
        $processed = min( (int) $job['total'], (int) $job['processed'] + count( $ids ) );
        $status = $processed >= (int) $job['total'] ? 'completed' : 'running';
        $new_changed = (int) $job['changed'] + $changed;
        self::update( $job['job_uuid'], array(
            'cursor_value'=>$offset+count($ids),
            'processed'=>$processed,
            'changed'=>$new_changed,
            'status'=>$status,
        ) );
        if ( 'completed' === $status ) {
            YSEC_Events::log( 'account_bulk_job_completed', array(
                'severity'=>'info','family'=>'authentication','state'=>'observed',
                'details'=>array( 'action'=>(string)$job['action_name'], 'processed'=>$processed, 'changed'=>$new_changed, 'actor'=>get_current_user_id() ),
            ) );
        }
    }

    private static function step_size( array $job ): int {
        $total = max( 0, (int) ( $job['total'] ?? 0 ) );
        if ( 'export' === ( $job['kind'] ?? '' ) ) {
            if ( $total > 250000 ) return 2000;
            if ( $total > 50000 ) return 1000;
            return 500;
        }
        if ( 'account_scope' === ( $job['kind'] ?? '' ) ) {
            if ( $total > 10000 ) return 250;
            if ( $total > 2000 ) return 150;
            return 100;
        }
        if ( 'source_scope' === ( $job['kind'] ?? '' ) ) {
            if ( $total > 100000 ) return 1000;
            if ( $total > 20000 ) return 750;
            return 500;
        }
        if ( $total > 250000 ) return 1000;
        if ( $total > 50000 ) return 750;
        return 500;
    }

    public static function ajax_pause(): void {
        self::guard();
        $uuid = self::post_value( 'job' );
        $job  = self::get_owned( $uuid );
        if ( $job && 'running' === $job['status'] ) self::update( $uuid, array( 'status' => 'paused' ) );
        wp_send_json_success( self::public_job( self::get_owned( $uuid ) ) );
    }

    public static function ajax_resume(): void {
        self::guard();
        $uuid = self::post_value( 'job' );
        $job  = self::get_owned( $uuid );
        if ( $job && in_array( $job['status'], array( 'paused', 'failed' ), true ) ) self::update( $uuid, array( 'status' => 'running' ) );
        wp_send_json_success( self::public_job( self::get_owned( $uuid ) ) );
    }

    public static function ajax_cancel(): void {
        self::guard();
        $uuid = self::post_value( 'job' );
        $job  = self::get_owned( $uuid );
        if ( $job ) self::delete_job( $uuid );
        wp_send_json_success( array( 'job' => $uuid, 'status' => 'cancelled' ) );
    }

    public static function ajax_dismiss(): void {
        self::guard();
        $uuid = self::post_value( 'job' );
        $job  = self::get_owned( $uuid );
        if ( $job && in_array( $job['status'], array( 'completed', 'downloaded', 'failed', 'cancelled' ), true ) ) self::delete_job( $uuid );
        wp_send_json_success( array( 'job' => $uuid, 'status' => 'dismissed' ) );
    }

    public static function ajax_status(): void {
        self::guard();
        global $wpdb;
        $uid   = get_current_user_id();
        $now   = current_time( 'mysql', true );
        $table = self::table();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Running/paused/failed administrator-owned jobs must reflect current state; terminal jobs are intentionally not restored after navigation/reload.
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM %i WHERE owner_user_id=%d AND expires_at>%s AND status IN ('running','paused','failed') ORDER BY id DESC LIMIT 8", $table, $uid, $now ), ARRAY_A ) ?: array();
        wp_send_json_success( array_map( array( __CLASS__, 'public_job' ), $rows ) );
    }

    private static function get( string $uuid ): ?array {
        global $wpdb;
        if ( ! preg_match( '/^[a-f0-9-]{36}$/i', $uuid ) ) return null;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Resumable job state must be current.
        $row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE job_uuid=%s', self::table(), $uuid ), ARRAY_A );
        return is_array( $row ) ? $row : null;
    }

    private static function get_owned( string $uuid ): ?array {
        $row = self::get( $uuid );
        return $row && (int) $row['owner_user_id'] === get_current_user_id() ? $row : null;
    }

    private static function update( string $uuid, array $values ): void {
        global $wpdb;
        $values['updated_at'] = current_time( 'mysql', true );
        $formats = array();
        foreach ( $values as $value ) $formats[] = is_int( $value ) ? '%d' : '%s';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Dedicated job state write; cache invalidation cannot replace an authoritative state mutation.
        $wpdb->update( self::table(), $values, array( 'job_uuid' => $uuid ), $formats, array( '%s' ) );
    }

    private static function store_part( string $uuid, int $part_no, string $payload ): void {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Temporary private export-part write; data is authoritative until download/expiry.
        $wpdb->replace( self::parts_table(), array( 'job_uuid' => $uuid, 'part_no' => $part_no, 'payload' => $payload ), array( '%s', '%d', '%s' ) );
    }

    private static function delete_job( string $uuid ): void {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit user-requested cleanup of private temporary export parts.
        $wpdb->delete( self::parts_table(), array( 'job_uuid' => $uuid ), array( '%s' ) );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit user-requested cleanup of terminal/cancelled job state.
        $wpdb->delete( self::table(), array( 'job_uuid' => $uuid ), array( '%s' ) );
    }

    private static function json_part( array $rows ): string {
        $out = array();
        foreach ( $rows as $row ) $out[] = wp_json_encode( $row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        return implode( ",\n", $out );
    }

    private static function csv_part( array $rows, bool $header ): string {
        if ( ! $rows ) return '';
        $out = '';
        if ( $header ) $out .= self::csv_line( array_keys( $rows[0] ) );
        foreach ( $rows as $row ) $out .= self::csv_line( array_values( $row ) );
        return $out;
    }

    private static function csv_line( array $cells ): string {
        $out = array();
        foreach ( $cells as $value ) {
            if ( is_array( $value ) || is_object( $value ) ) $value = wp_json_encode( $value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
            $value = is_scalar( $value ) ? (string) $value : '';
            if ( '' !== $value && in_array( $value[0], array( '=', '+', '-', '@' ), true ) ) $value = "'" . $value;
            $out[] = '"' . str_replace( '"', '""', $value ) . '"';
        }
        return implode( ',', $out ) . "\r\n";
    }

    public static function download(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'Not allowed.', 'yablonsky-security' ) );
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce is verified immediately below using the job-specific action.
        $uuid = isset( $_GET['job'] ) ? sanitize_text_field( wp_unslash( $_GET['job'] ) ) : '';
        check_admin_referer( 'ysec_job_download_' . $uuid );
        $job = self::get_owned( $uuid );
        if ( ! $job || 'export' !== $job['kind'] || ! in_array( $job['status'], array( 'completed', 'downloaded' ), true ) ) {
            wp_die( esc_html__( 'Export is not ready.', 'yablonsky-security' ) );
        }

        $stamp = gmdate( 'Ymd-His' );
        nocache_headers();
        header( 'X-Content-Type-Options: nosniff' );
        if ( 'json' === $job['format_name'] ) {
            header( 'Content-Type: application/json; charset=utf-8' );
            header( 'Content-Disposition: attachment; filename="yablonsky-security-' . $job['dataset'] . '-' . $stamp . '.json"' );
            $filters = json_decode( (string) $job['filters'], true );
            echo '{"dataset":' . wp_json_encode( $job['dataset'] ) . ',"exported_at":' . wp_json_encode( gmdate( 'c' ) ) . ',"filters":' . wp_json_encode( is_array( $filters ) ? $filters : array() ) . ',"rows":['; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download stream; dynamic values are JSON-encoded.
            $first = true;
            for ( $part_no = 1; $part_no <= (int) $job['parts']; $part_no++ ) {
                $part = self::load_part( $uuid, $part_no );
                if ( '' === $part ) continue;
                if ( ! $first ) echo ','; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static JSON separator.
                echo $part; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Stored fragments were produced only by wp_json_encode().
                $first = false;
                if ( function_exists( 'flush' ) ) flush();
            }
            echo ']}'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static JSON suffix.
        } else {
            header( 'Content-Type: text/csv; charset=utf-8' );
            header( 'Content-Disposition: attachment; filename="yablonsky-security-' . $job['dataset'] . '-' . $stamp . '.csv"' );
            for ( $part_no = 1; $part_no <= (int) $job['parts']; $part_no++ ) {
                echo self::load_part( $uuid, $part_no ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV content is escaped/quoted by csv_line().
                if ( function_exists( 'flush' ) ) flush();
            }
        }
        self::update( $uuid, array( 'status' => 'downloaded' ) );
        exit;
    }

    private static function load_part( string $uuid, int $part_no ): string {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Streaming one private export part at a time avoids loading the entire completed export into PHP memory.
        $part = $wpdb->get_var( $wpdb->prepare( 'SELECT payload FROM %i WHERE job_uuid=%s AND part_no=%d', self::parts_table(), $uuid, $part_no ) );
        return is_string( $part ) ? $part : '';
    }

    private static function public_job( ?array $job ): array {
        if ( ! $job ) return array();
        $total     = max( 0, (int) $job['total'] );
        $processed = max( 0, (int) $job['processed'] );
        $pct       = $total ? min( 100, (int) floor( ( $processed / $total ) * 100 ) ) : 100;
        $out       = array(
            'job'        => $job['job_uuid'],
            'kind'       => $job['kind'],
            'dataset'    => $job['dataset'],
            'action'     => $job['action_name'],
            'format'     => $job['format_name'],
            'status'     => $job['status'],
            'total'      => $total,
            'processed'  => $processed,
            'changed'    => (int) $job['changed'],
            'percent'    => $pct,
            'created_at' => $job['created_at'],
            'updated_at' => $job['updated_at'],
            'unit'       => 'source_scope' === $job['kind'] ? 'sources' : ( 'account_scope' === $job['kind'] ? 'accounts' : ( 'export' === $job['kind'] ? 'records' : 'records' ) ),
        );
        if ( 'export' === $job['kind'] && 'completed' === $job['status'] ) {
            $url = add_query_arg(
                array(
                    'action' => 'ysec_job_download',
                    'job'    => $job['job_uuid'],
                ),
                admin_url( 'admin-post.php' )
            );
            // Use a raw query URL for JSON/JavaScript. wp_nonce_url() HTML-escapes ampersands and previously produced literal `&amp;` in the browser address bar.
            $out['downloadUrl'] = add_query_arg( '_wpnonce', wp_create_nonce( 'ysec_job_download_' . $job['job_uuid'] ), $url );
        }
        return $out;
    }

    public static function cleanup_expired(): bool {
        global $wpdb;
        $now   = current_time( 'mysql', true );
        $jobs  = self::table();
        $parts = self::parts_table();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled cleanup of temporary export data.
        $expired = $wpdb->get_col( $wpdb->prepare( 'SELECT job_uuid FROM %i WHERE expires_at<=%s', $jobs, $now ) );
        if ( ! is_array( $expired ) || ! empty( $wpdb->last_error ) ) return false;
        foreach ( $expired as $uuid ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Remove export parts before their parent job to avoid orphaned data.
            if ( false === $wpdb->delete( $parts, array( 'job_uuid' => $uuid ), array( '%s' ) ) ) return false;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled cleanup of temporary job state.
            if ( false === $wpdb->delete( $jobs, array( 'job_uuid' => $uuid ), array( '%s' ) ) ) return false;
        }
        return true;
    }
}
