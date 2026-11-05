<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_DB  {
    public static function table( string $name ): string  {
        global $wpdb;
        return $wpdb->prefix . 'ysec_' . $name;
    }
    public static function storage_health(): array {
        $cached = get_transient( 'ysec_storage_health_v1' );
        if ( is_array( $cached ) ) return $cached;
        global $wpdb;
        $events = self::table( 'events' );
        $rollups = self::table( 'event_rollups' );
        $jobs = self::table( 'jobs' );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short-lived diagnostics for plugin-owned tables.
        $event_row = $wpdb->get_row( $wpdb->prepare( 'SELECT COUNT(*) rows_count,COALESCE(SUM(hit_count),0) hits,MIN(observed_at) oldest,MAX(observed_at) newest FROM %i', $events ), ARRAY_A );
        // A failed metrics query must never be cached or displayed as a healthy 0%.
        // Preserve the public array contract, but mark all measurements unavailable.
        if ( ! is_array( $event_row ) || ! empty( $wpdb->last_error ) ) return self::unavailable_storage_health();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short-lived diagnostics for compact rollups.
        $rollup_row = $wpdb->get_row( $wpdb->prepare( 'SELECT COUNT(*) rows_count,MIN(day) oldest_day,MAX(day) newest_day,COALESCE(SUM(hits),0) hits FROM %i', $rollups ), ARRAY_A );
        if ( ! is_array( $rollup_row ) || ! empty( $wpdb->last_error ) ) return self::unavailable_storage_health();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Current active background-job count.
        $jobs_result = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status IN ('running','paused','failed') AND expires_at>%s", $jobs, current_time('mysql',true) ) );
        if ( null === $jobs_result || ! empty( $wpdb->last_error ) ) return self::unavailable_storage_health();
        $active_jobs = (int) $jobs_result;
        $ceiling = max( 10000, absint( YSEC_Utils::option( 'event_max_rows', 250000 ) ) );
        $rows = (int) ( $event_row['rows_count'] ?? 0 );
        // Report actual overage; cap only the visual meter, never the metric.
        $pressure = round( 100 * $rows / max( 1, $ceiling ), 1 );
        $out = array(
            'valid'=>true,
            'event_rows'=>$rows,
            'event_hits'=>(int)($event_row['hits']??0),
            'oldest_event'=>(string)($event_row['oldest']??''),
            'newest_event'=>(string)($event_row['newest']??''),
            'rollup_rows'=>(int)($rollup_row['rows_count']??0),
            'rollup_hits'=>(int)($rollup_row['hits']??0),
            'oldest_rollup'=>(string)($rollup_row['oldest_day']??''),
            'newest_rollup'=>(string)($rollup_row['newest_day']??''),
            'active_jobs'=>$active_jobs,
            'row_ceiling'=>$ceiling,
            'pressure_percent'=>$pressure,
        );
        set_transient( 'ysec_storage_health_v1', $out, 20 );
        return $out;
    }

    /** Keep the established storage-health shape without inventing measurements. */
    private static function unavailable_storage_health(): array {
        return array(
            'valid'=>false,
            'event_rows'=>0, 'event_hits'=>0, 'oldest_event'=>'', 'newest_event'=>'',
            'rollup_rows'=>0, 'rollup_hits'=>0, 'oldest_rollup'=>'', 'newest_rollup'=>'',
            'active_jobs'=>0, 'row_ceiling'=>0, 'pressure_percent'=>0.0,
        );
    }

    public static function activate( bool $network_wide = false ): void  {
        if ( is_multisite() && $network_wide )  {
            foreach ( get_sites( array( 'number' => 0, 'fields' => 'ids' ) ) as $site_id )  {
                switch_to_blog( (int) $site_id );
                self::install_current_site();
                restore_current_blog();
            }
            return;
        }
        self::install_current_site();
    }
    public static function maybe_upgrade(): void  {
        static $checked = false;
        if ( $checked ) {
            return;
        }
        $checked = true;
        $target = defined( 'YSEC_DB_VERSION' ) ? YSEC_DB_VERSION : YSEC_VERSION;
        $current = (string) get_option( 'ysec_db_version', '' );
        if ( $target !== $current ) {
            // A failed schema migration must not hammer dbDelta on every request.
            // The guard is target-specific so a newer plugin build is never held
            // behind the cooldown left by a failed migration from an older schema.
            $retry_guard = 'ysec_db_upgrade_retry_' . sanitize_key( str_replace( '.', '_', (string) $target ) );
            if ( get_transient( $retry_guard ) ) return;
            set_transient( $retry_guard, 1, 5 * MINUTE_IN_SECONDS );
            self::install_current_site();
        }
    }
    public static function install_current_site(): void  {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset=$wpdb->get_charset_collate();
        $events=self::table('events');
        $blocks=self::table('blocks');
        $integrity=self::table('integrity');
        $jobs=self::table('jobs');
        $job_parts=self::table('job_parts');
        $rollups=self::table('event_rollups');
        $rollup_days=self::table('rollup_days');
        dbDelta("CREATE TABLE $events (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            event_uuid char(36) NOT NULL,
            observed_at datetime NOT NULL,
            first_seen_at datetime NULL,
            last_seen_at datetime NULL,
            hit_count bigint unsigned NOT NULL DEFAULT 1,
            request_id char(36) NOT NULL DEFAULT '',
            aggregation_key char(64) NULL,
            type varchar(64) NOT NULL,
            severity varchar(16) NOT NULL,
            confidence varchar(16) NOT NULL,
            state varchar(32) NOT NULL,
            family varchar(64) NOT NULL,
            path varchar(2048) NOT NULL DEFAULT '',
            method varchar(12) NOT NULL DEFAULT '',
            status_code smallint unsigned NOT NULL DEFAULT 0,
            source_hash char(64) NOT NULL DEFAULT '',
            source_enc longtext NULL,
            user_agent varchar(512) NOT NULL DEFAULT '',
            country char(2) NOT NULL DEFAULT '',
            query_redacted varchar(1024) NOT NULL DEFAULT '',
            classifier_version varchar(32) NOT NULL DEFAULT '',
            reviewed tinyint(1) NOT NULL DEFAULT 0,
            archived tinyint(1) NOT NULL DEFAULT 0,
            details longtext NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY event_uuid (event_uuid),
            UNIQUE KEY aggregation_key (aggregation_key),
            KEY observed_at (observed_at),
            KEY last_seen_at (last_seen_at),
            KEY family (family),
            KEY severity (severity),
            KEY state (state),
            KEY type (type),
            KEY source_hash (source_hash),
            KEY country (country),
            KEY archived_observed (archived,observed_at),
            KEY archived_state_observed (archived,state,observed_at),
            KEY reviewed_observed (reviewed,observed_at),
            KEY severity_observed (severity,observed_at),
            KEY family_observed (family,observed_at),
            KEY source_state_observed (source_hash,state,observed_at),
            KEY type_severity_observed (type,severity,observed_at),
            KEY country_observed (country,observed_at)
        ) $charset;");
        dbDelta("CREATE TABLE $blocks (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            source varchar(45) NOT NULL,
            source_hash char(64) NOT NULL,
            source_enc longtext NULL,
            source_version varchar(16) NOT NULL DEFAULT 'legacy_ua',
            reason varchar(255) NOT NULL,
            created_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            active tinyint(1) NOT NULL DEFAULT 1,
            PRIMARY KEY  (id),
            KEY source_hash (source_hash),
            KEY expires_at (expires_at),
            KEY active (active),
            KEY active_expires (active,expires_at)
        ) $charset;");
        dbDelta("CREATE TABLE $integrity (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            path varchar(512) NOT NULL,
            baseline_hash char(64) NOT NULL DEFAULT '',
            observed_hash char(64) NOT NULL DEFAULT '',
            state varchar(24) NOT NULL,
            baseline_version varchar(32) NOT NULL DEFAULT '',
            first_seen datetime NOT NULL,
            last_seen datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY path (path(191)),
            KEY state (state)
        ) $charset;");
        dbDelta("CREATE TABLE $jobs (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            job_uuid char(36) NOT NULL,
            owner_user_id bigint unsigned NOT NULL DEFAULT 0,
            kind varchar(24) NOT NULL,
            dataset varchar(24) NOT NULL,
            action_name varchar(40) NOT NULL DEFAULT '',
            format_name varchar(12) NOT NULL DEFAULT '',
            status varchar(20) NOT NULL DEFAULT 'running',
            filters longtext NULL,
            cursor_value bigint unsigned NOT NULL DEFAULT 0,
            max_id bigint unsigned NOT NULL DEFAULT 0,
            total bigint unsigned NOT NULL DEFAULT 0,
            processed bigint unsigned NOT NULL DEFAULT 0,
            changed bigint unsigned NOT NULL DEFAULT 0,
            parts int unsigned NOT NULL DEFAULT 0,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            result longtext NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY job_uuid (job_uuid),
            KEY owner_status (owner_user_id,status),
            KEY expires_at (expires_at)
        ) $charset;");
        dbDelta("CREATE TABLE $job_parts (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            job_uuid char(36) NOT NULL,
            part_no int unsigned NOT NULL,
            payload longtext NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY job_part (job_uuid,part_no),
            KEY job_uuid (job_uuid)
        ) $charset;");
        dbDelta("CREATE TABLE $rollups (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            day date NOT NULL,
            family varchar(64) NOT NULL DEFAULT '',
            severity varchar(16) NOT NULL DEFAULT '',
            state varchar(32) NOT NULL DEFAULT '',
            country char(2) NOT NULL DEFAULT '',
            hits bigint unsigned NOT NULL DEFAULT 0,
            records bigint unsigned NOT NULL DEFAULT 0,
            blocked_hits bigint unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            UNIQUE KEY day_dimension (day,family,severity,state,country),
            KEY day (day),
            KEY family (family),
            KEY severity (severity),
            KEY country (country)
        ) $charset;");
        dbDelta("CREATE TABLE $rollup_days (
            day date NOT NULL,
            finalized_at datetime NOT NULL,
            PRIMARY KEY  (day)
        ) $charset;");
        self::migrate_legacy_block_identities();
        add_option( 'ysec_settings', YSEC_Utils::settings() );

        $schema = self::schema_contract();
        if ( empty( $schema['ok'] ) ) {
            self::repair_schema_contract( $schema );
            $schema = self::schema_contract();
        }
        update_option( 'ysec_db_schema_status_v1', array(
            'checked_at' => current_time( 'mysql', true ),
            'target'     => defined( 'YSEC_DB_VERSION' ) ? YSEC_DB_VERSION : YSEC_VERSION,
            'ok'         => ! empty( $schema['ok'] ),
            'missing'    => $schema['missing'] ?? array(),
        ), false );
        if ( ! empty( $schema['ok'] ) ) {
            update_option( 'ysec_db_version', defined( 'YSEC_DB_VERSION' ) ? YSEC_DB_VERSION : YSEC_VERSION, false );
            $target = defined( 'YSEC_DB_VERSION' ) ? YSEC_DB_VERSION : YSEC_VERSION;
            delete_transient( 'ysec_db_upgrade_retry_' . sanitize_key( str_replace( '.', '_', (string) $target ) ) );
        }

        if ( ! wp_next_scheduled( 'ysec_daily_maintenance' ) )  {
            wp_schedule_event( time()+300, 'daily', 'ysec_daily_maintenance' );
        }
        if ( ! wp_next_scheduled( 'ysec_hourly_cleanup' ) )  {
            wp_schedule_event( time()+600, 'hourly', 'ysec_hourly_cleanup' );
        }
    }
    /**
     * Verify the index contract that dbDelta must establish for YSec-owned tables.
     * This intentionally checks the failure mode observed in production: malformed
     * combined index declarations were parsed as columns named UNIQUE/KEY.
     */
    public static function schema_contract(): array {
        global $wpdb;
        $expected = array(
            'events' => array( 'PRIMARY','event_uuid','aggregation_key','observed_at','last_seen_at','family','severity','state','type','source_hash','country','archived_observed','archived_state_observed','reviewed_observed','severity_observed','family_observed','source_state_observed','type_severity_observed','country_observed' ),
            'blocks' => array( 'PRIMARY','source_hash','expires_at','active','active_expires' ),
            'integrity' => array( 'PRIMARY','path','state' ),
            'jobs' => array( 'PRIMARY','job_uuid','owner_status','expires_at' ),
            'job_parts' => array( 'PRIMARY','job_part','job_uuid' ),
            'event_rollups' => array( 'PRIMARY','day_dimension','day','family','severity','country' ),
            'rollup_days' => array( 'PRIMARY' ),
        );
        $missing = array();
        foreach ( $expected as $table_key => $required ) {
            $table = self::table( $table_key );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Passive verification of indexes on plugin-owned schema immediately after dbDelta.
            $rows = $wpdb->get_results( $wpdb->prepare( 'SHOW INDEX FROM %i', $table ), ARRAY_A );
            if ( ! is_array( $rows ) || array() === $rows ) {
                $missing[ $table_key ] = $required;
                continue;
            }
            $found = array();
            foreach ( $rows as $row ) {
                $name = isset( $row['Key_name'] ) ? (string) $row['Key_name'] : '';
                if ( '' !== $name ) $found[ $name ] = true;
            }
            $absent = array_values( array_filter( $required, static fn( $name ) => empty( $found[ $name ] ) ) );
            if ( $absent ) $missing[ $table_key ] = $absent;
        }
        return array( 'ok'=>array() === $missing, 'missing'=>$missing );
    }

    /**
     * Repair only the exact, allowlisted indexes owned by the current YSec schema.
     * dbDelta remains the portable first pass; this closes known parser/legacy drift
     * without accepting a schema marker until SHOW INDEX proves the contract.
     */
    public static function repair_schema_contract( array $schema = array() ): array {
        if ( empty( $schema ) ) {
            $schema = self::schema_contract();
        }
        $missing = isset( $schema['missing'] ) && is_array( $schema['missing'] ) ? $schema['missing'] : array();
        if ( ! $missing ) {
            return self::schema_contract();
        }

        // Historical builds could write aggregation keys before the UNIQUE index was
        // successfully established. Keep every evidence row and hit_count, clear only
        // the legacy compression identities, then re-establish the unique contract.
        // New writes resume normal aggregation after the index exists.
        if ( ! empty( $missing['events'] ) && in_array( 'aggregation_key', (array) $missing['events'], true ) ) {
            self::normalize_aggregation_key_duplicates();
        }

        foreach ( $missing as $table_key => $indexes ) {
            foreach ( (array) $indexes as $index_name ) {
                self::add_known_index( (string) $table_key, (string) $index_name );
            }
        }
        return self::schema_contract();
    }

    private static function normalize_aggregation_key_duplicates(): void {
        global $wpdb;
        $events = self::table( 'events' );
        // The historical key is only a compression identity, never evidence itself.
        // Clearing legacy keys preserves every row and hit_count while avoiding an
        // unindexed self-join on large evidence tables. New writes resume normal
        // aggregation as soon as the UNIQUE index is established below.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time corrective normalization in the plugin-owned evidence table; no evidence rows or hit counts are deleted.
        $wpdb->query( $wpdb->prepare( 'UPDATE %i SET aggregation_key=NULL WHERE aggregation_key IS NOT NULL', $events ) );
    }

    /**
     * Add one exact schema index. Every ALTER statement is a fixed allowlisted SQL
     * literal so neither an index clause nor a column list can come from runtime data.
     */
    private static function add_known_index( string $table_key, string $index_name ): void {
        global $wpdb;
        $table = self::table( $table_key );
        $key = $table_key . ':' . $index_name;

        switch ( $key ) {
            case 'events:PRIMARY':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD PRIMARY KEY (`id`)', $table ) );
                break;
            case 'events:event_uuid':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD UNIQUE KEY `event_uuid` (`event_uuid`)', $table ) );
                break;
            case 'events:aggregation_key':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD UNIQUE KEY `aggregation_key` (`aggregation_key`)', $table ) );
                break;
            case 'events:observed_at':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `observed_at` (`observed_at`)', $table ) );
                break;
            case 'events:last_seen_at':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `last_seen_at` (`last_seen_at`)', $table ) );
                break;
            case 'events:family':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `family` (`family`)', $table ) );
                break;
            case 'events:severity':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `severity` (`severity`)', $table ) );
                break;
            case 'events:state':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `state` (`state`)', $table ) );
                break;
            case 'events:type':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `type` (`type`)', $table ) );
                break;
            case 'events:source_hash':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `source_hash` (`source_hash`)', $table ) );
                break;
            case 'events:country':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `country` (`country`)', $table ) );
                break;
            case 'events:archived_observed':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `archived_observed` (`archived`,`observed_at`)', $table ) );
                break;
            case 'events:archived_state_observed':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `archived_state_observed` (`archived`,`state`,`observed_at`)', $table ) );
                break;
            case 'events:reviewed_observed':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `reviewed_observed` (`reviewed`,`observed_at`)', $table ) );
                break;
            case 'events:severity_observed':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `severity_observed` (`severity`,`observed_at`)', $table ) );
                break;
            case 'events:family_observed':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `family_observed` (`family`,`observed_at`)', $table ) );
                break;
            case 'events:source_state_observed':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `source_state_observed` (`source_hash`,`state`,`observed_at`)', $table ) );
                break;
            case 'events:type_severity_observed':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `type_severity_observed` (`type`,`severity`,`observed_at`)', $table ) );
                break;
            case 'events:country_observed':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `country_observed` (`country`,`observed_at`)', $table ) );
                break;
            case 'blocks:PRIMARY':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD PRIMARY KEY (`id`)', $table ) );
                break;
            case 'blocks:source_hash':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `source_hash` (`source_hash`)', $table ) );
                break;
            case 'blocks:expires_at':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `expires_at` (`expires_at`)', $table ) );
                break;
            case 'blocks:active':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `active` (`active`)', $table ) );
                break;
            case 'blocks:active_expires':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `active_expires` (`active`,`expires_at`)', $table ) );
                break;
            case 'integrity:PRIMARY':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD PRIMARY KEY (`id`)', $table ) );
                break;
            case 'integrity:path':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD UNIQUE KEY `path` (`path`(191))', $table ) );
                break;
            case 'integrity:state':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `state` (`state`)', $table ) );
                break;
            case 'jobs:PRIMARY':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD PRIMARY KEY (`id`)', $table ) );
                break;
            case 'jobs:job_uuid':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD UNIQUE KEY `job_uuid` (`job_uuid`)', $table ) );
                break;
            case 'jobs:owner_status':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `owner_status` (`owner_user_id`,`status`)', $table ) );
                break;
            case 'jobs:expires_at':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `expires_at` (`expires_at`)', $table ) );
                break;
            case 'job_parts:PRIMARY':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD PRIMARY KEY (`id`)', $table ) );
                break;
            case 'job_parts:job_part':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD UNIQUE KEY `job_part` (`job_uuid`,`part_no`)', $table ) );
                break;
            case 'job_parts:job_uuid':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `job_uuid` (`job_uuid`)', $table ) );
                break;
            case 'event_rollups:PRIMARY':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD PRIMARY KEY (`id`)', $table ) );
                break;
            case 'event_rollups:day_dimension':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD UNIQUE KEY `day_dimension` (`day`,`family`,`severity`,`state`,`country`)', $table ) );
                break;
            case 'event_rollups:day':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `day` (`day`)', $table ) );
                break;
            case 'event_rollups:family':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `family` (`family`)', $table ) );
                break;
            case 'event_rollups:severity':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `severity` (`severity`)', $table ) );
                break;
            case 'event_rollups:country':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD KEY `country` (`country`)', $table ) );
                break;
            case 'rollup_days:PRIMARY':
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted DDL for a plugin-owned table; only the table identifier is prepared.
                $wpdb->query( $wpdb->prepare( 'ALTER TABLE %i ADD PRIMARY KEY (`day`)', $table ) );
                break;
            default:
                return;
        }
    }

    private static function migrate_legacy_block_identities(): void  {
        global $wpdb;
        $table = self::table( 'blocks' );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time guarded migration of legacy source identities in the plugin-owned block table.
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT id,source FROM %i WHERE source_version=%s AND source<>%s LIMIT 5000", $table, 'legacy_ua', '' ), ARRAY_A ) ?: array();
        foreach ( $rows as $row ) {
            $ip = filter_var( (string) $row['source'], FILTER_VALIDATE_IP ) ? (string) $row['source'] : '';
            if ( '' === $ip ) continue;
            $values = array(
                'source'         => YSEC_Utils::masked_ip( $ip ),
                'source_hash'    => YSEC_Utils::source_identity( $ip ),
                'source_enc'     => YSEC_Utils::encrypt( $ip ),
                'source_version' => 'stable_ip',
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time migration write to the dedicated block table.
            $wpdb->update( $table, $values, array( 'id' => (int) $row['id'] ), array( '%s', '%s', '%s', '%s' ), array( '%d' ) );
        }
    }

    public static function deactivate(): void  {
        wp_clear_scheduled_hook( 'ysec_daily_maintenance' );
        wp_clear_scheduled_hook( 'ysec_hourly_cleanup' );
    }
    public static function cleanup(): void  {
        global $wpdb;
        // Read a fresh baseline so retention receipts do not reuse an older UI cache.
        delete_transient( 'ysec_storage_health_v1' );
        $before = self::storage_health();
        if ( empty( $before['valid'] ) ) {
            self::retention_error( 'storage_read_before' );
            return;
        }
        // Preserve all raw evidence whenever a closed-day rollup cannot be
        // verified. A later hourly run can safely retry the idempotent upsert.
        if ( ! self::rollup_closed_days() ) {
            self::retention_error( 'daily_rollup' );
            return;
        }
        if ( ! self::tiered_evidence_cleanup() ) return;
        $days=max(1,(int)YSEC_Utils::option('retention_days',30));
        $cut=gmdate('Y-m-d H:i:s', time()-DAY_IN_SECONDS*$days);
        // Keep operational/audit evidence on the general retention window; request evidence is handled by severity tiers above.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled retention cleanup of dedicated plugin table.
        if ( ! self::retention_delete( $wpdb->prepare( "DELETE FROM %i WHERE type NOT IN ('request_decision','waf_match','request_signal','l7_abuse_signal') AND COALESCE(last_seen_at,observed_at) < %s", self::table('events'), $cut ), 'operational_evidence' ) ) return;
        // L7 request signals share the severity-based lifecycle, but are deleted
        // in small slices: an unbounded SQL delete can stall a busy store.
        if ( ! self::cleanup_l7_evidence() ) return;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled retention cleanup of dedicated plugin table.
        if ( ! self::retention_delete( $wpdb->prepare( 'DELETE FROM %i WHERE active=0 OR expires_at < %s', self::table('blocks'), current_time('mysql',true) ), 'expired_blocks' ) ) return;
        $rollup_cut=gmdate('Y-m-d',time()-DAY_IN_SECONDS*max(30,(int)YSEC_Utils::option('rollup_days',365)));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled compact analytics retention.
        if ( ! self::retention_delete( $wpdb->prepare('DELETE FROM %i WHERE day < %s',self::table('event_rollups'),$rollup_cut), 'rollup_expiry' ) ) return;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled rollup marker retention.
        if ( ! self::retention_delete( $wpdb->prepare('DELETE FROM %i WHERE day < %s',self::table('rollup_days'),$rollup_cut), 'marker_expiry' ) ) return;
        if ( ! self::enforce_event_ceiling() ) return;
        if ( ! YSEC_Jobs::cleanup_expired() ) {
            self::retention_error( 'expired_jobs' );
            return;
        }
        self::invalidate_evidence_caches();
        // Cleanup changes the same data that Storage health caches for the UI.
        delete_transient( 'ysec_storage_health_v1' );
        $after = self::storage_health();
        if ( empty( $after['valid'] ) ) {
            self::retention_error( 'storage_read_after' );
            return;
        }
        delete_option( 'ysec_last_retention_error' );
        $cycle = array(
            'ran_at'       => current_time( 'mysql', true ),
            'rows_before'  => (int) ( $before['event_rows'] ?? 0 ),
            'rows_after'   => (int) ( $after['event_rows'] ?? 0 ),
            'rows_removed' => max( 0, (int) ( $before['event_rows'] ?? 0 ) - (int) ( $after['event_rows'] ?? 0 ) ),
            'rollup_rows'  => (int) ( $after['rollup_rows'] ?? 0 ),
            'pressure'     => (float) ( $after['pressure_percent'] ?? 0 ),
            'row_ceiling'  => (int) ( $after['row_ceiling'] ?? 0 ),
            'excess_after' => max( 0, (int) ( $after['event_rows'] ?? 0 ) - (int) ( $after['row_ceiling'] ?? 0 ) ),
            'ceiling_complete' => (int) ( $after['event_rows'] ?? 0 ) <= (int) ( $after['row_ceiling'] ?? 0 ),
        );
        update_option( 'ysec_last_retention_cycle', $cycle, false );
        if ( $cycle['rows_removed'] > 0 ) {
            YSEC_Events::log( 'evidence_retention_cycle', array( 'severity'=>'info', 'family'=>'maintenance', 'state'=>'completed', 'details'=>$cycle ) );
        }
    }

    /**
     * A query failure is distinct from deleting zero rows. Keep the current
     * success receipt unchanged on partial failure, and retry on the next run.
     * No SQL text or private event data is persisted in the warning option.
     */
    /**
     * Expired evidence changes multiple independently cached views. Invalidating
     * the unsuffixed analytics key did nothing: actual dashboards use _7/_30.
     * Clear known live views after both success and partial SQL failure.
     */
    private static function invalidate_evidence_caches(): void {
        foreach ( array(
            'ysec_event_storage_summary_v2',
            'ysec_event_summary_24h_v2',
            'ysec_event_filter_options_v2',
            'ysec_threat_analytics_v1_7',
            'ysec_threat_analytics_v1_30',
            'ysec_recon_summary_v1_24',
            'ysec_firewall_decision_summary_v1_24',
            'ysec_crawler_claim_security_v1_24',
            'ysec_operations_v1_24',
        ) as $key ) delete_transient( $key );
    }

    private static function retention_error( string $phase ): void {
        // Earlier DELETE statements may already have succeeded. Never show a
        // stale storage count or pressure score after a partial cycle.
        delete_transient( 'ysec_storage_health_v1' );
        self::invalidate_evidence_caches();
        update_option( 'ysec_last_retention_error', array(
            'at'    => current_time( 'mysql', true ),
            'phase' => $phase,
        ), false );
    }

    private static function retention_delete( string $sql, string $phase ): bool {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- The only callers pass $wpdb->prepare() output for plugin-owned tables; writes must not be cached.
        if ( false === $wpdb->query( $sql ) ) {
            self::retention_error( $phase );
            return false;
        }
        return true;
    }

    public static function last_retention_cycle(): array {
        $cycle = get_option( 'ysec_last_retention_cycle', array() );
        return is_array( $cycle ) ? $cycle : array();
    }

    private static function rollup_closed_days(): bool {
        global $wpdb;
        $events=self::table('events'); $markers=self::table('rollup_days');
        $today=gmdate('Y-m-d'); $from=gmdate('Y-m-d',time()-DAY_IN_SECONDS*max(30,(int)YSEC_Utils::option('rollup_days',365)));
        // Skip already-finalized days in the SQL query. A fixed LIMIT over all
        // source days would repeatedly return the first 400 marked days and
        // starve older historical ranges when rollup_days permits >400 days.
        // Fetch one sentinel beyond our batch size: until every closed day has
        // been rolled up, do not start irreversible raw-event cleanup.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded discovery against plugin-owned evidence and rollup markers.
        $days = $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT DATE(e.observed_at) FROM %i e LEFT JOIN %i d ON d.day=DATE(e.observed_at) WHERE e.observed_at >= %s AND e.observed_at < %s AND d.day IS NULL ORDER BY DATE(e.observed_at) ASC LIMIT 401', $events, $markers, $from, $today ) );
        if ( ! is_array( $days ) || ! empty( $wpdb->last_error ) ) return false;
        $has_more = count( $days ) > 400;
        foreach ( array_slice( $days, 0, 400 ) as $day ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Day marker prevents duplicate finalization.
            $done = $wpdb->get_var( $wpdb->prepare( 'SELECT day FROM %i WHERE day=%s', $markers, $day ) );
            if ( ! empty( $wpdb->last_error ) ) return false;
            if ( $done ) continue;
            if ( ! self::finalize_rollup_day( (string) $day ) ) return false;
        }
        return ! $has_more;
    }

    private static function finalize_rollup_day( string $day ): bool {
        global $wpdb;
        $events=self::table('events'); $rollups=self::table('event_rollups'); $markers=self::table('rollup_days');
        $start=$day.' 00:00:00'; $end=gmdate('Y-m-d H:i:s',strtotime($day.' +1 day'));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Idempotent compact day summary before raw retention.
        $rows = $wpdb->query( $wpdb->prepare( "INSERT INTO %i (day,family,severity,state,country,hits,records,blocked_hits) SELECT %s,family,severity,state,country,SUM(hit_count),COUNT(*),SUM(CASE WHEN state IN ('blocked','request_denied','source_blocked','campaign_contained') THEN hit_count ELSE 0 END) FROM %i WHERE observed_at >= %s AND observed_at < %s GROUP BY family,severity,state,country ON DUPLICATE KEY UPDATE hits=VALUES(hits),records=VALUES(records),blocked_hits=VALUES(blocked_hits)", $rollups, $day, $events, $start, $end ) );
        if ( false === $rows ) return false;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- The marker is written only after a successful summary query.
        return false !== $wpdb->replace( $markers, array( 'day'=>$day, 'finalized_at'=>current_time('mysql',true) ), array('%s','%s') );
    }

    private static function tiered_evidence_cleanup(): bool {
        global $wpdb;
        $table=self::table('events');
        $cuts=array(
            'info'=>gmdate('Y-m-d H:i:s',time()-DAY_IN_SECONDS*max(1,(int)YSEC_Utils::option('evidence_retention_info',1))),
            'medium'=>gmdate('Y-m-d H:i:s',time()-DAY_IN_SECONDS*max(1,(int)YSEC_Utils::option('evidence_retention_medium',3))),
            'high'=>gmdate('Y-m-d H:i:s',time()-DAY_IN_SECONDS*max(1,(int)YSEC_Utils::option('evidence_retention_high',7))),
            'critical'=>gmdate('Y-m-d H:i:s',time()-DAY_IN_SECONDS*max(1,(int)YSEC_Utils::option('evidence_retention_critical',30))),
        );
        // Keep these branches explicit so neither severity identifiers nor SQL fragments originate in request/config data.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled bounded evidence cleanup.
        if ( ! self::retention_delete( $wpdb->prepare("DELETE FROM %i WHERE type IN ('request_decision','waf_match','request_signal') AND severity IN ('info','low') AND (last_seen_at < %s OR (last_seen_at IS NULL AND observed_at < %s))",$table,$cuts['info'],$cuts['info']), 'tiered_evidence' ) ) return false;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled bounded evidence cleanup.
        if ( ! self::retention_delete( $wpdb->prepare("DELETE FROM %i WHERE type IN ('request_decision','waf_match','request_signal') AND severity='medium' AND (last_seen_at < %s OR (last_seen_at IS NULL AND observed_at < %s))",$table,$cuts['medium'],$cuts['medium']), 'tiered_evidence' ) ) return false;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled bounded evidence cleanup.
        if ( ! self::retention_delete( $wpdb->prepare("DELETE FROM %i WHERE type IN ('request_decision','waf_match','request_signal') AND severity='high' AND (last_seen_at < %s OR (last_seen_at IS NULL AND observed_at < %s))",$table,$cuts['high'],$cuts['high']), 'tiered_evidence' ) ) return false;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled bounded evidence cleanup.
        if ( ! self::retention_delete( $wpdb->prepare("DELETE FROM %i WHERE type IN ('request_decision','waf_match','request_signal') AND severity='critical' AND (last_seen_at < %s OR (last_seen_at IS NULL AND observed_at < %s))",$table,$cuts['critical'],$cuts['critical']), 'tiered_evidence' ) ) return false;
        return true;
    }

    /**
     * Apply request-signal severity policy to L7 evidence. Work is intentionally
     * capped, so a long backlog is drained over subsequent hourly runs rather
     * than one oversized DELETE. No new schema or settings are required.
     */
    private static function cleanup_l7_evidence(): bool {
        global $wpdb;
        $table = self::table( 'events' );
        $deadline = microtime( true ) + 8.0;
        $remaining_batches = 6;
        foreach ( array( 'info', 'medium', 'high', 'critical' ) as $severity ) {
            $days = max( 1, absint( YSEC_Utils::option( 'evidence_retention_' . $severity, array( 'info'=>1, 'medium'=>3, 'high'=>7, 'critical'=>30 )[ $severity ] ) ) );
            $cut = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS * $days );
            do {
                if ( $remaining_batches <= 0 || microtime( true ) >= $deadline ) return true;
                $remaining_batches--;
                $batch = 2500;
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Prepared bounded retention for one L7 severity tier on a plugin-owned table.
                $deleted = self::retention_ceiling_write( $wpdb->prepare( "DELETE FROM %i WHERE type='l7_abuse_signal' AND severity=%s AND (last_seen_at < %s OR (last_seen_at IS NULL AND observed_at < %s)) ORDER BY observed_at ASC,id ASC LIMIT %d", $table, $severity, $cut, $cut, $batch ) );
                if ( null === $deleted ) {
                    self::retention_error( 'tiered_l7_evidence' );
                    return false;
                }
            } while ( $deleted === $batch );
        }
        return true;
    }

    /**
     * A bounded, priority-ordered storage ceiling. Each preferred tier is
     * drained (or the execution budget exhausted) before touching the next.
     * Incomplete progress is explicitly persisted: a successful SQL statement
     * is NOT a claim that the configured row ceiling was achieved.
     */
    private static function enforce_event_ceiling(): bool {
        global $wpdb;
        $table = self::table( 'events' );
        $max   = max( 10000, min( 2000000, absint( YSEC_Utils::option( 'event_max_rows', 250000 ) ) ) );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Hourly exact count of dedicated plugin evidence.
        $count_result = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table ) );
        if ( null === $count_result || ! empty( $wpdb->last_error ) ) {
            self::retention_error( 'event_ceiling_count' );
            return false;
        }
        $excess = max( 0, (int) $count_result - $max );
        $starting_excess = $excess;
        $deleted_total = 0;
        $batches = 0;
        $deadline = microtime( true ) + 12.0;
        $max_batches = 10;
        foreach ( array( 'archived', 'low', 'medium', 'oldest' ) as $tier ) {
            while ( $excess > 0 && $batches < $max_batches && microtime( true ) < $deadline ) {
                $batch = min( $excess, 3000 );
                $deleted = self::delete_event_ceiling_batch( $table, $tier, $batch );
                if ( null === $deleted ) {
                    self::retention_error( 'event_ceiling_delete' );
                    return false;
                }
                $deleted_total += $deleted;
                $excess -= $deleted;
                $batches++;
                // This priority tier has no more eligible rows. Only then
                // proceed to less-preferred evidence; never skip over medium
                // just because its first 3,000-row batch was full.
                if ( $deleted < $batch ) break;
            }
            if ( $excess <= 0 || $batches >= $max_batches || microtime( true ) >= $deadline ) break;
        }
        // Counts are a snapshot: concurrent inserts can increase actual excess.
        // Storage Health is independently reread after this pass.
        update_option( 'ysec_last_ceiling_status_v1', array(
            'checked_at'        => current_time( 'mysql', true ),
            'ceiling'           => $max,
            'excess_at_start'   => $starting_excess,
            'deleted_in_pass'   => $deleted_total,
            'remaining_estimate'=> max( 0, $excess ),
            'complete_at_snapshot'=> $excess <= 0,
            'batches'          => $batches,
        ), false );
        return true;
    }

    private static function retention_ceiling_write( string $sql ): ?int {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- All four private callers pass $wpdb->prepare() output; no caching for irreversible deletion.
        $result = $wpdb->query( $sql );
        return false === $result ? null : (int) $result;
    }

    private static function delete_event_ceiling_batch( string $table, string $tier, int $batch ): ?int {
        global $wpdb;
        if ( 'archived' === $tier ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Staged retention delete from the plugin-owned evidence table.
            return self::retention_ceiling_write( $wpdb->prepare( 'DELETE FROM %i WHERE archived=1 ORDER BY COALESCE(last_seen_at,observed_at) ASC,id ASC LIMIT %d', $table, $batch ) );
        }
        if ( 'low' === $tier ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Staged retention delete from the plugin-owned evidence table.
            return self::retention_ceiling_write( $wpdb->prepare( "DELETE FROM %i WHERE severity IN ('info','low') ORDER BY COALESCE(last_seen_at,observed_at) ASC,id ASC LIMIT %d", $table, $batch ) );
        }
        if ( 'medium' === $tier ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Staged retention delete from the plugin-owned evidence table.
            return self::retention_ceiling_write( $wpdb->prepare( "DELETE FROM %i WHERE severity='medium' ORDER BY COALESCE(last_seen_at,observed_at) ASC,id ASC LIMIT %d", $table, $batch ) );
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Final oldest-first retention delete from the plugin-owned evidence table.
        return self::retention_ceiling_write( $wpdb->prepare( 'DELETE FROM %i ORDER BY COALESCE(last_seen_at,observed_at) ASC,id ASC LIMIT %d', $table, $batch ) );
    }

}
