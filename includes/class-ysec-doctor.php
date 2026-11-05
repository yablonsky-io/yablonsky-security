<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Passive self-test. It never changes state and never makes an external request. */
final class YSEC_Doctor {
    public static function report(): array {
        $checks = array();
        self::add( $checks, 'runtime_slug', __( 'Runtime plugin folder', 'yablonsky-security' ), 'yablonsky-security' === basename( dirname( YSEC_FILE ) ), basename( dirname( YSEC_FILE ) ), __( 'Expected lowercase slug: yablonsky-security.', 'yablonsky-security' ) );
        self::add( $checks, 'version', __( 'Product version', 'yablonsky-security' ), (bool) preg_match( '/^\d+\.\d+\.\d+$/', YSEC_VERSION ), YSEC_VERSION, __( 'Version must be normalized MAJOR.MINOR.PATCH.', 'yablonsky-security' ) );
        $db_version = (string) get_option( 'ysec_db_version', '' );
        $db_target = defined( 'YSEC_DB_VERSION' ) ? YSEC_DB_VERSION : YSEC_VERSION;
        self::add( $checks, 'db_version', __( 'Database schema marker', 'yablonsky-security' ), hash_equals( (string) $db_target, $db_version ), $db_version ?: __( 'Missing', 'yablonsky-security' ), __( 'The stored schema marker must match the schema contract expected by this YSec build.', 'yablonsky-security' ) );

        $schema = YSEC_DB::schema_contract();
        $missing_indexes = is_array( $schema['missing'] ?? null ) ? $schema['missing'] : array();
        self::add(
            $checks,
            'db_index_contract',
            __( 'Database index contract', 'yablonsky-security' ),
            ! empty( $schema['ok'] ),
            ! empty( $schema['ok'] ) ? __( 'Complete', 'yablonsky-security' ) : self::schema_gap_label( $missing_indexes ),
            __( 'YSec verifies the required indexes after dbDelta before accepting a schema upgrade as complete.', 'yablonsky-security' )
        );

        global $wpdb;
        foreach ( array( 'events','blocks','integrity','jobs','job_parts','event_rollups','rollup_days' ) as $table_key ) {
            $table = YSEC_DB::table( $table_key );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Passive self-test for plugin-owned schema presence.
            $found = (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
            /* translators: %s: plugin-owned database table suffix. */
            $table_label = sprintf( __( 'Table: %s', 'yablonsky-security' ), $table_key );
            self::add( $checks, 'table_' . $table_key, $table_label, hash_equals( $table, $found ), $found ? __( 'Present', 'yablonsky-security' ) : __( 'Missing', 'yablonsky-security' ), __( 'YSec-owned table required by the current runtime.', 'yablonsky-security' ) );
        }

        self::add( $checks, 'cron_daily', __( 'Daily maintenance schedule', 'yablonsky-security' ), (bool) wp_next_scheduled( 'ysec_daily_maintenance' ), wp_next_scheduled( 'ysec_daily_maintenance' ) ? __( 'Scheduled', 'yablonsky-security' ) : __( 'Missing', 'yablonsky-security' ), __( 'Permissions and maintenance tasks depend on the daily hook.', 'yablonsky-security' ) );
        self::add( $checks, 'cron_hourly', __( 'Hourly cleanup schedule', 'yablonsky-security' ), (bool) wp_next_scheduled( 'ysec_hourly_cleanup' ), wp_next_scheduled( 'ysec_hourly_cleanup' ) ? __( 'Scheduled', 'yablonsky-security' ) : __( 'Missing', 'yablonsky-security' ), __( 'Evidence retention and cleanup depend on the hourly hook.', 'yablonsky-security' ) );

        $crypto = function_exists( 'sodium_crypto_secretbox' ) ? 'libsodium' : ( function_exists( 'openssl_encrypt' ) ? 'OpenSSL' : '' );
        self::add( $checks, 'crypto', __( 'Local encryption backend', 'yablonsky-security' ), '' !== $crypto, $crypto ?: __( 'Unavailable', 'yablonsky-security' ), __( 'Encrypted API keys, quarantine and recovery checkpoints require an authenticated local encryption backend.', 'yablonsky-security' ) );

        $rules = YSEC_Conditional_Rules::all();
        $rule_ok = count( $rules ) <= 50;
        /* translators: %d: number of stored conditional firewall rules. */
        $rule_count_label = sprintf( __( '%d stored rules', 'yablonsky-security' ), count( $rules ) );
        self::add( $checks, 'conditional_rules', __( 'Conditional firewall policy', 'yablonsky-security' ), $rule_ok, $rule_count_label, __( 'The deny-only ruleset is bounded to 50 entries.', 'yablonsky-security' ) );

        foreach ( array( 'ysec-recovery'=>trailingslashit( WP_CONTENT_DIR ) . 'ysec-recovery', 'ysec-quarantine'=>trailingslashit( WP_CONTENT_DIR ) . 'ysec-quarantine' ) as $key=>$dir ) {
            $exists = is_dir( $dir );
            $ok = ! $exists || ( is_readable( $dir ) && wp_is_writable( $dir ) );
            /* translators: %s: local protected-store directory name. */
            $store_label = sprintf( __( 'Protected local store: %s', 'yablonsky-security' ), $key );
            self::add( $checks, 'dir_' . sanitize_key( $key ), $store_label, $ok, $exists ? ( $ok ? __( 'Readable / writable', 'yablonsky-security' ) : __( 'Permission issue', 'yablonsky-security' ) ) : __( 'Not created yet', 'yablonsky-security' ), __( 'The directory is created only when that feature is used.', 'yablonsky-security' ) );
        }

        $comment_guard_ok = YSEC_Comment_Guard::proof_self_test();
        self::add(
            $checks,
            'comment_guard',
            __( 'Anonymous comment form proof', 'yablonsky-security' ),
            $comment_guard_ok,
            $comment_guard_ok ? __( 'Ready', 'yablonsky-security' ) : __( 'Failed', 'yablonsky-security' ),
            __( 'The local cache-compatible form proof must round-trip before it can protect standard anonymous comment submissions.', 'yablonsky-security' )
        );

        $mu = YSEC_Managed_MU::status();
        $mu_installed = ! empty( $mu['installed'] );
        $mu_ok = ! $mu_installed || ( ! empty( $mu['owned'] ) && ! empty( $mu['runtime_readable'] ) && ! empty( $mu['policy_valid'] ) );
        self::add(
            $checks,
            'managed_mu_runtime',
            __( 'Managed MU early security runtime', 'yablonsky-security' ),
            $mu_ok,
            $mu_installed ? ( $mu_ok ? __( 'Installed / handshake valid', 'yablonsky-security' ) : __( 'Installed / needs review', 'yablonsky-security' ) ) : __( 'Optional · not installed', 'yablonsky-security' ),
            __( 'The optional MU bridge must remain thin, YSec-owned, ABI-compatible and fail-safe when installed.', 'yablonsky-security' )
        );

        if ( YSEC_AI::configured() ) {
            $ai_state = YSEC_AI::state();
            $settings = YSEC_Utils::settings();
            $models = is_array( $ai_state['models'] ?? null ) ? $ai_state['models'] : array();
            $writer = is_array( $ai_state['model_projection'] ?? null ) ? (string) ( $ai_state['model_projection']['writer_default'] ?? '' ) : '';
            $selected = sanitize_text_field( (string) ( $settings['ai_model_id'] ?? '' ) );
            $route_ok = '' !== $selected || '' !== $writer || ! empty( $models );
            /* translators: %d: number of usable text models in the authenticated catalog. */
            $catalog_label = sprintf( __( '%d catalog models', 'yablonsky-security' ), count( $models ) );
            self::add( $checks, 'ai_route', __( 'Yablonsky AI text route', 'yablonsky-security' ), $route_ok, '' !== $selected ? $selected : ( $writer ?: $catalog_label ), __( 'A configured AI account should expose either a selected model, Writer default or usable text-model catalog.', 'yablonsky-security' ) );
        } else {
            self::add( $checks, 'ai_route', __( 'Yablonsky AI text route', 'yablonsky-security' ), true, __( 'Optional · not connected', 'yablonsky-security' ), __( 'Local protection does not require the external AI service.', 'yablonsky-security' ) );
        }

        $passed = count( array_filter( $checks, static fn( $row ) => ! empty( $row['pass'] ) ) );
        return array(
            'checks' => $checks,
            'passed' => $passed,
            'total'  => count( $checks ),
            'ok'     => $passed === count( $checks ),
            'ran_at' => current_time( 'mysql', true ),
            // Read-only localization evidence: supplied with Doctor exports to
            // distinguish a missing catalog from a loaded but incorrect locale.
            // The user-selected WordPress language is authoritative for admin.
            'translation_runtime' => self::translation_runtime(),
        );
    }

    private static function translation_runtime(): array {
        $locale = is_admin() && function_exists( 'get_user_locale' )
            ? (string) get_user_locale()
            : (string) determine_locale();
        $valid = (bool) preg_match( '/^[A-Za-z0-9_@.-]+$/', $locale );
        $catalog = $valid ? YSEC_DIR . 'languages/yablonsky-security-' . $locale . '.mo' : '';
        $sample = __( 'Overview', 'yablonsky-security' );
        // Direct bundled-MO proof, independent of WordPress/WPML translation state.
        $reader = new YSEC_Bundled_MO();
        $read_ok = '' !== $catalog && $reader->import_from_file( $catalog );
        $bundled_sample = $read_ok ? $reader->translate( 'Overview' ) : 'Overview';
        return array(
            'selected_locale' => $locale,
            'runtime_locale' => (string) determine_locale(),
            'bundled_catalog_exists' => '' !== $catalog && is_readable( $catalog ),
            'domain_loaded' => is_textdomain_loaded( 'yablonsky-security' ),
            'overview_sample' => $sample,
            'overview_translated' => 'Overview' !== $sample,
            'domain_specific_fallback_registered' => (bool) has_filter( 'gettext_yablonsky-security', array( 'YSEC_Plugin', 'fallback_gettext' ) ),
            'generic_gettext_fallback_registered' => (bool) has_filter( 'gettext', array( 'YSEC_Plugin', 'fallback_gettext' ) ),
            'bundled_mo_readable' => $read_ok,
            'bundled_overview_sample' => $bundled_sample,
            'bundled_overview_translated' => $read_ok && 'Overview' !== $bundled_sample,
        );
    }

    private static function schema_gap_label( array $missing ): string {
        $parts = array();
        foreach ( $missing as $table => $indexes ) {
            $names = is_array( $indexes ) ? array_map( 'sanitize_key', $indexes ) : array();
            if ( $names ) $parts[] = sanitize_key( (string) $table ) . ': ' . implode( ', ', $names );
        }
        if ( ! $parts ) return __( 'Index contract needs repair', 'yablonsky-security' );
        return implode( ' · ', array_slice( $parts, 0, 3 ) );
    }

    private static function add( array &$checks, string $id, string $label, bool $pass, string $value, string $detail ): void {
        $checks[] = array( 'id'=>$id, 'label'=>$label, 'pass'=>$pass, 'value'=>$value, 'detail'=>$detail );
    }
}
