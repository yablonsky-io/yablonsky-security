<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Advisories {
    private const OPTION = 'ysec_local_advisories_v2';
    private const LEGACY_OPTION = 'ysec_local_advisories_v1';

    public static function boot(): void {
        add_filter( 'ysec_vulnerability_advisories', array( __CLASS__, 'provide' ), 20, 2 );
    }

    public static function provide( array $existing, array $inventory ): array {
        return array_merge( $existing, self::items() );
    }

    public static function items(): array {
        $items = get_option( self::OPTION, null );
        if ( null === $items ) {
            $items = get_option( self::LEGACY_OPTION, array() );
        }
        return is_array( $items ) ? array_values( array_filter( $items, 'is_array' ) ) : array();
    }

    public static function import_json( string $json ) {
        $decoded = json_decode( $json, true );
        if ( ! is_array( $decoded ) ) {
            return new WP_Error( 'ysec_advisory_json', __( 'Advisory JSON is invalid.', 'yablonsky-security' ) );
        }
        $rows = isset( $decoded['advisories'] ) && is_array( $decoded['advisories'] ) ? $decoded['advisories'] : $decoded;
        $feed_source = sanitize_text_field( (string) ( $decoded['source'] ?? $decoded['feed'] ?? 'local-import' ) );
        $feed_reference = esc_url_raw( (string) ( $decoded['source_url'] ?? $decoded['reference'] ?? '' ) );
        $feed_generated = self::sanitize_datetime( (string) ( $decoded['generated_at'] ?? '' ) );
        $out = array();
        $allowed_severity = array( 'critical','high','medium','low','info' );

        foreach ( $rows as $row ) {
            if ( ! is_array( $row ) ) continue;
            $component = sanitize_text_field( (string) ( $row['component'] ?? $row['slug'] ?? '' ) );
            $id = sanitize_text_field( (string) ( $row['id'] ?? $row['cve'] ?? '' ) );
            $severity = sanitize_key( (string) ( $row['severity'] ?? 'info' ) );
            if ( '' === $component || '' === $id || ! in_array( $severity, $allowed_severity, true ) ) continue;

            $package_type = sanitize_key( (string) ( $row['package_type'] ?? $row['type'] ?? 'plugin' ) );
            if ( ! in_array( $package_type, array( 'core','plugin','theme','unknown' ), true ) ) $package_type = 'unknown';
            $source = sanitize_text_field( (string) ( $row['source'] ?? $feed_source ) );
            if ( '' === $source ) $source = 'local-import';
            $reference = esc_url_raw( (string) ( $row['reference'] ?? $row['url'] ?? $feed_reference ) );
            $published_at = self::sanitize_datetime( (string) ( $row['published_at'] ?? $row['published'] ?? '' ) );
            $updated_at = self::sanitize_datetime( (string) ( $row['updated_at'] ?? $row['modified_at'] ?? $feed_generated ) );
            $cve = strtoupper( sanitize_text_field( (string) ( $row['cve'] ?? ( preg_match( '/^CVE-/i', $id ) ? $id : '' ) ) ) );
            $cvss = isset( $row['cvss'] ) && is_numeric( $row['cvss'] ) ? max( 0, min( 10, (float) $row['cvss'] ) ) : null;
            $fixed_in = YSEC_Utils::log_string( (string) ( $row['fixed_in'] ?? '' ), 80 );
            $min_version = YSEC_Utils::log_string( (string) ( $row['min_version'] ?? $row['affected_min'] ?? '' ), 80 );
            $max_version = YSEC_Utils::log_string( (string) ( $row['max_version'] ?? $row['affected_max'] ?? '' ), 80 );
            $max_inclusive = ! empty( $row['max_inclusive'] );

            $patch = array();
            if ( isset( $row['virtual_patch'] ) && is_array( $row['virtual_patch'] ) ) {
                $mode = sanitize_key( (string) ( $row['virtual_patch']['mode'] ?? '' ) );
                $path = sanitize_text_field( (string) ( $row['virtual_patch']['path'] ?? '' ) );
                $methods = self::sanitize_methods( $row['virtual_patch']['methods'] ?? array() );
                $expires_at = self::sanitize_datetime( (string) ( $row['virtual_patch']['expires_at'] ?? '' ) );
                if ( in_array( $mode, array( 'exact_path','path_prefix' ), true ) && str_starts_with( $path, '/' ) && strlen( $path ) <= 256 ) {
                    $patch = array( 'mode'=>$mode, 'path'=>$path, 'methods'=>$methods, 'expires_at'=>$expires_at );
                }
            }

            $normalized = array(
                'id'=>$id,
                'cve'=>$cve,
                'component'=>$component,
                'package_type'=>$package_type,
                'severity'=>$severity,
                'cvss'=>$cvss,
                'title'=>YSEC_Utils::log_string( (string) ( $row['title'] ?? $id ), 240 ),
                'affected'=>YSEC_Utils::log_string( (string) ( $row['affected'] ?? '' ), 120 ),
                'min_version'=>$min_version,
                'max_version'=>$max_version,
                'max_inclusive'=>$max_inclusive,
                'fixed_in'=>$fixed_in,
                'source'=>$source,
                'reference'=>$reference,
                'published_at'=>$published_at,
                'updated_at'=>$updated_at,
                'virtual_patch'=>$patch,
            );
            $normalized['evidence_sha256'] = hash( 'sha256', wp_json_encode( $normalized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ?: '' );
            $out[] = $normalized;
            if ( count( $out ) >= 1000 ) break;
        }

        if ( ! $out ) {
            return new WP_Error( 'ysec_advisory_empty', __( 'No valid advisory records were found.', 'yablonsky-security' ) );
        }
        update_option( self::OPTION, $out, false );
        delete_option( self::LEGACY_OPTION );
        update_option( 'ysec_advisory_store_meta', array(
            'imported_at'=>gmdate( 'c' ),
            'source'=>$feed_source ?: 'local-import',
            'source_url'=>$feed_reference,
            'generated_at'=>$feed_generated,
            'count'=>count( $out ),
            'sha256'=>hash( 'sha256', wp_json_encode( $out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ?: '' ),
        ), false );
        YSEC_Vulnerabilities::clear_cache();
        YSEC_Events::log( 'advisory_store_imported', array( 'severity'=>'info','family'=>'vulnerability','details'=>array( 'count'=>count( $out ), 'source'=>$feed_source ?: 'local-import' ) ) );
        return count( $out );
    }

    public static function summary(): array {
        $items = self::items();
        $meta = get_option( 'ysec_advisory_store_meta', array() );
        $sources = array();
        $latest = 0;
        $with_reference = 0;
        foreach ( $items as $item ) {
            $source = sanitize_text_field( (string) ( $item['source'] ?? 'local-import' ) );
            if ( '' !== $source ) $sources[$source] = true;
            if ( ! empty( $item['reference'] ) ) $with_reference++;
            foreach ( array( 'updated_at','published_at' ) as $field ) {
                $ts = ! empty( $item[$field] ) ? strtotime( (string) $item[$field] ) : false;
                if ( $ts && $ts > $latest ) $latest = $ts;
            }
        }
        $imported = ! empty( $meta['imported_at'] ) ? strtotime( (string) $meta['imported_at'] ) : false;
        if ( $imported && $imported > $latest ) $latest = $imported;
        $age_hours = $latest ? max( 0, (int) floor( ( time() - $latest ) / HOUR_IN_SECONDS ) ) : null;
        return array(
            'count'=>count( $items ),
            'sources'=>array_keys( $sources ),
            'source_count'=>count( $sources ),
            'with_reference'=>$with_reference,
            'latest_at'=>$latest ? gmdate( 'c', $latest ) : '',
            'age_hours'=>$age_hours,
            'freshness_state'=>null === $age_hours ? 'unknown' : ( $age_hours <= 72 ? 'fresh' : ( $age_hours <= 336 ? 'aging' : 'stale' ) ),
            'store_sha256'=>sanitize_text_field( (string) ( is_array( $meta ) ? ( $meta['sha256'] ?? '' ) : '' ) ),
        );
    }

    public static function clear(): void {
        delete_option( self::OPTION );
        delete_option( self::LEGACY_OPTION );
        delete_option( 'ysec_advisory_store_meta' );
        YSEC_Vulnerabilities::clear_cache();
    }

    private static function sanitize_datetime( string $value ): string {
        $value = trim( $value );
        if ( '' === $value ) return '';
        $ts = strtotime( $value );
        return false === $ts ? '' : gmdate( 'c', $ts );
    }

    private static function sanitize_methods( $value ): array {
        if ( is_string( $value ) ) $value = preg_split( '/[\s,]+/', $value ) ?: array();
        if ( ! is_array( $value ) ) return array();
        $allowed = array( 'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS' );
        $out = array();
        foreach ( $value as $method ) {
            $method = strtoupper( sanitize_text_field( (string) $method ) );
            if ( in_array( $method, $allowed, true ) ) $out[] = $method;
        }
        return array_values( array_unique( $out ) );
    }
}
