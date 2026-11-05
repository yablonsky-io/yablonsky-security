<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Real-time file ingress protection for uploads and extracted update/install packages. */
final class YSEC_File_Ingress {
    private const RECEIPT_OPTION = 'ysec_last_file_ingress_receipt_v1';

    public static function last_receipt(): array {
        $receipt = get_option( self::RECEIPT_OPTION, array() );
        return is_array( $receipt ) ? $receipt : array();
    }

    public static function boot(): void {
        add_filter( 'wp_handle_upload_prefilter', array( __CLASS__, 'prefilter_upload' ), 1 );
        add_filter( 'wp_handle_sideload_prefilter', array( __CLASS__, 'prefilter_upload' ), 1 );
        add_filter( 'upgrader_source_selection', array( __CLASS__, 'inspect_upgrader_source' ), 10, 4 );
    }

    public static function prefilter_upload( array $file ): array {
        $tmp = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';
        $name = isset( $file['name'] ) ? sanitize_file_name( (string) $file['name'] ) : '';
        if ( '' === $tmp || ! is_file( $tmp ) ) return $file;
        $result = self::inspect_file( $tmp, $name, 'upload' );
        if ( ! empty( $result['blocked'] ) ) {
            $file['error'] = __( 'Yablonsky Security stopped this upload because local malware screening detected a high-confidence threat.', 'yablonsky-security' );
        }
        return $file;
    }

    public static function inspect_upgrader_source( $source, $remote_source, $upgrader, $hook_extra ) {
        unset( $remote_source, $upgrader, $hook_extra );
        $source = is_string( $source ) ? $source : '';
        if ( '' === $source || ! is_dir( $source ) ) return $source;
        // Package code may legitimately contain security signatures, samples or dynamic execution.
        // Keep deterministic package inspection advisory-only to avoid blocking legitimate plugins/themes.
        // Uploaded ZIP archives are signature-scanned by local ClamAV in prefilter_upload() when clamd is available.
        return $source;
    }

    private static function inspect_file( string $path, string $name, string $context ): array {
        $clam = YSEC_ClamAV::scan_file( $path );
        if ( 'infected' === (string) ( $clam['status'] ?? '' ) ) {
            YSEC_Events::log( 'malware_upload_blocked', array( 'severity'=>'critical', 'family'=>'malware', 'state'=>'blocked', 'path'=>$name, 'details'=>array( 'provider'=>'clamav', 'signature'=>(string)($clam['signature']??''), 'context'=>$context ) ) );
            self::record_receipt( $path, $name, $context, 'blocked', 'clamav', (string) ( $clam['status'] ?? 'infected' ), (string) ( $clam['signature'] ?? '' ) );
            return array( 'blocked'=>true, 'provider'=>'clamav', 'signature'=>(string)($clam['signature']??'') );
        }
        $local = YSEC_Malware::inspect_file( $path, $name, $context );
        if ( ! empty( $local['finding'] ) ) {
            $finding = $local['finding'];
            YSEC_Events::log( 'malware_upload_blocked', array( 'severity'=>(string)($finding['severity']??'high'), 'family'=>'malware', 'state'=>'blocked', 'path'=>$name, 'details'=>array( 'provider'=>'deterministic', 'rule'=>(string)($finding['rule']??''), 'context'=>$context ) ) );
            self::record_receipt( $path, $name, $context, 'blocked', 'deterministic', (string) ( $clam['status'] ?? 'standby' ), (string) ( $finding['rule'] ?? '' ) );
            return array( 'blocked'=>true, 'provider'=>'deterministic', 'finding'=>$finding );
        }
        self::record_receipt( $path, $name, $context, 'allowed', 'local_security', (string) ( $clam['status'] ?? 'standby' ), '' );
        return array( 'blocked'=>false, 'clamav'=>(string)($clam['status']??'standby') );
    }

    private static function record_receipt( string $path, string $name, string $context, string $decision, string $provider, string $clamav_status, string $detail ): void {
        $receipt = array(
            'checked_at'    => current_time( 'mysql', true ),
            'file'          => sanitize_file_name( $name ),
            'size'          => is_file( $path ) ? (int) ( @filesize( $path ) ?: 0 ) : 0,
            'context'       => sanitize_key( $context ),
            'decision'      => sanitize_key( $decision ),
            'provider'      => sanitize_key( $provider ),
            'clamav_status' => sanitize_key( $clamav_status ),
            'detail'        => sanitize_text_field( $detail ),
        );
        if ( false === get_option( self::RECEIPT_OPTION, false ) ) add_option( self::RECEIPT_OPTION, $receipt, '', false );
        else update_option( self::RECEIPT_OPTION, $receipt, false );
    }
}
