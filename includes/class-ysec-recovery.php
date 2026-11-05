<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Encrypted local recovery checkpoints for YSec-owned configuration only; not a full-site database backup. */
final class YSEC_Recovery {
    private const INDEX_OPTION = 'ysec_recovery_index_v1';
    private const MAX_ITEMS = 5;

    public static function items(): array {
        $items = get_option( self::INDEX_OPTION, array() );
        if ( ! is_array( $items ) ) return array();
        uasort( $items, static fn( $a, $b ) => strcmp( (string) ( $b['created_at'] ?? '' ), (string) ( $a['created_at'] ?? '' ) ) );
        return $items;
    }

    public static function create( string $label = '' ): array {
        $payload = array(
            'schema'=>'yablonsky.security.recovery.v1',
            'created_at'=>gmdate( 'c' ),
            'site_hash'=>hash( 'sha256', strtolower( untrailingslashit( home_url( '/' ) ) ) ),
            'plugin_version'=>YSEC_VERSION,
            'state'=>array(
                'ysec_settings'=>get_option( 'ysec_settings', array() ),
                'ysec_firewall_policy'=>get_option( 'ysec_firewall_policy', array() ),
                'ysec_conditional_rules_v1'=>get_option( 'ysec_conditional_rules_v1', array() ),
                'ysec_virtual_patches_v2'=>get_option( 'ysec_virtual_patches_v2', array() ),
                'ysec_integrity_ignores'=>get_option( 'ysec_integrity_ignores', array() ),
                'ysec_security_headers_policy'=>get_option( 'ysec_security_headers_policy', array() ),
            ),
        );
        $json = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        if ( ! is_string( $json ) || '' === $json ) return array( 'ok'=>false, 'message'=>__( 'Recovery checkpoint could not be serialized.', 'yablonsky-security' ) );
        $encrypted = YSEC_Utils::encrypt( $json );
        if ( '' === $encrypted ) return array( 'ok'=>false, 'message'=>__( 'No supported local encryption backend is available for recovery checkpoints.', 'yablonsky-security' ) );
        $fs = self::filesystem();
        if ( ! $fs ) return array( 'ok'=>false, 'message'=>__( 'WordPress filesystem access is unavailable.', 'yablonsky-security' ) );
        $dir = self::dir();
        if ( ! wp_mkdir_p( $dir ) ) return array( 'ok'=>false, 'message'=>__( 'Recovery checkpoint directory could not be created.', 'yablonsky-security' ) );
        $guard = trailingslashit( $dir ) . 'index.php';
        if ( ! $fs->exists( $guard ) ) $fs->put_contents( $guard, "<?php\n// Silence is golden.\n", FS_CHMOD_FILE );
        $id = wp_generate_uuid4();
        $file = trailingslashit( $dir ) . $id . '.ysec';
        if ( ! $fs->put_contents( $file, $encrypted, FS_CHMOD_FILE ) ) return array( 'ok'=>false, 'message'=>__( 'Recovery checkpoint could not be written.', 'yablonsky-security' ) );
        $stored = $fs->get_contents( $file );
        $plain = false === $stored ? '' : YSEC_Utils::decrypt( $stored );
        $sha = hash( 'sha256', $json );
        if ( '' === $plain || ! hash_equals( $sha, hash( 'sha256', $plain ) ) ) {
            $fs->delete( $file );
            return array( 'ok'=>false, 'message'=>__( 'Recovery checkpoint verification failed.', 'yablonsky-security' ) );
        }
        $items = self::items();
        $items[$id] = array(
            'id'=>$id,
            'label'=>YSEC_Utils::log_string( sanitize_text_field( $label ?: __( 'Security policy checkpoint', 'yablonsky-security' ) ), 120 ),
            'created_at'=>$payload['created_at'],
            'plugin_version'=>YSEC_VERSION,
            'sha256'=>$sha,
            'size'=>strlen( $encrypted ),
            'actor'=>get_current_user_id(),
        );
        update_option( self::INDEX_OPTION, $items, false );
        self::trim();
        YSEC_Events::log( 'recovery_checkpoint_created', array( 'severity'=>'info','family'=>'configuration','details'=>array( 'id'=>$id ) ) );
        return array( 'ok'=>true, 'item'=>$items[$id] );
    }

    public static function verify( string $id ): array {
        $loaded = self::load( $id );
        if ( is_wp_error( $loaded ) ) return array( 'ok'=>false, 'message'=>$loaded->get_error_message() );
        return array( 'ok'=>true, 'message'=>__( 'Encrypted checkpoint verified against its recorded SHA-256.', 'yablonsky-security' ) );
    }

    public static function restore( string $id ): array {
        $loaded = self::load( $id );
        if ( is_wp_error( $loaded ) ) return array( 'ok'=>false, 'message'=>$loaded->get_error_message() );
        $state = is_array( $loaded['state'] ?? null ) ? $loaded['state'] : array();
        $allowed = array( 'ysec_settings','ysec_firewall_policy','ysec_conditional_rules_v1','ysec_virtual_patches_v2','ysec_integrity_ignores','ysec_security_headers_policy' );
        foreach ( $allowed as $key ) if ( array_key_exists( $key, $state ) ) update_option( $key, $state[$key], false );
        YSEC_Vulnerabilities::clear_cache();
        YSEC_Events::log( 'recovery_checkpoint_restored', array( 'severity'=>'medium','family'=>'configuration','details'=>array( 'id'=>$id,'actor'=>get_current_user_id() ) ) );
        return array( 'ok'=>true, 'message'=>__( 'YSec-owned policy state restored from the verified checkpoint.', 'yablonsky-security' ) );
    }

    public static function delete( string $id ): bool {
        $items = self::items();
        if ( empty( $items[$id] ) ) return false;
        $fs = self::filesystem(); if ( ! $fs ) return false;
        $file = trailingslashit( self::dir() ) . $id . '.ysec';
        if ( $fs->exists( $file ) && ! $fs->delete( $file ) ) return false;
        unset( $items[$id] ); update_option( self::INDEX_OPTION, $items, false );
        YSEC_Events::log( 'recovery_checkpoint_deleted', array( 'severity'=>'info','family'=>'configuration','details'=>array( 'id'=>$id ) ) );
        return true;
    }

    private static function load( string $id ) {
        $id = sanitize_text_field( $id ); $items = self::items();
        if ( empty( $items[$id] ) ) return new WP_Error( 'ysec_recovery_missing', __( 'Recovery checkpoint not found.', 'yablonsky-security' ) );
        $fs = self::filesystem(); if ( ! $fs ) return new WP_Error( 'ysec_recovery_fs', __( 'WordPress filesystem access is unavailable.', 'yablonsky-security' ) );
        $file = trailingslashit( self::dir() ) . $id . '.ysec';
        if ( ! $fs->exists( $file ) ) return new WP_Error( 'ysec_recovery_payload', __( 'Recovery checkpoint payload is missing.', 'yablonsky-security' ) );
        $encrypted = $fs->get_contents( $file ); $plain = false === $encrypted ? '' : YSEC_Utils::decrypt( $encrypted );
        if ( '' === $plain || ! hash_equals( (string) ( $items[$id]['sha256'] ?? '' ), hash( 'sha256', $plain ) ) ) return new WP_Error( 'ysec_recovery_integrity', __( 'Recovery checkpoint failed integrity verification.', 'yablonsky-security' ) );
        $payload = json_decode( $plain, true );
        if ( ! is_array( $payload ) || 'yablonsky.security.recovery.v1' !== ( $payload['schema'] ?? '' ) ) return new WP_Error( 'ysec_recovery_schema', __( 'Recovery checkpoint schema is invalid.', 'yablonsky-security' ) );
        $site_hash = hash( 'sha256', strtolower( untrailingslashit( home_url( '/' ) ) ) );
        if ( ! hash_equals( $site_hash, (string) ( $payload['site_hash'] ?? '' ) ) ) return new WP_Error( 'ysec_recovery_site', __( 'Recovery checkpoint belongs to a different site identity.', 'yablonsky-security' ) );
        return $payload;
    }

    private static function trim(): void {
        $items = self::items();
        if ( count( $items ) <= self::MAX_ITEMS ) return;
        $fs = self::filesystem();
        foreach ( array_slice( array_keys( $items ), self::MAX_ITEMS ) as $id ) {
            if ( $fs ) { $file = trailingslashit( self::dir() ) . $id . '.ysec'; if ( $fs->exists( $file ) ) $fs->delete( $file ); }
            unset( $items[$id] );
        }
        update_option( self::INDEX_OPTION, $items, false );
    }

    private static function filesystem() {
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) require_once ABSPATH . 'wp-admin/includes/file.php';
        if ( ! WP_Filesystem() || ! is_object( $wp_filesystem ) ) return null;
        return $wp_filesystem;
    }

    private static function dir(): string { return trailingslashit( WP_CONTENT_DIR ) . 'ysec-recovery'; }
}
