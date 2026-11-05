<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Explicit, reversible quarantine for administrator-reviewed wp-content findings. */
final class YSEC_Quarantine {
    private static function dir(): string { return trailingslashit( WP_CONTENT_DIR ) . 'ysec-quarantine'; }

    public static function items(): array {
        $items = get_option( 'ysec_quarantine_index', array() );
        return is_array( $items ) ? $items : array();
    }

    private static function filesystem() {
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) require_once ABSPATH . 'wp-admin/includes/file.php';
        if ( ! WP_Filesystem() || ! is_object( $wp_filesystem ) ) return null;
        return $wp_filesystem;
    }

    public static function quarantine( string $relative_path, array $context = array() ): array {
        $source = self::resolve_wp_content_path( $relative_path );
        if ( is_wp_error( $source ) ) return array( 'ok'=>false, 'message'=>$source->get_error_message() );
        $fs = self::filesystem();
        if ( ! $fs ) return array( 'ok'=>false, 'message'=>__( 'WordPress filesystem access is unavailable.', 'yablonsky-security' ) );
        if ( ! is_file( $source ) || ! is_readable( $source ) ) return array( 'ok'=>false, 'message'=>__( 'The selected file is not readable.', 'yablonsky-security' ) );
        if ( false !== YSEC_Malware::trusted_runtime_artifact( $source, $relative_path ) ) return array( 'ok'=>false, 'message'=>__( 'This file matches a verified non-executable runtime configuration format and is not eligible for malware quarantine.', 'yablonsky-security' ) );
        if ( str_starts_with( wp_normalize_path( $source ), wp_normalize_path( YSEC_DIR ) ) ) return array( 'ok'=>false, 'message'=>__( 'Yablonsky Security will not quarantine its own active plugin files.', 'yablonsky-security' ) );
        $size = filesize( $source );
        if ( false === $size || $size > 5 * MB_IN_BYTES ) return array( 'ok'=>false, 'message'=>__( 'Quarantine is limited to reviewed files up to 5 MB.', 'yablonsky-security' ) );
        $raw = $fs->get_contents( $source );
        if ( false === $raw ) return array( 'ok'=>false, 'message'=>__( 'The selected file could not be read.', 'yablonsky-security' ) );
        $encrypted = YSEC_Utils::encrypt( $raw );
        if ( '' === $encrypted ) return array( 'ok'=>false, 'message'=>__( 'No supported local encryption backend is available for quarantine.', 'yablonsky-security' ) );
        $dir = self::dir();
        if ( ! wp_mkdir_p( $dir ) ) return array( 'ok'=>false, 'message'=>__( 'The quarantine directory could not be created.', 'yablonsky-security' ) );
        $index = trailingslashit( $dir ) . 'index.php';
        if ( ! $fs->exists( $index ) ) $fs->put_contents( $index, "<?php\n// Silence is golden.\n", FS_CHMOD_FILE );
        $id = wp_generate_uuid4();
        $blob = trailingslashit( $dir ) . $id . '.qsec';
        if ( ! $fs->put_contents( $blob, $encrypted, FS_CHMOD_FILE ) ) return array( 'ok'=>false, 'message'=>__( 'The encrypted quarantine copy could not be written.', 'yablonsky-security' ) );
        $sha = hash( 'sha256', $raw );
        $stored = $fs->get_contents( $blob );
        if ( false === $stored || ! hash_equals( $sha, hash( 'sha256', YSEC_Utils::decrypt( $stored ) ) ) ) {
            $fs->delete( $blob );
            return array( 'ok'=>false, 'message'=>__( 'Quarantine verification failed; the original file was left untouched.', 'yablonsky-security' ) );
        }
        if ( ! $fs->delete( $source ) ) {
            $fs->delete( $blob );
            return array( 'ok'=>false, 'message'=>__( 'The verified quarantine copy was created, but the original file could not be removed.', 'yablonsky-security' ) );
        }
        $items = self::items();
        $items[$id] = array(
            'id'=>$id,
            'path'=>self::relative_to_content( $source ),
            'sha256'=>$sha,
            'size'=>(int)$size,
            'quarantined_at'=>gmdate( 'c' ),
            'actor'=>get_current_user_id(),
            'rule'=>sanitize_key( (string) ( $context['rule'] ?? '' ) ),
            'reason'=>YSEC_Utils::log_string( (string) ( $context['reason'] ?? '' ), 300 ),
            'source_scan_sha256'=>sanitize_text_field( (string) ( $context['sha256'] ?? $sha ) ),
        );
        update_option( 'ysec_quarantine_index', $items, false );
        YSEC_Events::log( 'malware_quarantined', array( 'severity'=>'high', 'family'=>'malware', 'state'=>'contained', 'path'=>$items[$id]['path'], 'details'=>array( 'sha256'=>$sha, 'size'=>(int)$size ) ) );
        return array( 'ok'=>true, 'item'=>$items[$id] );
    }

    public static function verify_item( string $id ): array {
        $id = sanitize_text_field( $id );
        $items = self::items();
        if ( empty( $items[$id] ) ) return array( 'ok'=>false, 'message'=>__( 'Quarantine item not found.', 'yablonsky-security' ) );
        $fs = self::filesystem();
        if ( ! $fs ) return array( 'ok'=>false, 'message'=>__( 'WordPress filesystem access is unavailable.', 'yablonsky-security' ) );
        $blob = trailingslashit( self::dir() ) . $id . '.qsec';
        if ( ! $fs->exists( $blob ) ) return array( 'ok'=>false, 'message'=>__( 'Encrypted quarantine payload is missing.', 'yablonsky-security' ) );
        $encrypted = $fs->get_contents( $blob );
        $raw = false === $encrypted ? '' : YSEC_Utils::decrypt( $encrypted );
        $ok = '' !== $raw && hash_equals( (string) ( $items[$id]['sha256'] ?? '' ), hash( 'sha256', $raw ) );
        return array( 'ok'=>$ok, 'message'=>$ok ? __( 'Encrypted payload verified against its recorded SHA-256.', 'yablonsky-security' ) : __( 'Quarantine payload failed SHA-256 verification.', 'yablonsky-security' ) );
    }

    public static function restore( string $id ): array {
        $id = sanitize_text_field( $id );
        $items = self::items();
        if ( empty( $items[$id] ) ) return array( 'ok'=>false, 'message'=>__( 'Quarantine item not found.', 'yablonsky-security' ) );
        $fs = self::filesystem();
        if ( ! $fs ) return array( 'ok'=>false, 'message'=>__( 'WordPress filesystem access is unavailable.', 'yablonsky-security' ) );
        $item = $items[$id];
        $blob = trailingslashit( self::dir() ) . $id . '.qsec';
        if ( ! $fs->exists( $blob ) ) return array( 'ok'=>false, 'message'=>__( 'Encrypted quarantine payload is missing.', 'yablonsky-security' ) );
        $encrypted = $fs->get_contents( $blob );
        $raw = false === $encrypted ? '' : YSEC_Utils::decrypt( $encrypted );
        if ( '' === $raw || ! hash_equals( (string) $item['sha256'], hash( 'sha256', $raw ) ) ) return array( 'ok'=>false, 'message'=>__( 'Quarantine payload failed integrity verification.', 'yablonsky-security' ) );
        $target = trailingslashit( WP_CONTENT_DIR ) . ltrim( (string) $item['path'], '/\\' );
        $target_norm = wp_normalize_path( $target );
        if ( ! str_starts_with( $target_norm, trailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) ) ) return array( 'ok'=>false, 'message'=>__( 'Restore target is outside wp-content.', 'yablonsky-security' ) );
        if ( $fs->exists( $target ) ) return array( 'ok'=>false, 'message'=>__( 'Restore target already exists. Review it before restoring the quarantined copy.', 'yablonsky-security' ) );
        if ( ! wp_mkdir_p( dirname( $target ) ) || ! $fs->put_contents( $target, $raw, FS_CHMOD_FILE ) ) return array( 'ok'=>false, 'message'=>__( 'The quarantined file could not be restored.', 'yablonsky-security' ) );
        $fs->delete( $blob );
        unset( $items[$id] );
        update_option( 'ysec_quarantine_index', $items, false );
        YSEC_Events::log( 'malware_restored', array( 'severity'=>'medium', 'family'=>'malware', 'state'=>'observed', 'path'=>(string)$item['path'] ) );
        return array( 'ok'=>true );
    }

    public static function delete( string $id ): bool {
        $id = sanitize_text_field( $id );
        $items = self::items();
        if ( empty( $items[$id] ) ) return false;
        $fs = self::filesystem();
        if ( ! $fs ) return false;
        $blob = trailingslashit( self::dir() ) . $id . '.qsec';
        if ( $fs->exists( $blob ) && ! $fs->delete( $blob ) ) return false;
        $path = (string) $items[$id]['path'];
        unset( $items[$id] );
        update_option( 'ysec_quarantine_index', $items, false );
        YSEC_Events::log( 'malware_quarantine_deleted', array( 'severity'=>'medium', 'family'=>'malware', 'state'=>'reviewed', 'path'=>$path ) );
        return true;
    }

    private static function resolve_wp_content_path( string $relative_path ) {
        $relative_path = ltrim( wp_normalize_path( $relative_path ), '/\\' );
        if ( str_starts_with( $relative_path, 'wp-content/' ) ) $relative_path = substr( $relative_path, strlen( 'wp-content/' ) );
        if ( '' === $relative_path || str_contains( $relative_path, '../' ) ) return new WP_Error( 'ysec_bad_path', __( 'Invalid quarantine path.', 'yablonsky-security' ) );
        $candidate = trailingslashit( WP_CONTENT_DIR ) . $relative_path;
        $real = realpath( $candidate );
        if ( false === $real ) return new WP_Error( 'ysec_missing_path', __( 'The selected file no longer exists.', 'yablonsky-security' ) );
        $root = trailingslashit( wp_normalize_path( realpath( WP_CONTENT_DIR ) ?: WP_CONTENT_DIR ) );
        $real_norm = wp_normalize_path( $real );
        if ( ! str_starts_with( $real_norm, $root ) ) return new WP_Error( 'ysec_path_escape', __( 'The selected path resolves outside wp-content.', 'yablonsky-security' ) );
        return $real;
    }

    private static function relative_to_content( string $path ): string {
        $root = trailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
        $path = wp_normalize_path( $path );
        return str_starts_with( $path, $root ) ? substr( $path, strlen( $root ) ) : basename( $path );
    }
}
