<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Permissions {
    public static function targets(): array {
        $uploads = wp_upload_dir( null, false );
        $targets = array(
            array( 'name'=>'WordPress root', 'path'=>untrailingslashit( ABSPATH ), 'kind'=>'dir', 'recommended'=>0755 ),
            array( 'name'=>'wp-admin', 'path'=>ABSPATH . 'wp-admin', 'kind'=>'dir', 'recommended'=>0755 ),
            array( 'name'=>'wp-includes', 'path'=>ABSPATH . 'wp-includes', 'kind'=>'dir', 'recommended'=>0755 ),
            array( 'name'=>'wp-content', 'path'=>WP_CONTENT_DIR, 'kind'=>'dir', 'recommended'=>0755 ),
            array( 'name'=>'plugins', 'path'=>WP_PLUGIN_DIR, 'kind'=>'dir', 'recommended'=>0755 ),
            array( 'name'=>'themes', 'path'=>get_theme_root(), 'kind'=>'dir', 'recommended'=>0755 ),
            array( 'name'=>'uploads', 'path'=>(string) ( $uploads['basedir'] ?? '' ), 'kind'=>'dir', 'recommended'=>0755 ),
            array( 'name'=>'wp-config.php', 'path'=>self::wp_config_path(), 'kind'=>'file', 'recommended'=>0640 ),
            array( 'name'=>'index.php', 'path'=>ABSPATH . 'index.php', 'kind'=>'file', 'recommended'=>0644 ),
        );
        if ( file_exists( ABSPATH . '.htaccess' ) ) $targets[] = array( 'name'=>'.htaccess', 'path'=>ABSPATH . '.htaccess', 'kind'=>'file', 'recommended'=>0644 );
        return array_values( array_filter( $targets, static fn( $row ) => '' !== (string) $row['path'] && file_exists( $row['path'] ) ) );
    }

    private static function wp_config_path(): string {
        if ( file_exists( ABSPATH . 'wp-config.php' ) ) return ABSPATH . 'wp-config.php';
        $parent = dirname( untrailingslashit( ABSPATH ) ) . '/wp-config.php';
        return file_exists( $parent ) ? $parent : '';
    }

    public static function scan(): array {
        $rows = array(); $unsafe = 0;
        foreach ( self::targets() as $target ) {
            $perms = @fileperms( $target['path'] );
            if ( false === $perms ) continue;
            $mode = $perms & 0777;
            $world_writable = (bool) ( $mode & 0002 );
            $group_writable = (bool) ( $mode & 0020 );
            $executable_file = 'file' === $target['kind'] && (bool) ( $mode & 0111 );
            $too_open_config = 'wp-config.php' === $target['name'] && (bool) ( $mode & 0007 );
            $is_unsafe = $world_writable || $executable_file || $too_open_config;
            if ( $is_unsafe ) $unsafe++;
            $rows[] = array(
                'name'=>$target['name'], 'path'=>$target['path'], 'kind'=>$target['kind'],
                'current'=>sprintf('%04o',$mode), 'recommended'=>sprintf('%04o',$target['recommended']),
                'unsafe'=>$is_unsafe, 'group_writable'=>$group_writable, 'world_writable'=>$world_writable,
                'action'=>$is_unsafe ? 'repair' : 'none',
            );
        }
        $previous = get_option( 'ysec_permission_baseline', array() );
        $baseline = array(); foreach ( $rows as $row ) $baseline[ $row['path'] ] = $row['current'];
        $drift = array();
        if ( is_array( $previous ) && $previous ) foreach ( $baseline as $path=>$mode ) if ( isset( $previous[$path] ) && $previous[$path] !== $mode ) $drift[] = array( 'path'=>$path, 'before'=>$previous[$path], 'after'=>$mode );
        update_option( 'ysec_permission_baseline', $baseline, false );
        if ( $unsafe || $drift ) YSEC_Events::log( 'filesystem_permission_drift', array( 'severity'=>$unsafe?'high':'medium', 'confidence'=>'high', 'state'=>'suspicious', 'family'=>'filesystem', 'details'=>array( 'unsafe'=>$unsafe, 'drift'=>array_slice($drift,0,20) ) ) );
        return array( 'rows'=>$rows, 'unsafe'=>$unsafe, 'checked'=>count($rows), 'drift'=>$drift, 'scanned_at'=>current_time('mysql',true) );
    }

    public static function repair_safe(): array {
        $before = self::scan();
        $changed = 0; $failed = array();
        global $wp_filesystem;
        require_once ABSPATH . 'wp-admin/includes/file.php';
        if ( ! WP_Filesystem() || ! is_object( $wp_filesystem ) ) return array( 'ok'=>false, 'changed'=>0, 'message'=>__( 'WordPress filesystem access is not available for safe permission repair.', 'yablonsky-security' ) );
        foreach ( self::targets() as $target ) {
            $perms = @fileperms( $target['path'] );
            if ( false === $perms ) continue;
            $mode = $perms & 0777;
            $unsafe = (bool) ( $mode & 0002 ) || ( 'file' === $target['kind'] && (bool) ( $mode & 0111 ) ) || ( 'wp-config.php' === $target['name'] && (bool) ( $mode & 0007 ) );
            if ( ! $unsafe ) continue;
            if ( $wp_filesystem->chmod( $target['path'], $target['recommended'], 'dir' === $target['kind'] ) ) $changed++; else $failed[] = $target['path'];
        }
        $after = self::scan();
        YSEC_Events::log( 'filesystem_permissions_repaired', array( 'severity'=>'info', 'confidence'=>'high', 'state'=>'observed', 'family'=>'filesystem', 'details'=>array( 'changed'=>$changed, 'failed'=>count($failed) ) ) );
        return array( 'ok'=>empty($failed), 'changed'=>$changed, 'failed'=>$failed, 'before'=>$before, 'after'=>$after );
    }

    public static function scheduled(): void { self::scan(); }
}
