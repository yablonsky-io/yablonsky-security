<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Exposure {
    public static function audit(): array {
        $checks = array();
        $candidates = array(
            '.env'                    => 'critical',
            '.git/config'             => 'high',
            '.svn/entries'            => 'high',
            '.hg/requires'            => 'high',
            'wp-config.php.bak'       => 'critical',
            'wp-config.php.old'       => 'critical',
            'wp-config.php.save'      => 'critical',
            'wp-config.php~'          => 'critical',
            'wp-content/debug.log'    => 'medium',
            'backup.sql'              => 'critical',
            'database.sql'            => 'critical',
            'dump.sql'                => 'critical',
            'backup.sql.gz'           => 'critical',
            'phpinfo.php'             => 'high',
            'info.php'                => 'high',
        );
        foreach ( $candidates as $relative => $severity ) {
            $path = wp_normalize_path( ABSPATH . $relative );
            $exists = is_file( $path );
            $checks[] = array(
                'key'      => $relative,
                'severity' => $severity,
                'state'    => $exists ? 'exposed_local_artifact' : 'clear',
                'path'     => $relative,
                'message'  => self::artifact_message( $exists, $relative ),
            );
        }
        $checks[] = array(
            'key'      => 'wp_debug_display',
            'severity' => 'medium',
            'state'    => defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ? 'attention' : 'clear',
            'path'     => '',
            'message'  => defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY
                ? __( 'WP_DEBUG_DISPLAY is enabled. Production sites normally should not expose PHP diagnostic output to visitors.', 'yablonsky-security' )
                : __( 'Public WordPress debug display is not enabled.', 'yablonsky-security' ),
        );
        $attention = count( array_filter( $checks, static fn( $row ) => 'clear' !== ( $row['state'] ?? '' ) ) );
        return array( 'checked'=>count( $checks ), 'attention'=>$attention, 'checks'=>$checks, 'scanned_at'=>current_time( 'mysql', true ) );
    }
    private static function artifact_message( bool $exists, string $relative ): string {
        if ( $exists ) {
            /* translators: %s: relative file path. */
            return sprintf( __( 'Sensitive or diagnostic artifact exists locally: %s. Review whether it belongs in the public document root.', 'yablonsky-security' ), $relative );
        }
        /* translators: %s: relative file path. */
        return sprintf( __( 'No local %s artifact detected.', 'yablonsky-security' ), $relative );
    }

}
