<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Legacy guarded-code-repair compatibility boundary.
 *
 * WordPress.org distribution does not import, stage or execute arbitrary
 * externally generated PHP/JS/replacement files, including AI drafts.
 * Scanning, forensic export, encrypted quarantine and original-file restore
 * remain independent features of YSec.
 */
final class YSEC_Repair_Import {
    private const STAGE_OPTION = 'ysec_repair_stage_v1';
    private const LAST_APPLY_OPTION = 'ysec_repair_last_apply_v1';

    public static function current_stage(): array {
        if ( get_option( self::STAGE_OPTION, false ) ) {
            self::clear_stage();
        }
        return array();
    }

    public static function last_apply(): array {
        $last = get_option( self::LAST_APPLY_OPTION, array() );
        return is_array( $last ) ? $last : array();
    }

    public static function clear_stage(): void {
        // A pre-upgrade stage must never become applicable after updating.
        $stage = get_option( self::STAGE_OPTION, array() );
        delete_option( self::STAGE_OPTION );
        if ( ! is_array( $stage ) || ! isset( $stage['id'] ) ) {
            return;
        }
        $id = (string) $stage['id'];
        if ( ! preg_match( '/^[0-9a-f-]{36}$/i', $id ) ) {
            return;
        }
        $dir = trailingslashit( WP_CONTENT_DIR ) . 'ysec-repair-staging/' . $id;
        // Remove staged ciphertext only, never resolve or touch live site files.
        if ( is_dir( $dir ) ) {
            if ( ! function_exists( 'WP_Filesystem' ) ) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
            }
            global $wp_filesystem;
            if ( WP_Filesystem() && is_object( $wp_filesystem ) ) {
                $wp_filesystem->delete( $dir, true );
            }
        }
    }

    private static function disabled(): array {
        return array(
            'ok'=>false,
            'message'=>__( 'Executable code imports are disabled. Use quarantine, evidence export or official updates.', 'yablonsky-security' ),
        );
    }

    public static function stage_upload( array $upload ): array {
        return self::disabled();
    }

    public static function stage_ai_candidates( array $candidates, array $meta = array() ): array {
        return self::disabled();
    }

    public static function apply_stage( string $stage_id ): array {
        return self::disabled();
    }
}
