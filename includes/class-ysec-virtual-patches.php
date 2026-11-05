<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Virtual_Patches {
    private const OPTION = 'ysec_virtual_patches_v2';
    private const LEGACY_OPTION = 'ysec_virtual_patches_v1';

    public static function enabled(): array {
        $items = get_option( self::OPTION, null );
        if ( null === $items ) $items = get_option( self::LEGACY_OPTION, array() );
        if ( ! is_array( $items ) ) return array();
        $changed = false;
        foreach ( $items as $id=>$patch ) {
            if ( ! is_array( $patch ) ) { unset( $items[$id] ); $changed = true; continue; }
            $expires = (string) ( $patch['expires_at'] ?? '' );
            if ( '' !== $expires ) {
                $ts = strtotime( $expires );
                if ( $ts && $ts <= time() ) {
                    unset( $items[$id] );
                    $changed = true;
                    YSEC_Events::log( 'virtual_patch_expired', array( 'severity'=>'info','family'=>'vulnerability','details'=>array( 'advisory'=>(string)$id ) ) );
                }
            }
        }
        if ( $changed ) update_option( self::OPTION, $items, false );
        return $items;
    }

    public static function enable( string $advisory_id ) {
        $advisory_id = sanitize_text_field( $advisory_id );
        foreach ( YSEC_Advisories::items() as $row ) {
            if ( $advisory_id !== (string) ( $row['id'] ?? '' ) ) continue;
            $patch = $row['virtual_patch'] ?? array();
            if ( ! is_array( $patch ) || empty( $patch['mode'] ) || empty( $patch['path'] ) ) {
                return new WP_Error( 'ysec_patch_missing', __( 'This advisory does not contain an eligible virtual patch rule.', 'yablonsky-security' ) );
            }
            $mode = sanitize_key( (string) $patch['mode'] );
            $path = sanitize_text_field( (string) $patch['path'] );
            if ( ! in_array( $mode, array( 'exact_path','path_prefix' ), true ) || ! str_starts_with( $path, '/' ) || strlen( $path ) > 256 ) {
                return new WP_Error( 'ysec_patch_invalid', __( 'This advisory contains an invalid virtual patch boundary.', 'yablonsky-security' ) );
            }
            $methods = self::sanitize_methods( $patch['methods'] ?? array() );
            $expires = self::sanitize_datetime( (string) ( $patch['expires_at'] ?? '' ) );
            if ( '' !== $expires && strtotime( $expires ) <= time() ) {
                return new WP_Error( 'ysec_patch_expired', __( 'This advisory virtual patch has already expired and cannot be enabled.', 'yablonsky-security' ) );
            }
            $items = self::enabled();
            $items[$advisory_id] = array(
                'id'=>$advisory_id,
                'mode'=>$mode,
                'path'=>$path,
                'methods'=>$methods,
                'expires_at'=>$expires,
                'advisory_sha256'=>sanitize_text_field( (string) ( $row['evidence_sha256'] ?? '' ) ),
                'source'=>sanitize_text_field( (string) ( $row['source'] ?? '' ) ),
                'enabled_at'=>gmdate( 'c' ),
                'actor'=>get_current_user_id(),
            );
            update_option( self::OPTION, $items, false );
            delete_option( self::LEGACY_OPTION );
            YSEC_Events::log( 'virtual_patch_enabled', array( 'severity'=>'medium','family'=>'vulnerability','state'=>'contained','details'=>array( 'advisory'=>$advisory_id,'path'=>$path,'methods'=>$methods,'expires_at'=>$expires ) ) );
            return true;
        }
        return new WP_Error( 'ysec_patch_unknown', __( 'Advisory not found in the validated local store.', 'yablonsky-security' ) );
    }

    public static function disable( string $advisory_id ): bool {
        $items = self::enabled();
        if ( ! isset( $items[$advisory_id] ) ) return false;
        unset( $items[$advisory_id] );
        update_option( self::OPTION, $items, false );
        YSEC_Events::log( 'virtual_patch_disabled', array( 'severity'=>'info','family'=>'vulnerability','details'=>array( 'advisory'=>$advisory_id ) ) );
        return true;
    }

    public static function match( string $uri, string $method = '' ): array {
        $path = YSEC_Utils::normalize_path( $uri );
        if ( '' === $method ) $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        foreach ( self::enabled() as $patch ) {
            $methods = self::sanitize_methods( $patch['methods'] ?? array() );
            if ( $methods && ! in_array( $method, $methods, true ) ) continue;
            $rule = (string) ( $patch['path'] ?? '' );
            $mode = (string) ( $patch['mode'] ?? '' );
            if ( 'exact_path' === $mode && hash_equals( $rule, $path ) ) return $patch;
            if ( 'path_prefix' === $mode && '' !== $rule && str_starts_with( $path, $rule ) ) return $patch;
        }
        return array();
    }

    public static function status(): array {
        $items = self::enabled();
        $with_expiry = 0;
        $scoped_methods = 0;
        foreach ( $items as $patch ) {
            if ( ! empty( $patch['expires_at'] ) ) $with_expiry++;
            if ( ! empty( $patch['methods'] ) ) $scoped_methods++;
        }
        return array( 'enabled'=>count( $items ), 'with_expiry'=>$with_expiry, 'method_scoped'=>$scoped_methods );
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

    private static function sanitize_datetime( string $value ): string {
        $value = trim( $value );
        if ( '' === $value ) return '';
        $ts = strtotime( $value );
        return false === $ts ? '' : gmdate( 'c', $ts );
    }
}
