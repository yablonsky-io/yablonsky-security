<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Audit {
    private const CRITICAL_OPTIONS = array(
        'siteurl','home','admin_email','users_can_register','default_role','permalink_structure','blog_public',
        'template','stylesheet','active_plugins','new_admin_email','registration','default_ping_status','default_comment_status',
    );

    public static function boot(): void {
        add_action( 'activated_plugin', static fn( $p ) => self::log( 'plugin_activated', array( 'plugin'=>$p ) ) );
        add_action( 'deactivated_plugin', static fn( $p ) => self::log( 'plugin_deactivated', array( 'plugin'=>$p ) ) );
        add_action( 'switch_theme', static fn( $n, $t ) => self::log( 'theme_switched', array( 'theme'=>$n ) ), 10, 2 );
        add_action( 'user_register', static fn( $id ) => self::log( 'user_created', array( 'user_id'=>(int)$id ) ) );
        add_action( 'delete_user', static fn( $id ) => self::log( 'user_deleted', array( 'user_id'=>(int)$id ) ) );
        add_action( 'set_user_role', static fn( $id, $role, $old ) => self::log( 'user_role_changed', array( 'user_id'=>(int)$id,'role'=>$role,'old_roles'=>(array)$old ) ), 10, 3 );
        add_action( 'add_user_role', static fn( $id, $role ) => self::log( 'user_role_added', array( 'user_id'=>(int)$id,'role'=>$role ) ), 10, 2 );
        add_action( 'remove_user_role', static fn( $id, $role ) => self::log( 'user_role_removed', array( 'user_id'=>(int)$id,'role'=>$role ) ), 10, 2 );
        add_action( 'password_reset', static fn( $user ) => $user instanceof WP_User ? self::log( 'password_reset', array( 'user_id'=>$user->ID ) ) : null, 10, 1 );
        add_action( 'profile_update', array( __CLASS__, 'profile_updated' ), 10, 3 );
        add_action( 'deleted_plugin', static fn( $plugin, $deleted ) => $deleted ? self::log( 'plugin_deleted', array( 'plugin'=>$plugin ) ) : null, 10, 2 );
        add_action( 'deleted_theme', static fn( $stylesheet, $deleted ) => $deleted ? self::log( 'theme_deleted', array( 'theme'=>$stylesheet ) ) : null, 10, 2 );
        add_action( 'upgrader_process_complete', array( __CLASS__, 'software_updated' ), 10, 2 );
        add_action( 'admin_init', array( __CLASS__, 'flush_pending_software_update' ), 1 );
        add_action( 'wp_login', array( __CLASS__, 'login_success' ), 10, 2 );
        add_action( 'wp_logout', array( __CLASS__, 'logout' ), 10, 1 );
        add_action( 'wp_login_failed', array( __CLASS__, 'login_failed' ), 10, 2 );
        add_action( 'updated_option', array( __CLASS__, 'option_updated' ), 10, 3 );
        add_action( 'added_option', array( __CLASS__, 'option_added' ), 10, 2 );
        add_action( 'deleted_option', array( __CLASS__, 'option_deleted' ), 10, 1 );
        add_action( 'wp_create_application_password', array( __CLASS__, 'application_password_created' ), 10, 3 );
        add_action( 'wp_update_application_password', array( __CLASS__, 'application_password_updated' ), 10, 3 );
        add_action( 'wp_delete_application_password', array( __CLASS__, 'application_password_deleted' ), 10, 2 );
        add_action( 'wp_delete_all_application_passwords', array( __CLASS__, 'application_passwords_deleted' ), 10, 1 );
    }

    public static function profile_updated( int $user_id, WP_User $old_user_data, array $userdata ): void {
        $changed = array();
        $new = get_userdata( $user_id );
        if ( $new instanceof WP_User ) {
            if ( (string) $old_user_data->user_email !== (string) $new->user_email ) $changed[] = 'email';
            if ( (string) $old_user_data->display_name !== (string) $new->display_name ) $changed[] = 'display_name';
            if ( (string) $old_user_data->user_login !== (string) $new->user_login ) $changed[] = 'login';
        }
        if ( $changed ) self::log( 'user_profile_changed', array( 'user_id'=>$user_id, 'fields'=>$changed ) );
    }

    public static function software_updated( $upgrader, array $options ): void {
        $details = array(
            'type'=>sanitize_key( (string) ( $options['type'] ?? '' ) ),
            'action'=>sanitize_key( (string) ( $options['action'] ?? '' ) ),
        );
        if ( ! empty( $options['plugin'] ) && is_string( $options['plugin'] ) ) $details['plugin'] = sanitize_text_field( $options['plugin'] );
        if ( ! empty( $options['plugins'] ) && is_array( $options['plugins'] ) ) $details['plugins'] = array_values( array_map( 'sanitize_text_field', $options['plugins'] ) );
        if ( ! empty( $options['themes'] ) && is_array( $options['themes'] ) ) $details['themes'] = array_values( array_map( 'sanitize_text_field', $options['themes'] ) );

        /*
         * WordPress documents that upgrader_process_complete can run the OLD
         * version of a plugin while its files have already been replaced on
         * disk. Keep this callback deliberately tiny: do not enter YSec's event
         * DB/encryption stack from the upgrader critical path. Persist a bounded
         * marker and write the audit event on the next normal admin request.
         */
        try {
            update_option(
                'ysec_pending_software_update_v1',
                array( 'captured_at'=>gmdate( 'c' ), 'details'=>$details ),
                false
            );
        } catch ( Throwable $e ) {
            // Never turn an otherwise successful WordPress update into a fatal.
        }
    }

    public static function flush_pending_software_update(): void {
        $pending = get_option( 'ysec_pending_software_update_v1', array() );
        if ( ! is_array( $pending ) || empty( $pending['details'] ) || ! is_array( $pending['details'] ) ) return;
        delete_option( 'ysec_pending_software_update_v1' );
        try {
            self::log( 'software_updated', $pending['details'] );
        } catch ( Throwable $e ) {
            // Audit evidence is useful, but must never break wp-admin availability.
        }
    }

    public static function login_success( string $user_login, WP_User $user ): void {
        self::log( 'login_success', array( 'user_id'=>$user->ID ) );
    }

    public static function logout( $user_id = 0 ): void {
        self::log( 'logout', array( 'user_id'=>absint( $user_id ) ) );
    }

    public static function login_failed( string $username, $error = null ): void {
        self::log( 'login_failed', array( 'login_hash'=>hash_hmac( 'sha256', strtolower( trim( $username ) ), wp_salt( 'auth' ) ) ) );
    }

    public static function option_updated( string $option, $old_value, $value ): void {
        if ( ! in_array( $option, self::CRITICAL_OPTIONS, true ) ) return;
        $details = array( 'option'=>$option );
        if ( in_array( $option, array( 'users_can_register','blog_public','default_role','permalink_structure' ), true ) ) {
            $details['before'] = self::safe_option_value( $old_value );
            $details['after'] = self::safe_option_value( $value );
        }
        self::log( 'security_option_changed', $details );
    }

    public static function option_added( string $option, $value ): void {
        if ( in_array( $option, self::CRITICAL_OPTIONS, true ) ) self::log( 'security_option_added', array( 'option'=>$option ) );
    }

    public static function option_deleted( string $option ): void {
        if ( in_array( $option, self::CRITICAL_OPTIONS, true ) ) self::log( 'security_option_deleted', array( 'option'=>$option ) );
    }

    public static function application_password_created( $user_id, $new_item = array(), $new_password = '' ): void {
        self::log( 'application_password_created', array( 'user_id'=>absint( $user_id ), 'uuid'=>self::app_password_uuid( $new_item ) ) );
    }

    public static function application_password_updated( $user_id, $item = array(), $update = array() ): void {
        self::log( 'application_password_updated', array( 'user_id'=>absint( $user_id ), 'uuid'=>self::app_password_uuid( $item ) ) );
    }

    public static function application_password_deleted( $user_id, $item = array() ): void {
        self::log( 'application_password_deleted', array( 'user_id'=>absint( $user_id ), 'uuid'=>self::app_password_uuid( $item ) ) );
    }

    public static function application_passwords_deleted( $user_id ): void {
        self::log( 'application_passwords_deleted', array( 'user_id'=>absint( $user_id ) ) );
    }

    private static function app_password_uuid( $item ): string {
        if ( ! is_array( $item ) ) return '';
        return sanitize_text_field( (string) ( $item['uuid'] ?? '' ) );
    }

    private static function safe_option_value( $value ): string {
        if ( is_bool( $value ) || is_numeric( $value ) || is_string( $value ) ) return YSEC_Utils::log_string( (string) $value, 120 );
        return gettype( $value );
    }

    private static function log( string $event, array $details ): void {
        YSEC_Events::log( 'audit', array(
            'severity'=>'info',
            'family'=>$event,
            'details'=>array_merge( $details, array( 'actor'=>get_current_user_id() ) ),
        ) );
    }
}
