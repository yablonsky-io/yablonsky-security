<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Database_Safety {
    public static function audit(): array {
        global $wpdb;
        $checks = array();
        $prefix = (string) $wpdb->prefix;
        $checks[] = array(
            'key'=>'table_prefix','severity'=>'info','state'=>'observed',
            'message'=> 'wp_' === $prefix
                ? __( 'The site uses the conventional wp_ table prefix. This is not a vulnerability by itself; YSec does not perform risky live prefix rewrites.', 'yablonsky-security' )
                : __( 'The site uses a non-default WordPress table prefix.', 'yablonsky-security' ),
        );
        $admin_user = get_user_by( 'login', 'admin' );
        $checks[] = array(
            'key'=>'default_admin_login','severity'=>$admin_user ? 'medium' : 'info','state'=>$admin_user ? 'attention' : 'clear',
            'message'=>$admin_user
                ? __( 'A WordPress account with the login name “admin” exists. Consider a less predictable administrator login after confirming ownership and recovery paths.', 'yablonsky-security' )
                : __( 'No WordPress account uses the conventional “admin” login name.', 'yablonsky-security' ),
        );
        $admins = get_users( array( 'role'=>'administrator', 'fields'=>'ids', 'number'=>200 ) );
        $checks[] = array(
            'key'=>'administrator_population','severity'=>count($admins)>10?'medium':'info','state'=>count($admins)>10?'attention':'observed',
            // translators: %d: administrator account count.
            'message'=>sprintf( __( '%d administrator account(s) currently have full WordPress capabilities.', 'yablonsky-security' ), count( $admins ) ),
        );
        $db_debug = ! empty( $wpdb->show_errors );
        $checks[] = array(
            'key'=>'database_error_display','severity'=>$db_debug?'medium':'info','state'=>$db_debug?'attention':'clear',
            'message'=>$db_debug
                ? __( 'WordPress database error display is enabled in this request context. Public production requests should not expose SQL diagnostics.', 'yablonsky-security' )
                : __( 'WordPress database errors are not configured for direct display in this request context.', 'yablonsky-security' ),
        );
        $attention = count( array_filter( $checks, static fn($c)=>'attention'===($c['state']??'') ) );
        return array( 'checks'=>$checks, 'attention'=>$attention, 'checked'=>count($checks) );
    }
}
