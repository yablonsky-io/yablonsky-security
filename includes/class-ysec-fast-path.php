<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Fast_Path {
    private const TRANSIENT = 'ysec_fast_path_verify_result_v1';

    public static function verify(): array {
        $url = home_url( '/.__ysec_fastpath_probe__' );
        $response = wp_safe_remote_get( $url, array( 'timeout'=>8, 'redirection'=>0, 'sslverify'=>true, 'headers'=>array( 'User-Agent'=>'Yablonsky-Security-FastPath-Verify/' . YSEC_VERSION ) ) );
        if ( is_wp_error( $response ) ) return array( 'ok'=>false, 'checked_at'=>current_time('mysql',true), 'message'=>$response->get_error_message(), 'code'=>0 );
        $code = (int) wp_remote_retrieve_response_code( $response );
        $header = strtolower( trim( (string) wp_remote_retrieve_header( $response, 'x-yablonsky-security-fast-path' ) ) );
        $ok = 403 === $code && '1' === $header;
        $result = array(
            'ok'=>$ok,'checked_at'=>current_time('mysql',true),'code'=>$code,
            'message'=>$ok ? __( 'Server fast-path verification header was observed before WordPress handling.', 'yablonsky-security' ) : __( 'Run server fast-path deployment verification after the reviewed rules are installed and reloaded.', 'yablonsky-security' ),
        );
        set_transient( self::TRANSIENT, $result, DAY_IN_SECONDS );
        return $result;
    }

    public static function last(): array {
        $value = get_transient( self::TRANSIENT );
        return is_array( $value ) ? $value : array();
    }
    public static function bundle(): string {
        $rules = YSEC_Firewall_Profiles::generate_fast_path_rules();
        $env = YSEC_Environment::detect();
        return "Yablonsky Security optional server fast path\n" .
            'Generated: ' . gmdate('c') . "\n" .
            'Plugin: ' . YSEC_VERSION . "\n" .
            'Detected server: ' . (string)($env['server']??'Generic') . "\n\n" .
            "IMPORTANT\n- Review before deployment.\n- YSec never edits .htaccess or web-server configuration automatically.\n- Deploy only the block matching your server, reload/test the server configuration, then use Verify deployment in YSec.\n\n" .
            "===== NGINX =====\n" . $rules['nginx'] . "\n===== APACHE / LITESPEED =====\n" . $rules['apache'] . "\n";
    }
}
