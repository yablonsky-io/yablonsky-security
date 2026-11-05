<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Environment  {
    public static function detect(): array  {
        $software=sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE']??''));
        $s=strtolower($software);
        $server='Generic';
        if(str_contains($s,'nginx'))$server='Nginx';
        elseif(str_contains($s,'litespeed'))$server='LiteSpeed';
        elseif(str_contains($s,'apache'))$server='Apache';
        elseif(str_contains($s,'iis'))$server='IIS';
        elseif(str_contains($s,'caddy'))$server='Caddy';
        return array('server'=>$server,'server_software'=>$software,'php'=>PHP_VERSION,'sapi'=>PHP_SAPI,'multisite'=>is_multisite(),'https'=>is_ssl(),'sodium'=>function_exists('sodium_crypto_secretbox'),'openssl'=>function_exists('openssl_encrypt'),'pretty_permalinks'=>(bool)get_option('permalink_structure'));
    }
}
