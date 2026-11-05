<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Uploads  {
    public static function boot(): void  {
        add_filter('wp_handle_upload_prefilter',array(__CLASS__,'inspect'));
    }
    public static function inspect(array $file): array  {
        if(!empty($file['error'])||empty($file['tmp_name'])||!is_readable($file['tmp_name']))return $file;
        $name=sanitize_file_name((string)($file['name']??''));
        $ext=strtolower(pathinfo($name,PATHINFO_EXTENSION));
        $blocked=array('php','phtml','pht','phar','cgi','pl','py','sh','bash','exe','dll','so','com','bat','cmd','ps1');
        if(in_array($ext,$blocked,true)||preg_match('/\.(?:php\d*|phtml|pht|phar)\.[a-z0-9]{1,8}$/i',$name)) {
            $file['error']=__('This upload was blocked because its filename can execute server-side code.','yablonsky-security');
            YSEC_Events::log('upload_blocked',array('severity'=>'critical','family'=>'malicious_upload','state'=>'blocked','details'=>array('name_hash'=>hash('sha256',$name),'reason'=>'executable_extension')));
            return $file;
        }
        $head=@file_get_contents($file['tmp_name'],false,null,0,131072);
        if(false===$head)return $file;
        if(in_array($ext,array('jpg','jpeg','png','gif','webp','avif','ico','pdf'),true)&&preg_match('/<\?(?:php|=)|<script\b|__HALT_COMPILER\s*\(/i',$head)) {
            $file['error']=__('This upload was blocked because executable content was detected inside a non-executable file.','yablonsky-security');
            YSEC_Events::log('upload_blocked',array('severity'=>'critical','family'=>'polyglot_upload','state'=>'blocked','details'=>array('name_hash'=>hash('sha256',$name),'reason'=>'embedded_executable_marker')));
            return $file;
        }
        return $file;
    }
}
