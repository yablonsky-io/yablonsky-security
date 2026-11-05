<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_REST  {
    public static function boot():void {
        add_action('rest_api_init',function(){register_rest_route('yablonsky-security/v1','/status',array('methods'=>WP_REST_Server::READABLE,'callback'=>fn()=>rest_ensure_response(array('version'=>YSEC_VERSION,'summary'=>YSEC_Events::summary(),'environment'=>YSEC_Environment::detect())),'permission_callback'=>fn()=>current_user_can('manage_options')));});
    }
}
