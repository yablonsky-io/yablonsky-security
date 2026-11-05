<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class YSEC_Compatibility {
    public static function boot(): void {
        add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
        add_action( 'activated_plugin', array( __CLASS__, 'clear_cache' ) );
        add_action( 'deactivated_plugin', array( __CLASS__, 'clear_cache' ) );
    }
    public static function clear_cache(): void { delete_transient( 'ysec_compatibility_report_v2' ); }
    private static function catalog(): array {
        return array(
            'all-in-one-wp-security-and-firewall/wp-security.php' => array('name'=>'All-In-One Security (AIOS)','overlap'=>array('Firewall','Brute force','2FA','File scanning','Login protection','Security headers'),'migration'=>array('settings_review','login_protection','firewall_policy','two_factor','hardening')),
            'wordfence/wordfence.php' => array('name'=>'Wordfence Security','overlap'=>array('WAF','Brute force','2FA','Malware scanning','IP blocking','Login protection'),'migration'=>array('settings_review','login_protection','firewall_policy','two_factor','blocking_policy')),
            'hide-my-wp/index.php' => array('name'=>'Hide My WP Ghost','overlap'=>array('Firewall','Brute force','2FA','Login paths','Security headers','Path hiding'),'migration'=>array('settings_review','login_paths','firewall_policy','security_headers')),
            'better-wp-security/better-wp-security.php' => array('name'=>'Solid/Kadence Security','overlap'=>array('Brute force','2FA','Hardening','Login protection','File monitoring')),
            'sucuri-scanner/sucuri.php' => array('name'=>'Sucuri Security','overlap'=>array('Audit','Integrity','Hardening','Scanner')),
            'wp-cerber/wp-cerber.php' => array('name'=>'WP Cerber','overlap'=>array('Firewall','Brute force','Login protection','Traffic inspection','IP blocking')),
            'wp-simple-firewall/icwp-wpsf.php' => array('name'=>'Shield Security','overlap'=>array('Firewall','Brute force','2FA','Bot protection','Audit')),
            'ninjafirewall/lib/firewall.php' => array('name'=>'NinjaFirewall','overlap'=>array('WAF','IP blocking','Traffic inspection')),
        );
    }
    public static function report(): array {
        $cache_key='ysec_compatibility_report_v2';
        $cached=get_transient($cache_key);
        if(is_array($cached))return $cached;
        if ( ! function_exists( 'get_plugins' ) ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $installed=get_plugins();
        $out=array();
        foreach(self::catalog() as $file=>$meta){
            if(!isset($installed[$file]))continue;
            $active=is_plugin_active($file);
            $out[]=array(
                'file'=>$file,
                'name'=>$meta['name'],
                'active'=>$active,
                'overlap'=>$meta['overlap'],
                'recommendation'=>$active ? __('Assign one owner to each overlapping enforcement responsibility, then verify the intended stack.','yablonsky-security') : __('Available for guided migration when you choose.','yablonsky-security'),
                'migration'=>isset($meta['migration'])&&is_array($meta['migration'])?$meta['migration']:array('settings_review'),
            );
        }
        set_transient($cache_key,$out,5*MINUTE_IN_SECONDS);
        return $out;
    }
    public static function has_active_overlap(): bool {
        foreach(self::report() as $item) if($item['active']) return true;
        return false;
    }
    public static function notice(): void {
        if(!current_user_can('manage_options') || !self::has_active_overlap())return;
        $url=add_query_arg(array('page'=>'yablonsky-security','tab'=>'compatibility'),admin_url('admin.php'));
        echo '<div class="notice notice-warning"><p>'.esc_html__('Yablonsky Security detected another active security plugin. Review overlapping protection layers and assign one owner to each enforcement responsibility.','yablonsky-security').' <a href="'.esc_url($url).'">'.esc_html__('Review compatibility','yablonsky-security').'</a></p></div>';
    }
    public static function migration_plan( string $file ): array {
        $catalog=self::catalog();
        if(!isset($catalog[$file]))return array();
        $meta=$catalog[$file];
        $steps = array(
            __('Record the source plugin state and overlapping controls.','yablonsky-security'),
            __('Map supported controls into Yablonsky Security without changing plugin activation state.','yablonsky-security'),
            __('Run Yablonsky Security in observe/coexistence mode and verify login, firewall and site behavior.','yablonsky-security'),
            __('Cut over one enforcement layer at a time only after human approval.','yablonsky-security'),
            __('Keep the prior plugin configuration available as the rollback path until acceptance.','yablonsky-security'),
        );
        if ( 'hide-my-wp/index.php' === $file ) {
            $steps = array(
                __('Record the current WP Ghost login/admin path ownership and overlapping controls.','yablonsky-security'),
                __('Prepare YSec Private Entry while WP Ghost remains active; YSec must report STANDBY rather than competing for the same paths.','yablonsky-security'),
                __('Run Firewall Proof and require a deterministic PASS for the selected YSec profile.','yablonsky-security'),
                __('Capture the pre-cutover snapshot, then deactivate WP Ghost without deleting it.','yablonsky-security'),
                __('Confirm YSec Private Entry becomes ACTIVE, verify the private login in an incognito session, then rerun the live firewall proof.','yablonsky-security'),
                __('Delete WP Ghost only after login/admin, WooCommerce, YPerf, REST/AJAX and cache smoke tests pass.','yablonsky-security'),
            );
        }
        return array(
            'source_plugin'=>$meta['name'],
            'principle'=>__('Guided coexistence first. Yablonsky Security never deactivates or deletes another plugin automatically.','yablonsky-security'),
            'steps'=>$steps,
            'areas'=>isset($meta['migration'])?$meta['migration']:array('settings_review'),
            'automatic_deactivation'=>false,
        );
    }

}
