<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Privacy  {
    public static function boot(): void  {
        add_action('admin_init',array(__CLASS__,'policy'));
        add_action('wp_initialize_site',array(__CLASS__,'new_site'),20,1);
    }
    public static function new_site(WP_Site $site): void  {
        if(!is_multisite())return;
        switch_to_blog((int)$site->blog_id);
        YSEC_DB::install_current_site();
        restore_current_blog();
    }
    public static function policy(): void  {
        if(!function_exists('wp_add_privacy_policy_content'))return;
        $text='<p>'.esc_html__('Yablonsky Security records bounded security evidence needed to protect the site. Suspicious request evidence can include a salted source identifier, an encrypted source IP, user agent, a country signal supplied by a validated trusted proxy, and a redacted request query. Raw request evidence expires automatically according to severity, while compact non-identifying daily rollups can be kept longer for security trends. Firewall blocks are time-bounded and reversible. Optional Yablonsky AI analysis is disabled by default and sends a structured evidence bundle only when an administrator enables the integration and explicitly requests analysis.','yablonsky-security').'</p>';
        wp_add_privacy_policy_content('Yablonsky Security',wp_kses_post($text));
    }
}
