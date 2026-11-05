<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Login  {
    public static function boot(): void  {
        add_filter('authenticate',array(__CLASS__,'policy_login'),4,3);
        add_filter('authenticate',array(__CLASS__,'rate_limit'),5,3);
        add_action('wp_login_failed',array(__CLASS__,'failed'),10,2);
        add_action('wp_login',array(__CLASS__,'success'),10,2);
        add_action('login_form',array(__CLASS__,'honeypot_field'));
        add_action('login_form',array(__CLASS__,'otp_field'));
        add_action('register_form',array(__CLASS__,'honeypot_field'));
        add_action('woocommerce_login_form',array(__CLASS__,'honeypot_field'));
        add_action('woocommerce_register_form',array(__CLASS__,'honeypot_field'));
        add_filter('registration_errors',array(__CLASS__,'registration_errors'),10,3);
        add_filter('woocommerce_registration_errors',array(__CLASS__,'woocommerce_registration_errors'),10,3);
        add_action('user_register',array(__CLASS__,'mark_pending_registration'),20,1);
        add_filter('woocommerce_registration_auth_new_customer',array(__CLASS__,'woocommerce_registration_auth_new_customer'));
        add_filter('authenticate',array(__CLASS__,'pending_approval'),33,3);
        add_filter('authenticate',array(__CLASS__,'account_lock'),34,3);
        add_filter('authenticate',array(__CLASS__,'require_otp'),35,3);
        add_action('show_user_profile',array(__CLASS__,'profile'));
        add_action('edit_user_profile',array(__CLASS__,'profile'));
        add_action('personal_options_update',array(__CLASS__,'save_profile'));
        add_action('edit_user_profile_update',array(__CLASS__,'save_profile'));
        add_filter('login_errors',array(__CLASS__,'generic_login_error'));
        add_filter('rest_endpoints',array(__CLASS__,'limit_user_rest'));
        add_filter('wp_sitemaps_add_provider',array(__CLASS__,'limit_user_sitemap'),10,2);
        add_action('template_redirect',array(__CLASS__,'limit_numeric_author_enumeration'),1);
    }
    public static function honeypot_field(): void {
        if ( ! YSEC_Firewall_Policy::honeypot_enabled() ) return;
        echo '<p class="ysec-hp-field" aria-hidden="true" style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden"><label>' . esc_html__( 'Company website', 'yablonsky-security' ) . '<input type="text" name="ysec_company_url" value="" tabindex="-1" autocomplete="off"></label></p>';
    }

    public static function policy_login( $user, $username, $password ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Login forms do not use an action nonce; the honeypot is an authentication signal only.
        $trap = isset( $_POST['ysec_company_url'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_company_url'] ) ) : '';
        if ( YSEC_Firewall_Policy::honeypot_enabled() && '' !== $trap ) {
            YSEC_Events::log( 'login_honeypot_triggered', array( 'severity'=>'high', 'family'=>'credential_attack', 'state'=>'blocked' ) );
            return new WP_Error( 'ysec_honeypot', __( 'Login failed. Check your credentials and security verification.', 'yablonsky-security' ) );
        }
        if ( $username && ! YSEC_Firewall_Policy::login_allowed( YSEC_Utils::client_ip() ) ) {
            YSEC_Events::log( 'login_source_not_allowed', array( 'severity'=>'high', 'family'=>'authentication', 'state'=>'blocked' ) );
            return new WP_Error( 'ysec_login_source', __( 'Login from this network is not allowed by the site security policy.', 'yablonsky-security' ) );
        }
        return $user;
    }

    public static function registration_errors( WP_Error $errors, string $sanitized_user_login, string $user_email ): WP_Error {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core public registration validation has no plugin action nonce.
        $trap = isset( $_POST['ysec_company_url'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_company_url'] ) ) : '';
        if ( YSEC_Firewall_Policy::honeypot_enabled() && '' !== $trap ) {
            $errors->add( 'ysec_honeypot', __( 'Registration could not be completed.', 'yablonsky-security' ) );
            YSEC_Events::log( 'registration_honeypot_triggered', array( 'severity'=>'high', 'family'=>'credential_attack', 'state'=>'blocked' ) );
        }
        return $errors;
    }

    public static function woocommerce_registration_errors( WP_Error $errors, string $username, string $email ): WP_Error {
        return self::registration_errors( $errors, $username, $email );
    }

    public static function mark_pending_registration( int $user_id ): void {
        if ( ! YSEC_Firewall_Policy::registration_approval_enabled() ) return;
        if ( defined( 'WP_CLI' ) && WP_CLI ) return;
        if ( is_admin() && current_user_can( 'create_users' ) ) return;
        update_user_meta( $user_id, 'ysec_registration_pending', 1 );
        WP_Session_Tokens::get_instance( $user_id )->destroy_all();
        YSEC_Events::log( 'registration_pending_approval', array( 'severity'=>'info', 'family'=>'authentication', 'state'=>'contained', 'details'=>array( 'user_id'=>$user_id ) ) );
    }

    public static function woocommerce_registration_auth_new_customer( bool $authenticate ): bool {
        return YSEC_Firewall_Policy::registration_approval_enabled() ? false : $authenticate;
    }

    public static function pending_approval( $user, $username, $password ) {
        if ( ! ( $user instanceof WP_User ) ) return $user;
        if ( ! get_user_meta( $user->ID, 'ysec_registration_pending', true ) ) return $user;
        YSEC_Events::log( 'registration_pending_login_blocked', array( 'severity'=>'medium', 'family'=>'authentication', 'state'=>'blocked', 'details'=>array( 'user_id'=>$user->ID ) ) );
        return new WP_Error( 'ysec_pending_approval', __( 'This account is awaiting administrator approval.', 'yablonsky-security' ) );
    }

    private static function key(string $username): string  {
        return 'ysec_lf_'.hash('sha256',strtolower($username).'|'.YSEC_Utils::client_ip());
    }
    private static function ip_key(): string  {
        return 'ysec_lf_ip_'.hash('sha256',YSEC_Utils::client_ip());
    }
    public static function rate_limit($user,$username,$password) {
        if(!$username)return $user;
        $d=get_transient(self::key($username));
        $ipd=get_transient(self::ip_key());
        $limit=max(3,absint(YSEC_Utils::option('login_limit',8)));
        $ip_limit=max($limit*3,20);
        if((is_array($d)&&($d['count']??0)>=$limit)||(is_array($ipd)&&($ipd['count']??0)>=$ip_limit)) {
            YSEC_Events::log('login_rate_limited',array('severity'=>'high','family'=>'credential_attack','state'=>'blocked'));
            return new WP_Error('ysec_rate_limit',__('Too many login attempts. Please try again later.','yablonsky-security'));
        }
        return $user;
    }
    public static function failed(string $username,$error): void  {
        $k=self::key($username);
        $d=get_transient($k);
        $count=is_array($d)?(int)($d['count']??0):0;
        $count++;
        $ttl=MINUTE_IN_SECONDS*max(1,absint(YSEC_Utils::option('login_window',15)));
        set_transient($k,array('count'=>$count),$ttl);
        $ik=self::ip_key();
        $ipd=get_transient($ik);
        $ip_count=is_array($ipd)?(int)($ipd['count']??0):0;
        set_transient($ik,array('count'=>$ip_count+1),$ttl);
        YSEC_Events::log('login_failed',array('severity'=>$count>=5?'high':'medium','family'=>'credential_attack','details'=>array('username_hash'=>hash('sha256',strtolower($username)))));
    }
    public static function success(string $user_login,WP_User $user): void  {
        delete_transient(self::key($user_login));
        $ip = YSEC_Utils::client_ip();
        update_user_meta( $user->ID, 'ysec_last_login_at', time() );
        update_user_meta( $user->ID, 'ysec_last_login_source', $ip ? YSEC_Utils::encrypt( $ip ) : '' );
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        update_user_meta( $user->ID, 'ysec_last_login_ua', YSEC_Utils::log_string( $user_agent, 180 ) );
        YSEC_Events::log('login_success',array('severity'=>'info','family'=>'authentication','details'=>array('user_id'=>$user->ID)));
    }

    public static function auth_summary( int $hours = 24 ): array {
        global $wpdb;
        $hours = max( 1, min( 168, $hours ) );
        $cut = gmdate( 'Y-m-d H:i:s', time() - $hours * HOUR_IN_SECONDS );
        $table = YSEC_DB::table( 'events' );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded security dashboard summary from the plugin-owned evidence table.
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT type,SUM(hit_count) hits FROM %i WHERE observed_at >= %s AND type IN ('login_success','login_failed','login_rate_limited','2fa_failed','captcha_failed','account_login_blocked','login_source_not_allowed') GROUP BY type", $table, $cut ), ARRAY_A ) ?: array();
        $out = array( 'success'=>0, 'failed'=>0, 'rate_limited'=>0, 'second_factor_failed'=>0, 'blocked'=>0 );
        foreach ( $rows as $row ) {
            $hits = (int) ( $row['hits'] ?? 0 );
            switch ( (string) ( $row['type'] ?? '' ) ) {
                case 'login_success': $out['success'] += $hits; break;
                case 'login_failed': case 'captcha_failed': $out['failed'] += $hits; break;
                case 'login_rate_limited': $out['rate_limited'] += $hits; break;
                case '2fa_failed': $out['second_factor_failed'] += $hits; break;
                default: $out['blocked'] += $hits;
            }
        }
        return $out;
    }
    public static function otp_field(): void  {
        if ( ! self::has_enabled_users() ) return;
        echo '<p><label for="ysec_otp">'.esc_html__('Authenticator code','yablonsky-security').'<br><input type="text" inputmode="numeric" autocomplete="one-time-code" name="ysec_otp" id="ysec_otp" class="input" value="" size="20"><span class="description">'.esc_html__('Required only for accounts that enabled Yablonsky Security two-factor authentication.','yablonsky-security').'</span></label></p>';
    }
    public static function has_enabled_users(): bool {
        $cached=get_transient('ysec_has_2fa_users');
        if(false!==$cached)return '1'===$cached;
        // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key,WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- Bounded existence check (one ID maximum), cached for ten minutes; user meta is the authoritative per-account TOTP state.
        $q=new WP_User_Query(array('number'=>1,'fields'=>'ids','meta_key'=>'ysec_totp_secret','meta_value'=>'','meta_compare'=>'!='));
        $has=!empty($q->get_results());
        set_transient('ysec_has_2fa_users',$has?'1':'0',10*MINUTE_IN_SECONDS);
        return $has;
    }
    public static function enabled_count(): int {
        $cached=get_transient('ysec_2fa_enabled_count');
        if(false!==$cached)return absint($cached);
        // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key,WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- Exact protected-account count for the Accounts screen; cached for ten minutes and invalidated whenever Yablonsky TOTP state changes.
        $q=new WP_User_Query(array('fields'=>'ID','number'=>1,'count_total'=>true,'meta_key'=>'ysec_totp_secret','meta_value'=>'','meta_compare'=>'!='));
        $q->get_results();
        $count=(int)$q->get_total();
        set_transient('ysec_2fa_enabled_count',(string)$count,10*MINUTE_IN_SECONDS);
        return $count;
    }
    public static function account_lock($user,$username,$password) {
        if ( ! ( $user instanceof WP_User ) ) return $user;
        $until = absint( get_user_meta( $user->ID, 'ysec_account_locked_until', true ) );
        if ( ! $until ) return $user;
        if ( $until <= time() ) {
            delete_user_meta( $user->ID, 'ysec_account_locked_until' );
            return $user;
        }
        YSEC_Events::log( 'account_login_blocked', array( 'severity'=>'high', 'family'=>'authentication', 'state'=>'blocked', 'details'=>array( 'user_id'=>$user->ID, 'locked_until'=>$until ) ) );
        return new WP_Error( 'ysec_account_locked', __( 'This account is temporarily unavailable. Please contact the site administrator.', 'yablonsky-security' ) );
    }
    public static function require_otp($user,$username,$password) {
        if(!($user instanceof WP_User))return $user;
        if(defined('REST_REQUEST')&&REST_REQUEST)return $user;
        $enc=(string)get_user_meta($user->ID,'ysec_totp_secret',true);
        if(!$enc)return $user;
        $secret=YSEC_Utils::decrypt($enc);
        if(!$secret)return new WP_Error('ysec_2fa_error',__('Two-factor authentication configuration is invalid.','yablonsky-security'));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- This field is processed inside the core authentication flow; wp-login credentials do not use an action nonce.
        $otp=isset($_POST['ysec_otp']) ? sanitize_text_field(wp_unslash($_POST['ysec_otp'])) : '';
        if(self::verify_totp($secret,$otp))return $user;
        if(self::use_recovery_code($user->ID,$otp))return $user;
        YSEC_Events::log('2fa_failed',array('severity'=>'high','family'=>'authentication','details'=>array('user_id'=>$user->ID)));
        return new WP_Error('ysec_2fa_required',__('A valid authenticator or recovery code is required.','yablonsky-security'));
    }
    public static function profile(WP_User $user): void  {
        if(!current_user_can('edit_user',$user->ID))return;
        $active=(bool)get_user_meta($user->ID,'ysec_totp_secret',true);
        $pending=(string)get_user_meta($user->ID,'ysec_totp_pending_secret',true);
        $pending_plain=$pending?YSEC_Utils::decrypt($pending):'';
        $setup_enc=(string)get_transient('ysec_2fa_setup_'.$user->ID);
        $setup_plain=$setup_enc?YSEC_Utils::decrypt($setup_enc):'';
        $setup=$setup_plain?preg_split('/\R/',$setup_plain):array();
        wp_nonce_field('ysec_2fa_profile','ysec_2fa_nonce');
        echo '<h2 id="ysec-two-factor-authentication">'.esc_html__('Yablonsky Security — Two-factor authentication','yablonsky-security').'</h2><table class="form-table"><tr><th>'.esc_html__('Status','yablonsky-security').'</th><td><strong>'.($active?esc_html__('Enabled','yablonsky-security'):($pending_plain?esc_html__('Setup pending','yablonsky-security'):esc_html__('Disabled','yablonsky-security'))).'</strong></td></tr>';
        if($pending_plain) {
            $label=rawurlencode(get_bloginfo('name').':'.$user->user_login);
            $issuer=rawurlencode('Yablonsky Security');
            $uri='otpauth://totp/'.$label.'?secret='.rawurlencode($pending_plain).'&issuer='.$issuer.'&algorithm=SHA1&digits=6&period=30';
            echo '<tr><th>'.esc_html__('Authenticator setup','yablonsky-security').'</th><td><p>'.esc_html__('Add this secret to your authenticator app, then enter a current six-digit code below to activate 2FA.','yablonsky-security').'</p><p><code>'.esc_html($pending_plain).'</code></p><p><code>'.esc_html($uri).'</code></p>';
            if(is_array($setup)&&!empty($setup)) {
                echo '<p><strong>'.esc_html__('Recovery codes — store these safely now.','yablonsky-security').'</strong></p><pre>'.esc_html(implode("\n",$setup)).'</pre>';
            }
            echo '<label>'.esc_html__('Confirmation code','yablonsky-security').' <input type="text" inputmode="numeric" autocomplete="one-time-code" name="ysec_2fa_confirm" value=""></label></td></tr>';
        }
        echo '<tr><th>'.esc_html__('Action','yablonsky-security').'</th><td>';
        if(!$active&&!$pending_plain)echo '<label><input type="checkbox" name="ysec_2fa_begin" value="1"> '.esc_html__('Begin TOTP 2FA setup','yablonsky-security').'</label><br>';
        if($active)echo '<label><input type="checkbox" name="ysec_2fa_regenerate" value="1"> '.esc_html__('Regenerate secret and recovery codes','yablonsky-security').'</label><br>';
        if($active||$pending_plain)echo '<label><input type="checkbox" name="ysec_2fa_disable" value="1"> '.esc_html__('Disable 2FA','yablonsky-security').'</label>';
        echo '</td></tr></table>';
    }
    public static function save_profile(int $user_id): void  {
        if(!current_user_can('edit_user',$user_id)||!isset($_POST['ysec_2fa_nonce'])||!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['ysec_2fa_nonce'])),'ysec_2fa_profile'))return;
        if(!empty($_POST['ysec_2fa_disable'])) {
            delete_user_meta($user_id,'ysec_totp_secret');
            delete_user_meta($user_id,'ysec_totp_pending_secret');
            delete_user_meta($user_id,'ysec_recovery_codes');
            delete_user_meta($user_id,'ysec_recovery_pending');
            delete_transient('ysec_2fa_setup_'.$user_id);
            delete_transient('ysec_has_2fa_users');
            delete_transient('ysec_2fa_enabled_count');
            YSEC_Events::log('2fa_disabled',array('severity'=>'medium','family'=>'authentication','details'=>array('user_id'=>$user_id)));
            return;
        }
        if(!empty($_POST['ysec_2fa_begin'])||!empty($_POST['ysec_2fa_regenerate']))self::begin_setup($user_id);
        $confirm=sanitize_text_field(wp_unslash($_POST['ysec_2fa_confirm']??''));
        if($confirm) {
            $enc=(string)get_user_meta($user_id,'ysec_totp_pending_secret',true);
            $secret=YSEC_Utils::decrypt($enc);
            if($secret&&self::verify_totp($secret,$confirm)) {
                update_user_meta($user_id,'ysec_totp_secret',$enc);
                $codes=get_user_meta($user_id,'ysec_recovery_pending',true);
                if(is_array($codes))update_user_meta($user_id,'ysec_recovery_codes',$codes);
                delete_user_meta($user_id,'ysec_totp_pending_secret');
                delete_user_meta($user_id,'ysec_recovery_pending');
                delete_transient('ysec_2fa_setup_'.$user_id);
                delete_transient('ysec_has_2fa_users');
                delete_transient('ysec_2fa_enabled_count');
                YSEC_Events::log('2fa_enabled',array('severity'=>'info','family'=>'authentication','details'=>array('user_id'=>$user_id)));
            }
            else {
                add_settings_error('ysec','2fa_confirm',__('The 2FA confirmation code was not valid. Setup remains pending.','yablonsky-security'),'error');
            }
        }
    }

    public static function generic_login_error( string $message ): string {
        if ( ! YSEC_Utils::option( 'reduce_user_enumeration', 1 ) ) return $message;
        return __( 'Login failed. Check your credentials and any required security verification.', 'yablonsky-security' );
    }
    public static function limit_user_rest( array $endpoints ): array {
        if ( ! YSEC_Utils::option( 'reduce_user_enumeration', 1 ) || is_user_logged_in() ) return $endpoints;
        foreach ( array_keys( $endpoints ) as $route ) {
            if ( '/wp/v2/users' === $route || str_starts_with( $route, '/wp/v2/users/' ) ) unset( $endpoints[$route] );
        }
        return $endpoints;
    }
    public static function limit_user_sitemap( $provider, string $name ) {
        if ( YSEC_Utils::option( 'reduce_user_enumeration', 1 ) && 'users' === $name ) return false;
        return $provider;
    }
    public static function limit_numeric_author_enumeration(): void {
        if ( ! YSEC_Utils::option( 'reduce_user_enumeration', 1 ) || is_user_logged_in() || is_admin() ) return;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only public author enumeration probe.
        $author = isset( $_GET['author'] ) ? absint( wp_unslash( $_GET['author'] ) ) : 0;
        if ( $author < 1 ) return;
        global $wp_query;
        if ( $wp_query instanceof WP_Query ) {
            $wp_query->set_404();
            status_header( 404 );
            nocache_headers();
        }
    }

    private static function begin_setup(int $user_id): void  {
        $secret=self::generate_secret();
        $hashes=[];
        $plain=[];
        for($i=0;$i<8;$i++) {
            $c=strtoupper(wp_generate_password(12,false,false));
            $plain[]=$c;
            $hashes[]=wp_hash_password($c);
        }
        update_user_meta($user_id,'ysec_totp_pending_secret',YSEC_Utils::encrypt($secret));
        update_user_meta($user_id,'ysec_recovery_pending',$hashes);
        set_transient('ysec_2fa_setup_'.$user_id,YSEC_Utils::encrypt(implode("\n",$plain)),20*MINUTE_IN_SECONDS);
    }
    public static function generate_secret(): string  {
        $alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $out='';
        $bytes=random_bytes(20);
        for($i=0;$i<20;$i++)$out.=$alphabet[ord($bytes[$i])%32];
        return $out;
    }
    private static function b32decode(string $secret): string  {
        $alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret=strtoupper(preg_replace('/[^A-Z2-7]/','',$secret));
        $bits='';
        foreach(str_split($secret) as $c) {
            $v=strpos($alphabet,$c);
            $bits.=str_pad(decbin((int)$v),5,'0',STR_PAD_LEFT);
        }
        $out='';
        foreach(str_split($bits,8) as $b) {
            if(strlen($b)===8)$out.=chr(bindec($b));
        }
        return $out;
    }
    public static function totp(string $secret,int $time=null): string  {
        $time=$time??time();
        $counter=intdiv($time,30);
        $bin=pack('N*',0,$counter);
        $hash=hash_hmac('sha1',$bin,self::b32decode($secret),true);
        $o=ord(substr($hash,-1))&15;
        $v=(unpack('N',substr($hash,$o,4))[1]&0x7fffffff)%1000000;
        return str_pad((string)$v,6,'0',STR_PAD_LEFT);
    }
    public static function verify_totp(string $secret,string $code): bool  {
        if(!preg_match('/^\d{6}$/',$code))return false;
        foreach(array(-30,0,30) as $d) {
            if(hash_equals(self::totp($secret,time()+$d),$code))return true;
        }
        return false;
    }
    private static function use_recovery_code(int $user_id,string $code): bool  {
        if(strlen($code)<8)return false;
        $codes=get_user_meta($user_id,'ysec_recovery_codes',true);
        if(!is_array($codes))return false;
        foreach($codes as $i=>$hash) {
            if(wp_check_password(strtoupper($code),$hash)) {
                unset($codes[$i]);
                update_user_meta($user_id,'ysec_recovery_codes',array_values($codes));
                return true;
            }
        }
        return false;
    }
}
