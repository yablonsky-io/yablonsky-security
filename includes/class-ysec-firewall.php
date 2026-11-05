<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Firewall  {
    public static function boot(): void  {
        add_action('init',array(__CLASS__,'inspect'),-999);
        add_action('ysec_hourly_cleanup',array(__CLASS__,'expire_blocks'));
    }
    public static function inspect(): void  {
        // Server-owner recovery switch. wp-config.php loads before MU/normal plugins,
        // so this restores administrator access without requiring wp-admin itself.
        if ( defined( 'YSEC_EMERGENCY_BYPASS' ) && true === YSEC_EMERGENCY_BYPASS ) return;
        if ( ! YSEC_Utils::option( 'waf_enabled', 1 ) || wp_doing_cron() ) return;
        // Administrator workspace requests are authenticated and nonce/capability protected; avoid re-running the public WAF stack on every internal tab/AJAX navigation.
        if ( is_admin() && is_user_logged_in() && current_user_can( 'manage_options' ) ) return;
        $ip = YSEC_Utils::client_ip();

        // Durable policy remains an explicit human override. Allowlist bypasses YSec enforcement; permanent block denies before routing.
        if ( $ip && YSEC_Firewall_Policy::allowlisted( $ip ) ) {
            YSEC_Request_Contract::publish( 'ALLOW', array( 'family'=>'administrator_allowlist', 'stage'=>'wordpress_firewall' ) );
            return;
        }
        if ( $ip && YSEC_Firewall_Policy::permanently_blocked( $ip ) ) {
            YSEC_Events::log( 'request_denied', array( 'severity'=>'high', 'confidence'=>'high', 'state'=>'request_denied', 'family'=>'policy_block', 'details'=>array( 'reason'=>'permanent_block_policy' ) ) );
            self::deny( 'permanent_policy' );
        }

        // Explicit/manual temporary source blocks still deny the whole source. Smart automatic response uses scoped containment below instead.
        if ( $ip && self::is_blocked( $ip ) ) self::deny( 'active_block' );

        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Normalized by bounded request policy matchers before any comparison.
        $blocked_country = YSEC_Country_Policy::match( (string) $request_uri );
        if ( '' !== $blocked_country ) {
            YSEC_Events::log( 'request_denied', array(
                'severity'=>'high', 'confidence'=>'high', 'state'=>'request_denied', 'family'=>'country_policy',
                'details'=>array( 'reason'=>'trusted_country_block_policy', 'country'=>$blocked_country, 'scope'=>YSEC_Country_Policy::scope(), 'recovery_surfaces_preserved'=>true ),
            ) );
            self::deny( 'country_policy' );
        }

        // Scoped adaptive containment protects privileged/write surfaces while deliberately preserving read-only public discovery.
        if ( $ip ) {
            $scope = YSEC_Adaptive_Response::preflight( $ip );
            if ( ! empty( $scope['active'] ) && ! empty( $scope['deny'] ) ) {
                YSEC_Events::log( 'request_denied', array(
                    'severity'=>'high', 'confidence'=>'high', 'state'=>'request_denied', 'family'=>'adaptive_containment',
                    'details'=>array( 'reason'=>'scoped_source_containment', 'pressure'=>(int)($scope['pressure']??0), 'families'=>(array)($scope['families']??array()), 'public_discovery_preserved'=>true ),
                ) );
                self::deny( 'adaptive_containment' );
            }
        }

        // Classify production-relevant application-resource abuse before the main query/template runs.
        // This is intentionally separate from exploit/probe detection: state-action and faceted GETs can be valid-looking yet expensive.
        $l7 = YSEC_L7_Abuse::inspect_current();
        if ( ! empty( $l7['enforce'] ) ) {
            YSEC_Events::capture_waf_signals( array( array( 'family'=>'state_action_get', 'severity'=>'high', 'confidence'=>'high', 'state'=>'blocked', 'class'=>'application_abuse' ) ), true );
            YSEC_Events::log( 'request_denied', array(
                'severity'=>'high','confidence'=>'high','state'=>'request_denied','family'=>'state_action_get',
                'path'=>(string)($l7['path']??''),'method'=>(string)($l7['method']??'GET'),'request_id'=>(string)($l7['request_id']??''),
                'aggregate'=>true,'aggregate_window'=>300,'aggregate_seed'=>(string)($l7['action']??''),
                'details'=>array( 'reason'=>'l7_state_action_rate', 'action'=>(string)($l7['action']??''), 'query_keys'=>(array)($l7['query_keys']??array()), 'source_rate'=>(int)($l7['source_rate']??0), 'window_seconds'=>(int)($l7['window_seconds']??60), 'origin_stage'=>'pre_main_query' ),
            ) );
            self::deny( 'l7_state_action_rate' );
        }

        $virtual_patch = YSEC_Virtual_Patches::match( (string) $request_uri );
        if ( $virtual_patch ) {
            $signals = array( array( 'family'=>'virtual_patch', 'severity'=>'high', 'confidence'=>'high', 'state'=>'blocked', 'class'=>'attack' ) );
            YSEC_Events::capture_waf_signals( $signals, true );
            if ( $ip ) YSEC_Adaptive_Response::record_harmful( $ip, $signals, 'virtual_patch' );
            YSEC_Events::log( 'request_denied', array( 'severity'=>'high','confidence'=>'high','state'=>'request_denied','family'=>'virtual_patch','details'=>array( 'advisory'=>(string)($virtual_patch['id']??''),'path'=>(string)($virtual_patch['path']??'') ) ) );
            self::deny( 'virtual_patch' );
        }
        if ( YSEC_Firewall_Policy::path_blocked( (string) $request_uri ) ) {
            $signals = array( array( 'family'=>'custom_policy', 'severity'=>'high', 'confidence'=>'high', 'state'=>'blocked', 'class'=>'probe' ) );
            YSEC_Events::capture_waf_signals( $signals, true );
            if ( $ip ) YSEC_Adaptive_Response::record_harmful( $ip, $signals, 'custom_path_policy' );
            self::deny( 'custom_path_policy' );
        }

        $conditional_rule = YSEC_Conditional_Rules::match_current_request( (string) $request_uri, $ip );
        if ( $conditional_rule ) {
            $signals = array( array( 'family'=>'conditional_policy', 'severity'=>'high', 'confidence'=>'high', 'state'=>'blocked', 'class'=>'policy' ) );
            YSEC_Events::capture_waf_signals( $signals, true );
            YSEC_Events::log( 'request_denied', array( 'severity'=>'high','confidence'=>'high','state'=>'request_denied','family'=>'conditional_policy','details'=>array( 'rule_id'=>(string)($conditional_rule['id']??''), 'label'=>(string)($conditional_rule['label']??''), 'method'=>(string)($conditional_rule['method']??'ANY'), 'path'=>(string)($conditional_rule['path']??'') ) ) );
            self::deny( 'conditional_policy' );
        }

        $request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        $profile_exception = YSEC_Firewall_Policy::request_exception_active( $request_method, (string) $request_uri );
        if ( ! $profile_exception ) {
            $profile_signal = YSEC_Firewall_Profiles::evaluate();
            if ( $profile_signal ) {
                YSEC_Events::capture_waf_signals( array( $profile_signal ), true );
                if ( $ip ) YSEC_Adaptive_Response::record_harmful( $ip, array( $profile_signal ), 'firewall_profile' );
                // First hit: deny the harmful request, not the whole IP. Broader containment is earned by sustained behavior.
                self::deny( 'firewall_profile' );
            }
        }

        $signals = YSEC_Classifier::request_threats( ! is_user_logged_in() );
        if ( ! $signals ) {
            if ( $ip ) YSEC_Adaptive_Response::record_benign( $ip );
            YSEC_Request_Contract::publish( 'ALLOW', array( 'family'=>'request_safety', 'stage'=>'wordpress_firewall' ) );
            return;
        }

        if ( $ip ) YSEC_Adaptive_Response::record_harmful( $ip, $signals, 'classifier' );
        $rate = $ip ? YSEC_Rate_Intelligence::observe( $ip, $signals ) : array();
        if ( ! empty( $rate['enforce'] ) ) {
            YSEC_Events::capture_waf_signals( $signals, true );
            YSEC_Events::log( 'request_denied', array( 'severity'=>'high','confidence'=>'high','state'=>'request_denied','family'=>'automated_scanner','details'=>array( 'reason'=>'suspicious_rate_threshold','count'=>(int)$rate['count'] ) ) );
            self::deny( 'suspicious_rate' );
        }

        YSEC_Firewall_Profiles::observe_adaptive_recon( $ip, $signals );
        $critical = array_filter( $signals, static fn( $signal ) => 'critical' === ( $signal['severity'] ?? '' ) );
        YSEC_Events::capture_waf_signals( $signals, ! empty( $critical ) );
        if ( $critical ) {
            $critical_families = array_values( array_unique( array_column( $critical, 'family' ) ) );
            YSEC_Events::log( 'request_denied', array(
                'severity'=>'critical','confidence'=>'high','state'=>'request_denied','family'=>'waf',
                'details'=>array( 'reason'=>'critical_waf','families'=>$critical_families, 'source_blocked'=>false ),
            ) );
            do_action( 'ysec_security_alert', 'critical_waf', array( 'family'=>implode( ',', array_map( 'sanitize_key', $critical_families ) ), 'reason'=>'critical_waf', 'profile'=>YSEC_Firewall_Profiles::current() ) );
            self::deny( 'waf' );
        }
        YSEC_Request_Contract::publish( 'OBSERVE', array( 'family'=>(string) ( $signals[0]['family'] ?? 'security_signal' ), 'stage'=>'wordpress_firewall' ) );
    }
    private static function deny(string $reason): void  {
        YSEC_Request_Contract::publish( 'DENY', array( 'family'=>$reason, 'stage'=>'wordpress_firewall', 'http_status'=>403 ) );
        status_header(403);
        nocache_headers();
        header('Content-Type: text/plain; charset=utf-8');
        // A valid canary proves the selected firewall profile only when that profile
        // actually produced this deny; unrelated WAF or manual blocks do not qualify.
        $proof_token = 'firewall_profile' === $reason && class_exists( 'YSEC_Firewall_Proof' ) ? YSEC_Firewall_Proof::proof_response_token() : '';
        if ( '' !== $proof_token ) header( 'X-Yablonsky-Security-Proof: ' . $proof_token );
        YSEC_Events::flush_request_record();
        echo esc_html__('Request blocked by Yablonsky Security.','yablonsky-security');
        exit;
    }
    public static function block(string $ip,string $reason,int $minutes=0): bool  {
        if(!filter_var($ip,FILTER_VALIDATE_IP))return false;
        return self::block_hash(YSEC_Utils::source_identity($ip),$reason,$minutes,$ip);
    }
    public static function block_hash(string $source_hash,string $reason,int $minutes=0,string $source_label=''): bool {
        global $wpdb;
        if(!preg_match('/^[a-f0-9]{64}$/',$source_hash))return false;
        // Never let an administrator bulk-response action lock out the source executing it.
        if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
            $admin_ip = YSEC_Utils::client_ip();
            if ( '' !== $admin_ip && hash_equals( YSEC_Utils::source_identity( $admin_ip ), $source_hash ) ) return false;
        }
        $now=current_time('mysql',true);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Idempotent live enforcement check must use current block state.
        $existing=(int)$wpdb->get_var($wpdb->prepare('SELECT id FROM %i WHERE source_hash=%s AND active=1 AND expires_at>%s ORDER BY id DESC LIMIT 1',YSEC_DB::table('blocks'),$source_hash,$now));
        if($existing)return false;
        $minutes=$minutes?:absint(YSEC_Utils::option('block_minutes',60));
        $has_ip=''!==$source_label&&filter_var($source_label,FILTER_VALIDATE_IP);
        $label=$has_ip?YSEC_Utils::masked_ip($source_label):'source:'.substr($source_hash,0,12);
        $source_enc=$has_ip?YSEC_Utils::encrypt($source_label):'';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Dedicated security block table requires immediate write.
        return false!==$wpdb->insert(YSEC_DB::table('blocks'),array('source'=>$label,'source_hash'=>$source_hash,'source_enc'=>$source_enc,'source_version'=>'stable_ip','reason'=>substr(sanitize_text_field($reason),0,255),'created_at'=>$now,'expires_at'=>gmdate('Y-m-d H:i:s',time()+60*$minutes),'active'=>1),array('%s','%s','%s','%s','%s','%s','%s','%d'));
    }
    public static function unblock_hash(string $source_hash): int {
        global $wpdb;
        if(!preg_match('/^[a-f0-9]{64}$/',$source_hash))return 0;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Administrator-requested reversible enforcement update.
        $changed=$wpdb->query($wpdb->prepare('UPDATE %i SET active=0 WHERE source_hash=%s AND active=1',YSEC_DB::table('blocks'),$source_hash));
        return false===$changed?0:(int)$changed;
    }
    public static function unblock_all(): int {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit emergency recovery action must update live block state immediately.
        $changed = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET active=0 WHERE active=1', YSEC_DB::table( 'blocks' ) ) );
        return false === $changed ? 0 : (int) $changed;
    }
    public static function observe_recon(string $source_hash,array $classification): void {
        if ( ! YSEC_Utils::option( 'auto_block', 0 ) || 'probe' !== ( $classification['class'] ?? '' ) || 'high' !== ( $classification['confidence'] ?? '' ) ) return;
        if ( ! preg_match( '/^[a-f0-9]{64}$/', $source_hash ) ) return;
        // Historical source hashes cannot be reversed safely. Request-time adaptive response is handled from the real client IP in inspect().
        // Keep this method as a no-op compatibility hook for observer callers instead of turning one classification into an IP-wide ban.
    }
    public static function is_blocked(string $ip): bool  {
        global $wpdb;
        $stable=YSEC_Utils::source_identity($ip);
        $legacy=YSEC_Utils::legacy_fingerprint($ip);
        $now=current_time('mysql',true);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Block decisions must use current state. Legacy identity is checked during migration compatibility only.
        return (bool)$wpdb->get_var($wpdb->prepare('SELECT id FROM %i WHERE source_hash IN (%s,%s) AND active=1 AND expires_at>%s ORDER BY id DESC LIMIT 1',YSEC_DB::table('blocks'),$stable,$legacy,$now));
    }
    public static function unblock(int $id): bool  {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Dedicated security block table update; cached state would be unsafe.
        return false!==$wpdb->update(YSEC_DB::table('blocks'),array('active'=>0),array('id'=>$id),array('%d'),array('%d'));
    }
    public static function is_hash_blocked(string $source_hash): bool {
        if(!preg_match('/^[a-f0-9]{64}$/',$source_hash))return false;
        global $wpdb;$now=current_time('mysql',true);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Current enforcement state must not be stale.
        return (bool)$wpdb->get_var($wpdb->prepare('SELECT id FROM %i WHERE source_hash=%s AND active=1 AND expires_at>%s ORDER BY id DESC LIMIT 1',YSEC_DB::table('blocks'),$source_hash,$now));
    }
    public static function blocked_hashes(array $hashes): array {
        global $wpdb;$hashes=array_values(array_unique(array_filter(array_map('strval',$hashes),static fn($h)=>preg_match('/^[a-f0-9]{64}$/',$h))));
        if(!$hashes)return array();$hashes=array_slice($hashes,0,200);$ph=implode(',',array_fill(0,count($hashes),'%s'));$params=array_merge(array(YSEC_DB::table('blocks'),current_time('mysql',true)),$hashes);
        $sql="SELECT DISTINCT source_hash FROM %i WHERE active=1 AND expires_at>%s AND source_hash IN ($ph)";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Batched current block-state lookup; identifier and values prepared.
        $rows=$wpdb->get_col($wpdb->prepare($sql,$params))?:array();return array_fill_keys($rows,true);
    }
    public static function active_blocks(): array  {
        $result=self::query_blocks(array('page'=>1,'per_page'=>100));
        return $result['rows'];
    }
    public static function query_blocks(array $args=array()): array {
        global $wpdb;
        $args=wp_parse_args($args,array('page'=>1,'per_page'=>25,'search'=>'','orderby'=>'expires_at','order'=>'ASC'));
        $page=max(1,absint($args['page']));
        $per_page=max(10,min(100,absint($args['per_page'])?:25));
        $table=YSEC_DB::table('blocks');
        $now=current_time('mysql',true);
        $where=' AND active=1 AND expires_at>%s';
        $params=array($table,$now);
        $search=trim(sanitize_text_field((string)$args['search']));
        if(''!==$search){
            $like='%'.$wpdb->esc_like($search).'%';
            $where.=' AND (source LIKE %s OR reason LIKE %s)';
            $params[]=$like;
            $params[]=$like;
        }
        $order_map=array('source'=>'source','reason'=>'reason','created_at'=>'created_at','expires_at'=>'expires_at','id'=>'id');
        $orderby=$order_map[$args['orderby']]??'expires_at';
        $order='DESC'===strtoupper((string)$args['order'])?'DESC':'ASC';
        $count_sql='SELECT COUNT(*) FROM %i WHERE 1=1'.$where;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dedicated live block table; identifier and values are prepared.
        $total=(int)$wpdb->get_var($wpdb->prepare($count_sql,$params));
        $offset=($page-1)*$per_page;
        $query_args=$params; $query_args[]=$per_page; $query_args[]=$offset;
        $sql='SELECT * FROM %i WHERE 1=1'.$where.' ORDER BY '.$orderby.' '.$order.', id DESC LIMIT %d OFFSET %d';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dedicated live block table; identifier and values are prepared; ORDER BY is allowlisted.
        $rows=$wpdb->get_results($wpdb->prepare($sql,$query_args),ARRAY_A)?:array();
        return array('rows'=>$rows,'total'=>$total,'page'=>$page,'per_page'=>$per_page);
    }
    public static function display_source( array $row ): string  {
        $encrypted = (string) ( $row['source_enc'] ?? '' );
        $ip = '' !== $encrypted ? YSEC_Utils::decrypt( $encrypted ) : '';
        if ( '' !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
        return (string) ( $row['source'] ?? ( 'source:' . substr( (string) ( $row['source_hash'] ?? '' ), 0, 12 ) ) );
    }

    public static function expire_blocks(): void  {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scheduled cleanup of dedicated security table.
        $wpdb->query($wpdb->prepare('UPDATE %i SET active=0 WHERE active=1 AND expires_at<=%s',YSEC_DB::table('blocks'),current_time('mysql',true)));
    }
}
