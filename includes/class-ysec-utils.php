<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Utils  {
    /**
     * PHP 7.4 / WordPress 6.4 compatible list-array check.
     *
     * Kept behind the YSec namespace boundary instead of polyfilling the
     * global native-list helper symbol, so Plugin Check can validate the declared
     * WordPress compatibility floor without mistaking a runtime shim for a
     * newer-core dependency.
     */
    public static function is_list_array( array $array ): bool  {
        $index = 0;
        foreach ( $array as $key => $_value )  {
            if ( $key !== $index++ ) return false;
        }
        return true;
    }
    public static function option( string $key, $default = null )  {
        $settings = get_option( 'ysec_settings', array() );
        if ( ! is_array( $settings ) ) return $default;
        return array_key_exists( $key, $settings ) ? $settings[ $key ] : $default;
    }
    public static function settings(): array  {
        $defaults = array(
        'observe_requests' => 1,
        'extended_telemetry' => 0,
        'waf_enabled' => 1,
        'firewall_profile' => 'minimal',
        'adaptive_404_shield' => 1,
        'adaptive_recon_threshold' => 15,
        'adaptive_recon_window' => 10,
        'suspicious_rate_enforce' => 0,
        'suspicious_rate_threshold' => 120,
        'suspicious_rate_window' => 10,
        'auto_block' => 0,
        'preserve_public_discovery' => 1,
        'l7_abuse_observe' => 1,
        'l7_state_action_enforce' => 1,
        'l7_state_action_threshold' => 60,
        'l7_abuse_window_seconds' => 60,
        'country_block_enabled' => 0,
        'country_blocklist' => '',
        'country_block_scope' => 'public',
        'smart_response_window' => 10,
        'smart_containment_score' => 24,
        'smart_containment_families' => 3,
        'smart_containment_attack_hits' => 8,
        'block_minutes' => 60,
        'recon_block_threshold' => 20,
        'recon_block_window' => 15,
        'campaign_family_threshold' => 3,
        'campaign_hit_threshold' => 30,
        'login_limit' => 8,
        'login_window' => 15,
        'private_login_enabled' => 0,
        'private_login_mode' => 'off',
        'private_login_slug' => '',
        'private_admin_slug' => '',
        'captcha_provider' => 'none',
        'captcha_site_key' => '',
        'captcha_secret_key' => '',
        'captcha_wp_login' => 1,
        'captcha_wp_register' => 1,
        'captcha_wp_recovery' => 1,
        'captcha_woo_login' => 1,
        'captcha_woo_register' => 1,
        'captcha_woo_recovery' => 1,
        'reduce_user_enumeration' => 1,
        'comment_form_proof' => 1,
        'comment_honeypot' => 1,
        'comment_rate_enforce' => 0,
        'comment_rate_limit' => 10,
        'comment_rate_window' => 10,
        'trusted_proxies' => '',
        'crawler_feeds_consent' => 0,
        'security_headers' => 1,
        'technology_exposure_mode' => 'safe',
        'disable_file_editor' => 0,
        'disable_application_passwords' => 0,
        'xmlrpc_mode' => 'monitor',
        'alerts_enabled' => 0,
        'alerts_email' => '',
        'alerts_admin_changes' => 1,
        'alerts_admin_login' => 1,
        'alerts_critical_events' => 1,
        'alerts_daily_digest' => 1,
        'ai_enabled' => 0,
        'ai_api_key' => '',
        'ai_workspace_id' => '',
        'ai_model_id' => '',
        'ai_reasoning' => 'auto',
        'retention_days' => 30,
        'evidence_retention_info' => 1,
        'evidence_retention_medium' => 3,
        'evidence_retention_high' => 7,
        'evidence_retention_critical' => 30,
        'rollup_days' => 365,
        'event_max_rows' => 250000,
        );
        return wp_parse_args( get_option( 'ysec_settings', array() ), $defaults );
    }
    public static function sanitize_settings( array $input ): array  {
        $current = self::settings();
        $out = $current;
        foreach ( array( 'observe_requests','extended_telemetry','waf_enabled','adaptive_404_shield','suspicious_rate_enforce','auto_block','preserve_public_discovery','security_headers','disable_file_editor','disable_application_passwords','captcha_wp_login','captcha_wp_register','captcha_wp_recovery','captcha_woo_login','captcha_woo_register','captcha_woo_recovery','reduce_user_enumeration','comment_form_proof','comment_honeypot','comment_rate_enforce','country_block_enabled','crawler_feeds_consent','l7_abuse_observe','l7_state_action_enforce','alerts_enabled','alerts_admin_changes','alerts_admin_login','alerts_critical_events','alerts_daily_digest' ) as $k )  {
            $out[$k] = empty( $input[$k] ) ? 0 : 1;
        }
        $profile = sanitize_key( (string) ( $input['firewall_profile'] ?? $current['firewall_profile'] ?? 'minimal' ) );
        $out['firewall_profile'] = in_array( $profile, array( 'minimal','5g','6g','7g','8g' ), true ) ? $profile : 'minimal';
        $out['adaptive_recon_threshold'] = max( 5, min( 200, absint( $input['adaptive_recon_threshold'] ?? $current['adaptive_recon_threshold'] ?? 15 ) ) );
        $out['adaptive_recon_window'] = max( 1, min( 60, absint( $input['adaptive_recon_window'] ?? $current['adaptive_recon_window'] ?? 10 ) ) );
        $out['suspicious_rate_threshold'] = max( 20, min( 1000, absint( $input['suspicious_rate_threshold'] ?? $current['suspicious_rate_threshold'] ?? 120 ) ) );
        $out['suspicious_rate_window'] = max( 1, min( 60, absint( $input['suspicious_rate_window'] ?? $current['suspicious_rate_window'] ?? 10 ) ) );
        $out['l7_state_action_threshold'] = max( 20, min( 1000, absint( $input['l7_state_action_threshold'] ?? $current['l7_state_action_threshold'] ?? 60 ) ) );
        $out['l7_abuse_window_seconds'] = max( 30, min( 300, absint( $input['l7_abuse_window_seconds'] ?? $current['l7_abuse_window_seconds'] ?? 60 ) ) );
        $out['smart_response_window'] = max( 1, min( 60, absint( $input['smart_response_window'] ?? $current['smart_response_window'] ?? 10 ) ) );
        $out['smart_containment_score'] = max( 8, min( 500, absint( $input['smart_containment_score'] ?? $current['smart_containment_score'] ?? 24 ) ) );
        $out['smart_containment_families'] = max( 1, min( 12, absint( $input['smart_containment_families'] ?? $current['smart_containment_families'] ?? 3 ) ) );
        $out['smart_containment_attack_hits'] = max( 2, min( 100, absint( $input['smart_containment_attack_hits'] ?? $current['smart_containment_attack_hits'] ?? 8 ) ) );
        $out['block_minutes'] = max( 1, min( 1440, absint( $input['block_minutes'] ?? 60 ) ) );
        $out['recon_block_threshold'] = max( 5, min( 500, absint( $input['recon_block_threshold'] ?? 20 ) ) );
        $out['recon_block_window'] = max( 1, min( 1440, absint( $input['recon_block_window'] ?? 15 ) ) );
        $out['campaign_family_threshold'] = max( 2, min( 12, absint( $input['campaign_family_threshold'] ?? 3 ) ) );
        $out['campaign_hit_threshold'] = max( 10, min( 1000, absint( $input['campaign_hit_threshold'] ?? 30 ) ) );
        $out['login_limit'] = max( 2, min( 50, absint( $input['login_limit'] ?? 8 ) ) );
        $out['login_window'] = max( 1, min( 1440, absint( $input['login_window'] ?? 15 ) ) );
        $legacy_private_enabled = ! empty( $current['private_login_enabled'] );
        $private_mode = sanitize_key( (string) ( $input['private_login_mode'] ?? ( $legacy_private_enabled ? 'test' : 'off' ) ) );
        if ( ! in_array( $private_mode, array( 'off','test','enforce' ), true ) ) $private_mode = 'off';
        $out['private_login_mode'] = $private_mode;
        $out['private_login_enabled'] = 'off' === $private_mode ? 0 : 1; // compatibility mirror for older reports / rollback.
        $login_slug = YSEC_Private_Login::sanitize_slug( (string) ( $input['private_login_slug'] ?? $current['private_login_slug'] ?? '' ), 'login' );
        $admin_slug = YSEC_Private_Login::sanitize_slug( (string) ( $input['private_admin_slug'] ?? $current['private_admin_slug'] ?? '' ), 'admin' );
        if ( 'off' !== $private_mode ) {
            if ( '' === $login_slug ) $login_slug = YSEC_Private_Login::generate_slug( 'login' );
            if ( '' !== $admin_slug && hash_equals( $login_slug, $admin_slug ) ) $admin_slug = YSEC_Private_Login::generate_slug( 'admin' );
        }
        $out['private_login_slug'] = $login_slug;
        $out['private_admin_slug'] = $admin_slug;
        $out['comment_rate_limit'] = max( 3, min( 100, absint( $input['comment_rate_limit'] ?? $current['comment_rate_limit'] ?? 10 ) ) );
        $out['comment_rate_window'] = max( 1, min( 60, absint( $input['comment_rate_window'] ?? $current['comment_rate_window'] ?? 10 ) ) );
        $provider = sanitize_key( (string) ( $input['captcha_provider'] ?? 'none' ) );
        $out['captcha_provider'] = in_array( $provider, array( 'none', 'turnstile', 'recaptcha' ), true ) ? $provider : 'none';
        $out['captcha_site_key'] = sanitize_text_field( (string) ( $input['captcha_site_key'] ?? $current['captcha_site_key'] ?? '' ) );
        if ( ! empty( $input['captcha_clear_secret'] ) ) {
            $out['captcha_secret_key'] = '';
        } elseif ( ! empty( $input['captcha_secret_key'] ) ) {
            $out['captcha_secret_key'] = self::encrypt( sanitize_text_field( (string) $input['captcha_secret_key'] ) );
        } else {
            $out['captcha_secret_key'] = (string) ( $current['captcha_secret_key'] ?? '' );
        }
        $out['retention_days'] = max( 1, min( 365, absint( $input['retention_days'] ?? 30 ) ) );
        $out['evidence_retention_info'] = max( 1, min( 30, absint( $input['evidence_retention_info'] ?? $current['evidence_retention_info'] ?? 1 ) ) );
        $out['evidence_retention_medium'] = max( $out['evidence_retention_info'], min( 90, absint( $input['evidence_retention_medium'] ?? $current['evidence_retention_medium'] ?? 3 ) ) );
        $out['evidence_retention_high'] = max( $out['evidence_retention_medium'], min( 180, absint( $input['evidence_retention_high'] ?? $current['evidence_retention_high'] ?? 7 ) ) );
        $out['evidence_retention_critical'] = max( $out['evidence_retention_high'], min( 365, absint( $input['evidence_retention_critical'] ?? $current['evidence_retention_critical'] ?? 30 ) ) );
        $out['rollup_days'] = max( 30, min( 1095, absint( $input['rollup_days'] ?? $current['rollup_days'] ?? 365 ) ) );
        $out['event_max_rows'] = max( 10000, min( 2000000, absint( $input['event_max_rows'] ?? 250000 ) ) );
        $out['trusted_proxies'] = sanitize_textarea_field( $input['trusted_proxies'] ?? '' );
        $out['country_blocklist'] = YSEC_Country_Policy::sanitize_list( sanitize_textarea_field( $input['country_blocklist'] ?? $current['country_blocklist'] ?? '' ) );
        $country_scope = sanitize_key( (string) ( $input['country_block_scope'] ?? $current['country_block_scope'] ?? 'public' ) );
        $out['country_block_scope'] = in_array( $country_scope, array( 'auth','public','all' ), true ) ? $country_scope : 'public';
        $out['alerts_email'] = sanitize_email( (string) ( $input['alerts_email'] ?? $current['alerts_email'] ?? '' ) );
        $out['xmlrpc_mode'] = in_array( $input['xmlrpc_mode'] ?? 'monitor', array( 'monitor','pingbacks','disable' ), true ) ? $input['xmlrpc_mode'] : 'monitor';
        $technology_mode = sanitize_key( (string) ( $input['technology_exposure_mode'] ?? $current['technology_exposure_mode'] ?? 'safe' ) );
        $out['technology_exposure_mode'] = in_array( $technology_mode, array( 'off','safe','extended' ), true ) ? $technology_mode : 'safe';
        // Yablonsky AI account and routing preferences are saved only from the dedicated AI workspace.
        return $out;
    }
    public static function log_string( string $value, int $max=2048 ): string  {
        $value=wp_check_invalid_utf8($value,true);
        $value=preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u','',$value)??'';
        return function_exists('mb_substr') ? mb_substr($value,0,$max,'UTF-8') : substr($value,0,$max);
    }
    public static function safe_url_for_log( string $url ): string  {
        $url = esc_url_raw( $url );
        if ( '' === $url ) {
            return '';
        }
        $parts = wp_parse_url( $url );
        if ( ! is_array( $parts ) ) {
            return '';
        }
        $scheme = isset( $parts['scheme'] ) ? strtolower( (string) $parts['scheme'] ) : '';
        $host = isset( $parts['host'] ) ? strtolower( (string) $parts['host'] ) : '';
        $path = isset( $parts['path'] ) ? (string) $parts['path'] : '';
        $port = isset( $parts['port'] ) ? ':' . absint( $parts['port'] ) : '';
        if ( '' !== $host && in_array( $scheme, array( 'http', 'https' ), true ) ) {
            return self::log_string( $scheme . '://' . $host . $port . $path, 2048 );
        }
        return self::log_string( $path, 2048 );
    }
    public static function request_id(): string  {
        static $id = null;
        if ( null === $id )  {
            $id = wp_generate_uuid4();
        }
        return $id;
    }
    public static function normalize_path( string $uri ): string  {
        $path = wp_parse_url( $uri, PHP_URL_PATH );
        if ( ! is_string( $path ) || '' === $path )  {
            return '/';
        }
        $decoded = rawurldecode( $path );
        $decoded = preg_replace( '#/+#', '/', $decoded );
        return substr( $decoded ?: '/', 0, 2048 );
    }
    public static function client_ip(): string  {
        $remote_raw = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
        $remote = self::valid_ip( $remote_raw );
        if ( ! $remote ) return '';

        // Cloudflare headers are trusted only when the TCP peer is in Cloudflare's published
        // origin-facing proxy ranges. A direct visitor cannot forge CF-Connecting-IP into authority.
        if ( self::ip_in_list( $remote, self::cloudflare_proxy_ranges() ) ) {
            $cf_raw = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '';
            $cf_ip = self::valid_ip( $cf_raw );
            if ( '' !== $cf_ip ) return $cf_ip;
        }

        $trusted = self::trusted_proxy_list();
        if ( ! self::ip_in_list( $remote, $trusted ) ) return $remote;
        $xff = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '' ) );
        if ( '' === $xff ) return $remote;
        $chain = array_map( 'trim', explode( ',', $xff ) );
        if ( count( $chain ) > 12 ) return $remote;
        foreach ( $chain as $hop ) { if ( ! self::valid_ip( $hop ) ) return $remote; }
        $chain[] = $remote;
        for ( $i = count( $chain ) - 1; $i >= 0; $i-- )  {
            $ip = self::valid_ip( $chain[$i] );
            if ( ! $ip ) continue;
            if ( ! self::ip_in_list( $ip, $trusted ) ) return $ip;
        }
        return $remote;
    }
    private static function trusted_proxy_list(): array  {
        $raw = (string) self::option( 'trusted_proxies', '' );
        return array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ?: array() ) ) );
    }
    public static function early_proxy_contract(): array {
        return array(
            'trusted'    => array_slice( self::trusted_proxy_list(), 0, 100 ),
            'cloudflare' => self::cloudflare_proxy_ranges(),
        );
    }
    private static function cloudflare_proxy_ranges(): array  {
        // Cloudflare's published origin-facing proxy ranges. Keep explicit and local: these ranges
        // establish whether CF-Connecting-IP / CF-IPCountry can be treated as trusted provenance.
        return array(
            '103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','104.16.0.0/13','104.24.0.0/14',
            '108.162.192.0/18','131.0.72.0/22','141.101.64.0/18','162.158.0.0/15','172.64.0.0/13',
            '173.245.48.0/20','188.114.96.0/20','190.93.240.0/20','197.234.240.0/22','198.41.128.0/17',
            '2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32','2405:8100::/32',
            '2a06:98c0::/29','2c0f:f248::/32',
        );
    }
    private static function valid_ip( string $ip ): string  {
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
    }
    private static function ip_in_list( string $ip, array $list ): bool  {
        foreach ( $list as $entry )  {
            if ( $ip === $entry )  {
                return true;
            }
            if ( false !== strpos( $entry, '/' ) && self::cidr_match( $ip, $entry ) )  {
                return true;
            }
        }
        return false;
    }
    private static function cidr_match( string $ip, string $cidr ): bool  {
        list( $subnet, $mask ) = array_pad( explode( '/', $cidr, 2 ), 2, null );
        $ip_bin = @inet_pton( $ip );
        $subnet_bin = @inet_pton( (string) $subnet );
        if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) )  {
            return false;
        }
        $bits = (int) $mask;
        $max = 8 * strlen( $ip_bin );
        if ( $bits < 0 || $bits > $max )  {
            return false;
        }
        $bytes = intdiv( $bits, 8 );
        $rem = $bits % 8;
        if ( $bytes && substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) )  {
            return false;
        }
        if ( $rem )  {
            $m = ( 0xFF << ( 8 - $rem ) ) & 0xFF;
            if ( ( ord( $ip_bin[$bytes] ) & $m ) !== ( ord( $subnet_bin[$bytes] ) & $m ) )  {
                return false;
            }
        }
        return true;
    }
    public static function source_identity( string $ip ): string  {
        $ip = self::valid_ip( $ip );
        if ( '' === $ip ) return '';
        return hash_hmac( 'sha256', 'source-ip|' . $ip, wp_salt( 'auth' ) );
    }
    public static function legacy_fingerprint( string $ip ): string  {
        $ip = self::valid_ip( $ip );
        if ( '' === $ip ) return '';
        $ua = self::user_agent();
        return hash_hmac( 'sha256', $ip . '|' . substr( $ua, 0, 300 ), wp_salt( 'auth' ) );
    }
    public static function fingerprint( string $ip ): string  {
        // Backward-compatible API name. Enforcement identity is intentionally stable across User-Agent rotation.
        return self::source_identity( $ip );
    }
    public static function user_agent(): string  {
        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        return self::log_string( $ua, 512 );
    }
    public static function country_signal(): string  {
        $remote_raw = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
        $remote = self::valid_ip( $remote_raw );
        if ( '' === $remote || ! self::ip_in_list( $remote, self::cloudflare_proxy_ranges() ) ) return '';
        $raw = isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) ) : '';
        if ( ! preg_match( '/^[A-Z]{2}$/', $raw ) || in_array( $raw, array( 'XX', 'T1' ), true ) ) return '';
        return $raw;
    }
    public static function redacted_query(): string  {
        $query = isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '';
        if ( '' === $query ) return '';
        $pairs = array();
        wp_parse_str( $query, $pairs );
        $clean = self::redact_query_value( $pairs );
        return self::log_string( http_build_query( $clean, '', '&', PHP_QUERY_RFC3986 ), 1024 );
    }
    private static function redact_query_value( $value, string $key = '' )  {
        if ( preg_match( '/pass|password|secret|token|key|auth|authorization|cookie|nonce|email|user|login/i', $key ) ) return '[redacted]';
        if ( is_array( $value ) ) {
            $out = array();
            foreach ( $value as $k => $v ) $out[ sanitize_key( (string) $k ) ] = self::redact_query_value( $v, (string) $k );
            return $out;
        }
        return self::log_string( sanitize_text_field( (string) $value ), 256 );
    }
    public static function masked_ip( string $ip ): string  {
        $ip = self::valid_ip( $ip );
        if ( '' === $ip ) return '';
        if ( false !== strpos( $ip, ':' ) ) {
            $bin = inet_pton( $ip );
            if ( false === $bin ) return '';
            $hex = bin2hex( substr( $bin, 0, 8 ) );
            return implode( ':', str_split( $hex, 4 ) ) . '::/64';
        }
        $parts = explode( '.', $ip );
        return count( $parts ) === 4 ? $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.x' : '';
    }
    public static function encrypt( string $value ): string  {
        if ( '' === $value )  {
            return '';
        }
        $key = hash( 'sha256', wp_salt( 'secure_auth' ), true );
        if ( function_exists( 'sodium_crypto_secretbox' ) )  {
            $nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
            return 's1:' . base64_encode( $nonce . sodium_crypto_secretbox( $value, $nonce, $key ) );
        }
        if ( function_exists( 'openssl_encrypt' ) )  {
            $iv = random_bytes( 12 );
            $tag = '';
            $cipher = openssl_encrypt( $value, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
            if ( false !== $cipher )  {
                return 'o1:' . base64_encode( $iv . $tag . $cipher );
            }
        }
        return '';
    }
    public static function decrypt( string $value ): string  {
        if ( str_starts_with( $value, 's1:' ) && function_exists( 'sodium_crypto_secretbox_open' ) )  {
            $raw = base64_decode( substr( $value, 3 ), true );
            if ( false === $raw )  {
                return '';
            }
            $n = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
            if ( strlen( $raw ) <= $n )  {
                return '';
            }
            $key = hash( 'sha256', wp_salt( 'secure_auth' ), true );
            $out = sodium_crypto_secretbox_open( substr( $raw, $n ), substr( $raw, 0, $n ), $key );
            return false === $out ? '' : $out;
        }
        if ( str_starts_with( $value, 'o1:' ) && function_exists( 'openssl_decrypt' ) )  {
            $raw = base64_decode( substr( $value, 3 ), true );
            if ( false === $raw || strlen( $raw ) < 29 )  {
                return '';
            }
            $iv=substr($raw,0,12);
            $tag=substr($raw,12,16);
            $cipher=substr($raw,28);
            $key=hash('sha256',wp_salt('secure_auth'),true);
            $out=openssl_decrypt($cipher,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag);
            return false===$out?'':$out;
        }
        return '';
    }
    public static function redact( $data )  {
        if ( is_array( $data ) )  {
            foreach ( $data as $k => $v )  {
                if ( preg_match( '/pass|secret|token|key|authorization|cookie/i', (string) $k ) )  {
                    $data[$k] = '[redacted]';
                }
                else  {
                    $data[$k] = self::redact( $v );
                }
            }
        }
        return $data;
    }
}
