<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Provider evidence registry: bounded, official HTTPS feeds refreshed only by WP-Cron.
 * No DNS/HTTP calls on visitor requests, no crawler-specific bypass.
 */
final class YSEC_Crawler_Verification {
    public const CONTRACT_VERSION = '1.0';
    private const OPTION = 'ysec_crawler_official_feeds_v1';
    private const BATCH = 2;
    private const GOOD_SECONDS = 172800; // 48h from successful verified retrieval.
    private const POLL_SECONDS = 43200; // 12 hours / feed when cron catches up.

    /** Profiles from official provider documentation; not a per-request verified verdict. */
    public static function profiles(): array {
        return array(
            'Googlebot'          => array('provider'=>'google','purpose'=>array('search'),'feed'=>'google_common','document'=>'https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests'),
            'GoogleOther'        => array('provider'=>'google','purpose'=>array('search'),'feed'=>'google_common','document'=>'https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests'),
            'AdsBot-Google'      => array('provider'=>'google','purpose'=>array('ads_validation'),'feed'=>'google_special','document'=>'https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests'),
            'Google-InspectionTool'=>array('provider'=>'google','purpose'=>array('user_fetch'),'feed'=>'google_user','document'=>'https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests'),
            'OAI-SearchBot'      => array('provider'=>'openai','purpose'=>array('ai_search'),'feed'=>'openai_search','document'=>'https://developers.openai.com/api/docs/bots'),
            'OAI-AdsBot'         => array('provider'=>'openai','purpose'=>array('ads_validation'),'feed'=>'openai_ads','document'=>'https://developers.openai.com/api/docs/bots'),
            'GPTBot'             => array('provider'=>'openai','purpose'=>array('training'),'feed'=>'openai_training','document'=>'https://developers.openai.com/api/docs/bots'),
            'ChatGPT-User'       => array('provider'=>'openai','purpose'=>array('user_fetch'),'feed'=>'openai_user','document'=>'https://developers.openai.com/api/docs/bots'),
            'PerplexityBot'      => array('provider'=>'perplexity','purpose'=>array('ai_search'),'feed'=>'perplexity_search','document'=>'https://docs.perplexity.ai/docs/resources/perplexity-crawlers'),
            'Perplexity-User'    => array('provider'=>'perplexity','purpose'=>array('user_fetch'),'feed'=>'perplexity_user','document'=>'https://docs.perplexity.ai/docs/resources/perplexity-crawlers'),
            'ClaudeBot'          => array('provider'=>'anthropic','purpose'=>array('training'),'feed'=>'anthropic','document'=>'https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler'),
            'Claude-SearchBot'   => array('provider'=>'anthropic','purpose'=>array('ai_search'),'feed'=>'anthropic','document'=>'https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler'),
            'Claude-User'        => array('provider'=>'anthropic','purpose'=>array('user_fetch'),'feed'=>'anthropic','document'=>'https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler'),
            'Applebot'          => array('provider'=>'apple','purpose'=>array('search'),'feed'=>'apple','document'=>'https://support.apple.com/en-us/119829'),
            'Bingbot'           => array('provider'=>'microsoft','purpose'=>array('search'),'feed'=>'bing','document'=>'https://www.bing.com/webmasters/help/verify-bingbot-2195837f'),
        );
    }

    /** Hard-coded URLs are the only permitted updater targets: prevents SSRF and host redirects. */
    public static function feed_urls(): array {
        return array(
            'google_common'     => 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
            'google_special'    => 'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
            'google_user'       => 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json',
            'openai_search'     => 'https://openai.com/searchbot.json',
            'openai_ads'        => 'https://openai.com/adsbot.json',
            'openai_training'   => 'https://openai.com/gptbot.json',
            'openai_user'       => 'https://openai.com/chatgpt-user.json',
            'perplexity_search' => 'https://www.perplexity.ai/perplexitybot.json',
            'perplexity_user'   => 'https://www.perplexity.ai/perplexity-user.json',
            'anthropic'         => 'https://claude.com/crawling/bots.json',
            'bing'              => 'https://www.bing.com/toolbox/bingbot.json',
            'apple'             => 'https://search.developer.apple.com/applebot.json',
        );
    }

    /** Safe parser for the Google/OpenAI/Anthropic/Perplexity official JSON prefix formats. */
    public static function parse_feed( string $json ): array {
        if ( strlen( $json ) > 350000 ) return array();
        $data = json_decode( $json, true );
        if ( ! is_array( $data ) || ! isset( $data['prefixes'] ) || ! is_array( $data['prefixes'] ) || count( $data['prefixes'] ) > 5000 ) return array();
        $ranges = array();
        foreach ( $data['prefixes'] as $row ) {
            if ( ! is_array( $row ) ) return array();
            $s = isset( $row['ipv4Prefix'] ) ? $row['ipv4Prefix'] : ( $row['ipv6Prefix'] ?? null );
            if ( ! is_string( $s ) || ! self::valid_cidr( $s ) ) return array();
            $ranges[] = $s;
        }
        return array_values( array_unique( $ranges ) );
    }

    public static function valid_cidr( string $range ): bool {
        if ( strlen( $range ) > 64 || 1 !== substr_count( $range, '/' ) ) return false;
        list( $ip, $bits ) = explode( '/', $range, 2 );
        if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) || ! preg_match( '/^(?:0|[1-9][0-9]{0,2})$/D', $bits ) ) return false;
        $packed = @inet_pton( $ip );
        return false !== $packed && (int) $bits <= 8 * strlen( $packed );
    }

    public static function ip_in_cidr( string $ip, string $range ): bool {
        if ( ! self::valid_cidr( $range ) ) return false;
        list( $network, $mask ) = explode( '/', $range, 2 );
        $packed = @inet_pton( $ip );
        $net = @inet_pton( $network );
        if ( false === $packed || false === $net || strlen( $packed ) !== strlen( $net ) ) return false;
        $bits = (int) $mask;
        $bytes = intdiv( $bits, 8 );
        $extra = $bits % 8;
        return substr( $packed, 0, $bytes ) === substr( $net, 0, $bytes )
            && ( 0 === $extra || ( ( ord( $packed[$bytes] ) ^ ord( $net[$bytes] ) ) & ( 0xff << ( 8 - $extra ) ) ) === 0 );
    }

    private static function data(): array {
        static $cached = null;
        if ( null === $cached ) {
            $row = get_option( self::OPTION, array() );
            $cached = is_array( $row ) ? $row : array();
        }
        return $cached;
    }

    /** Consent is stored only through the nonce-protected administrator settings form. */
    public static function consented(): bool {
        return 1 === (int) YSEC_Utils::option( 'crawler_feeds_consent', 0 );
    }

    /** No network calls here, ever. This function can safely be used in hot paths. */
    public static function check( string $agent, string $ip ): array {
        $profiles = self::profiles();
        $p = $profiles[ $agent ] ?? array();
        $feed = (string) ( $p['feed'] ?? '' );
        $result = array(
            'status' => 'unverified', 'method' => 'none', 'evidence_source' => '',
            'checked_at' => '', 'valid_until' => '', 'purpose' => (array) ( $p['purpose'] ?? array('unknown') ),
            'provider' => (string) ( $p['provider'] ?? '' ),
        );
        if ( '' === $feed || ! isset( self::feed_urls()[ $feed ] ) ) return $result;
        // Explicit opt-in, fail-closed even when a formerly fetched record is fresh.
        if ( ! self::consented() ) {
            $result['status'] = 'verification_unavailable';
            return $result;
        }
        $result['method'] = 'provider_ip_cidr';
        $result['evidence_source'] = self::feed_urls()[ $feed ];
        if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            $result['status'] = 'verification_unavailable';
            return $result;
        }
        $record = self::data()[ $feed ] ?? array();
        $when = is_array( $record ) ? (int) ( $record['checked'] ?? 0 ) : 0;
        $ranges = is_array( $record ) ? ( $record['ranges'] ?? array() ) : array();
        if ( $when <= 0 || $when > time() || time() - $when > self::GOOD_SECONDS || ! is_array( $ranges ) || empty( $ranges ) ) {
            $result['status'] = 'verification_unavailable';
            return $result;
        }
        $result['checked_at'] = gmdate( 'Y-m-d\TH:i:s\Z', $when );
        $result['valid_until'] = gmdate( 'Y-m-d\TH:i:s\Z', $when + self::GOOD_SECONDS );
        foreach ( array_slice( $ranges, 0, 5000 ) as $range ) {
            if ( is_string( $range ) && self::ip_in_cidr( $ip, $range ) ) {
                $result['status'] = 'verified';
                return $result;
            }
        }
        $result['status'] = 'spoofed'; // Fresh authoritative provider CIDR mismatched a claimed HTTP identity.
        return $result;
    }

    /** Bound network work to two feeds per hourly housekeeping run; never run for visitors. */
    public static function refresh_due(): void {
        if ( ! wp_doing_cron() || ! self::consented() ) return;
        $urls = self::feed_urls();
        $stored = get_option( self::OPTION, array() );
        if ( ! is_array( $stored ) ) $stored = array();
        $updated = false;
        $checked = 0;
        foreach ( $urls as $id => $url ) {
            $item = is_array( $stored[$id] ?? null ) ? $stored[$id] : array();
            if ( time() - (int) ( $item['attempted'] ?? 0 ) < self::POLL_SECONDS ) continue;
            if ( ++$checked > self::BATCH ) break;
            $item['attempted'] = time();
            $response = wp_remote_get( $url, array(
                'timeout' => 4, 'redirection' => 0, 'sslverify' => true,
                'limit_response_size' => 350001, 'reject_unsafe_urls' => true, 'user-agent' => 'Yablonsky-Security/' . YSEC_VERSION,
            ) );
            if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
                $parsed = self::parse_feed( (string) wp_remote_retrieve_body( $response ) );
                if ( ! empty( $parsed ) ) {
                    $item['ranges'] = $parsed;
                    $item['checked'] = time();
                    $item['source'] = $url;
                }
            }
            // On failure preserve last-known-good, but expiration in check() prevents stale trust.
            $stored[$id] = $item;
            $updated = true;
        }
        if ( $updated ) update_option( self::OPTION, $stored, false );
    }

    /** Aggregate only; no IPs or request bodies. */
    public static function health(): array {
        $stored = self::data();
        $out = array( 'feeds_total' => count(self::feed_urls()), 'fresh' => 0, 'stale' => 0, 'missing' => 0, 'consent' => self::consented() );
        foreach ( self::feed_urls() as $key => $url ) {
            $record = $stored[$key] ?? null;
            $when = is_array( $record ) ? (int) ( $record['checked'] ?? 0 ) : 0;
            if ( $when <= 0 ) $out['missing']++;
            elseif ( time() - $when > self::GOOD_SECONDS ) $out['stale']++;
            else $out['fresh']++;
        }
        return $out;
    }
}
