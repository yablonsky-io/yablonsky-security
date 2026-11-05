<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Discovery / crawler interoperability boundary.
 *
 * Yablonsky Security owns request safety and response. Search/AI discovery permissions,
 * robots controls and crawler-surface policy belong to Yablonsky SEO (when installed)
 * or another discovery-policy owner. These APIs exchange bounded context without
 * granting any crawler a security bypass.
 */
final class YSEC_Discovery_Interop {
    public const CONTRACT_VERSION = '1.0.0';

    public static function yseo_active(): bool {
        $plugins = (array) get_option( 'active_plugins', array() );
        if ( is_multisite() ) {
            $plugins = array_merge( $plugins, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
        }
        foreach ( $plugins as $plugin ) {
            $plugin = strtolower( (string) $plugin );
            if ( str_contains( $plugin, 'yablonsky-seo' ) || str_contains( $plugin, '/yseo' ) ) return true;
        }
        return false;
    }

    /**
     * Vendor-neutral discovery policy context.
     *
     * YSec does not interpret these preferences as permission to bypass security.
     * Another plugin (normally YSEO) may enrich them via `ysec_discovery_policy_context`.
     */
    public static function policy_context( array $request_context = array() ): array {
        $policy = array(
            'contract_version' => self::CONTRACT_VERSION,
            'owner'            => self::yseo_active() ? 'yseo' : 'external_or_unset',
            'search_discovery' => 'neutral',
            'ai_answers'       => 'neutral',
            'ai_agents'        => 'neutral',
            'model_training'   => 'neutral',
        );
        /**
         * Filter vendor-neutral discovery policy context.
         *
         * @param array $policy Discovery preferences. Security enforcement does not trust this as a bypass.
         * @param array $request_context Sanitized request context.
         */
        $filtered = apply_filters( 'ysec_discovery_policy_context', $policy, $request_context );
        if ( ! is_array( $filtered ) ) $filtered = $policy;
        $allowed = array( 'allow', 'disallow', 'neutral', 'unknown' );
        foreach ( array( 'search_discovery', 'ai_answers', 'ai_agents', 'model_training' ) as $key ) {
            $value = sanitize_key( (string) ( $filtered[ $key ] ?? $policy[ $key ] ) );
            $policy[ $key ] = in_array( $value, $allowed, true ) ? $value : 'neutral';
        }
        $owner = sanitize_key( (string) ( $filtered['owner'] ?? $policy['owner'] ) );
        $policy['owner'] = '' !== $owner ? substr( $owner, 0, 64 ) : $policy['owner'];
        return $policy;
    }

    public static function crawler_registry(): array {
        $rows = array(
            array( 'pattern'=>'~OAI-AdsBot~i', 'provider'=>'openai', 'agent'=>'OAI-AdsBot', 'surface'=>'ads_validation' ),
            array( 'pattern'=>'~OAI-SearchBot~i', 'provider'=>'openai', 'agent'=>'OAI-SearchBot', 'surface'=>'ai_search' ),
            array( 'pattern'=>'~ChatGPT-User~i', 'provider'=>'openai', 'agent'=>'ChatGPT-User', 'surface'=>'user_fetch' ),
            array( 'pattern'=>'~GPTBot~i', 'provider'=>'openai', 'agent'=>'GPTBot', 'surface'=>'model_training' ),
            array( 'pattern'=>'~Google-InspectionTool~i', 'provider'=>'google', 'agent'=>'Google-InspectionTool', 'surface'=>'search' ),
            array( 'pattern'=>'~AdsBot-Google~i', 'provider'=>'google', 'agent'=>'AdsBot-Google', 'surface'=>'ads_validation' ),
            array( 'pattern'=>'~GoogleOther~i', 'provider'=>'google', 'agent'=>'GoogleOther', 'surface'=>'search' ),
            array( 'pattern'=>'~Googlebot~i', 'provider'=>'google', 'agent'=>'Googlebot', 'surface'=>'search' ),
            array( 'pattern'=>'~bingbot~i', 'provider'=>'microsoft', 'agent'=>'Bingbot', 'surface'=>'search' ),
            array( 'pattern'=>'~Applebot~i', 'provider'=>'apple', 'agent'=>'Applebot', 'surface'=>'search' ),
            array( 'pattern'=>'~Claude-SearchBot~i', 'provider'=>'anthropic', 'agent'=>'Claude-SearchBot', 'surface'=>'ai_search' ),
            array( 'pattern'=>'~Claude-User~i', 'provider'=>'anthropic', 'agent'=>'Claude-User', 'surface'=>'user_fetch' ),
            array( 'pattern'=>'~ClaudeBot~i', 'provider'=>'anthropic', 'agent'=>'ClaudeBot', 'surface'=>'model_training' ),
            array( 'pattern'=>'~Perplexity-User~i', 'provider'=>'perplexity', 'agent'=>'Perplexity-User', 'surface'=>'user_fetch' ),
            array( 'pattern'=>'~PerplexityBot~i', 'provider'=>'perplexity', 'agent'=>'PerplexityBot', 'surface'=>'ai_search' ),
            array( 'pattern'=>'~Amazonbot~i', 'provider'=>'amazon', 'agent'=>'Amazonbot', 'surface'=>'search' ),
            array( 'pattern'=>'~Bytespider~i', 'provider'=>'bytedance', 'agent'=>'Bytespider', 'surface'=>'crawler' ),
            array( 'pattern'=>'~meta-externalagent~i', 'provider'=>'meta', 'agent'=>'Meta-ExternalAgent', 'surface'=>'agent' ),
            array( 'pattern'=>'~meta-externalfetcher~i', 'provider'=>'meta', 'agent'=>'Meta-ExternalFetcher', 'surface'=>'agent' ),
            array( 'pattern'=>'~CCBot~i', 'provider'=>'common_crawl', 'agent'=>'CCBot', 'surface'=>'crawler' ),
            array( 'pattern'=>'~DuckAssistBot~i', 'provider'=>'duckduckgo', 'agent'=>'DuckAssistBot', 'surface'=>'ai_search' ),
            array( 'pattern'=>'~YouBot~i', 'provider'=>'you_com', 'agent'=>'YouBot', 'surface'=>'ai_search' ),
            array( 'pattern'=>'~PetalBot~i', 'provider'=>'huawei', 'agent'=>'PetalBot', 'surface'=>'search' ),
            array( 'pattern'=>'~YandexBot~i', 'provider'=>'yandex', 'agent'=>'YandexBot', 'surface'=>'search' ),
            array( 'pattern'=>'~Baiduspider~i', 'provider'=>'baidu', 'agent'=>'Baiduspider', 'surface'=>'search' ),
        );
        // Policy-only robots directives are never presented as real HTTP User-Agent crawlers.
        $filtered = apply_filters( 'ysec_crawler_registry_v1', $rows );
        return is_array( $filtered ) ? array_values( array_filter( $filtered, 'is_array' ) ) : $rows;
    }

    public static function claimed_crawler( string $user_agent = '' ): array {
        $ua = '' !== $user_agent ? YSEC_Utils::log_string( $user_agent, 512 ) : YSEC_Utils::user_agent();
        if ( '' === $ua ) return array( 'claimed'=>false, 'provider'=>'', 'agent'=>'', 'surface'=>'unknown' );
        // These are policy-only robots.txt controls, never separate HTTP User-Agents.
        if ( preg_match( '~(?:Google-Extended|Applebot-Extended)~i', $ua ) ) return array( 'claimed'=>false, 'provider'=>'', 'agent'=>'', 'surface'=>'unknown' );
        foreach ( self::crawler_registry() as $row ) {
            $pattern = (string) ( $row['pattern'] ?? '' );
            if ( '' !== $pattern && @preg_match( $pattern, $ua ) ) {
                return array(
                    'claimed'  => true,
                    'provider' => sanitize_key( (string) ( $row['provider'] ?? 'crawler' ) ),
                    'agent'    => sanitize_text_field( (string) ( $row['agent'] ?? 'Crawler' ) ),
                    'surface'  => sanitize_key( (string) ( $row['surface'] ?? 'crawler' ) ),
                );
            }
        }
        return array( 'claimed'=>false, 'provider'=>'', 'agent'=>'', 'surface'=>'unknown' );
    }

    public static function crawler_summary(): array {
        $registry = self::crawler_registry();
        $providers = array_values( array_unique( array_filter( array_map( static fn( array $row ): string => sanitize_key( (string) ( $row['provider'] ?? '' ) ), $registry ) ) ) );
        return array(
            'agents'             => count( $registry ),
            'providers'          => count( $providers ),
            'security_basis'     => 'behavior_first',
            'publication_owner'  => self::yseo_active() ? 'yseo' : 'site_policy',
            'identity_enrichment'=> 'official_cidr_async',
            'verification_feeds' => YSEC_Crawler_Verification::health(),
        );
    }

    /** Resolve official identity evidence without network operations or bypass semantics. */
    public static function identity( string $user_agent = '', array $request_context = array() ): array {
        $claim = self::claimed_crawler( $user_agent );
        $identity = array_merge( $claim, array(
            'verified' => false,
            'trust' => ! empty( $claim['claimed'] ) ? 'unverified_claim' : 'not_claimed',
            'status' => 'unknown', 'verifier' => '', 'method' => 'none',
            'checked_at' => '', 'evidence_source' => '', 'purpose' => array(),
            'behavior' => 'unknown',
        ) );
        if ( empty( $claim['claimed'] ) ) return $identity;
        $ip = YSEC_Utils::client_ip();
        $proof = YSEC_Crawler_Verification::check( (string) $claim['agent'], $ip );
        $identity['status'] = (string) $proof['status'];
        $identity['method'] = (string) $proof['method'];
        $identity['checked_at'] = (string) $proof['checked_at'];
        $identity['evidence_source'] = (string) $proof['evidence_source'];
        $identity['purpose'] = (array) $proof['purpose'];
        $identity['verified'] = 'verified' === $identity['status'];
        $identity['trust'] = $identity['verified'] ? 'verified' : ( 'spoofed' === $identity['status'] ? 'spoofed' : 'unverified_claim' );
        $identity['verifier'] = $identity['verified'] ? 'official_ip_cidr' : '';

        // Compatibility hook can supply supplemental data, but cannot promote a UA claim
        // to verified. Only the trusted internal proof engine may set that verdict.
        $enriched = apply_filters( 'ysec_crawler_identity', $identity, $request_context );
        if ( is_array( $enriched ) && isset( $enriched['behavior'] ) ) {
            $behavior = sanitize_key( (string) $enriched['behavior'] );
            if ( in_array( $behavior, array( 'unknown', 'normal', 'rate_anomaly', 'suspected_abuse', 'confirmed_abuse' ), true ) ) {
                $identity['behavior'] = $behavior;
            }
        }
        return $identity;
    }

    public static function request_context(): array {
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        $uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
        return array(
            'method' => $method,
            'path'   => YSEC_Utils::normalize_path( $uri ),
            'host'   => isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '',
        );
    }

    public static function evidence_context(): array {
        $request = self::request_context();
        $identity = self::identity( '', $request );
        if ( empty( $identity['claimed'] ) ) return array();
        return array(
            'crawler_claim' => array(
                'provider' => $identity['provider'],
                'agent'    => $identity['agent'],
                'surface'  => $identity['surface'],
                'verified' => (bool) $identity['verified'],
                'trust'    => $identity['trust'],
                'verifier' => $identity['verifier'],
                'status' => $identity['status'],
                'method' => $identity['method'],
                'checked_at' => $identity['checked_at'],
                'evidence_source' => $identity['evidence_source'],
                'purpose' => $identity['purpose'],
                'behavior' => $identity['behavior'],
            ),
            'discovery_policy_owner' => self::yseo_active() ? 'yseo' : 'external_or_unset',
        );
    }

    public static function publish_security_signal( array $decision ): void {
        $evidence = self::evidence_context();
        if ( empty( $evidence['crawler_claim'] ) ) return;
        $payload = array(
            'contract_version' => self::CONTRACT_VERSION,
            'decision'         => sanitize_key( (string) ( $decision['decision'] ?? 'observed' ) ),
            'blocked'          => ! empty( $decision['blocked'] ),
            'family'           => sanitize_key( (string) ( $decision['family'] ?? 'security' ) ),
            'families'         => array_values( array_unique( array_filter( array_map( 'sanitize_key', (array) ( $decision['families'] ?? array() ) ) ) ) ),
            'method'           => substr( sanitize_key( (string) ( $decision['method'] ?? 'GET' ) ), 0, 12 ),
            'path'             => YSEC_Utils::log_string( (string) ( $decision['path'] ?? '/' ), 2048 ),
            'request_id'       => sanitize_text_field( (string) ( $decision['request_id'] ?? '' ) ),
            'crawler_claim'    => $evidence['crawler_claim'],
            'policy_owner'     => (string) ( $evidence['discovery_policy_owner'] ?? 'external_or_unset' ),
        );
        /**
         * Publish a bounded crawler-related security observation for discovery-policy tooling.
         * No raw IP, cookie, Authorization header, password or request body is included.
         *
         * @param array $payload Sanitized security observation.
         */
        do_action( 'ysec_discovery_security_signal', $payload );
    }

    public static function admin_summary(): array {
        $active = self::yseo_active();
        return array(
            'yseo_active' => $active,
            'owner'       => $active ? 'Yablonsky SEO' : __( 'Site publication policy', 'yablonsky-security' ),
            'contract'    => self::CONTRACT_VERSION,
        );
    }
}
