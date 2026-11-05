<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Read-only, bounded multisite/fleet diagnostics. No remote control and no cross-site mutation. */
final class YSEC_Multisite {
    private const SITE_LIMIT = 100;

    public static function report(): array {
        $is_multisite = is_multisite();
        $plugin = plugin_basename( YSEC_FILE );
        $network_active = false;
        $current_site_active = true;
        if ( $is_multisite ) {
            $network_plugins = get_site_option( 'active_sitewide_plugins', array() );
            $network_active = is_array( $network_plugins ) && isset( $network_plugins[ $plugin ] );
            $active_plugins = get_option( 'active_plugins', array() );
            $current_site_active = $network_active || ( is_array( $active_plugins ) && in_array( $plugin, $active_plugins, true ) );
        }

        $out = array(
            'multisite'            => $is_multisite,
            'network_active'       => $network_active,
            'current_site_active'  => $current_site_active,
            'network_id'           => function_exists( 'get_current_network_id' ) ? (int) get_current_network_id() : 0,
            'current_blog_id'      => (int) get_current_blog_id(),
            'site_limit'           => self::SITE_LIMIT,
            'site_count'           => 1,
            'scanned_sites'        => 1,
            'truncated'            => false,
            'active_sites'         => 1,
            'policy_groups'        => 1,
            'divergent_sites'      => 0,
            'fingerprints'         => array(),
            'sites'                => array(),
            'validation_state'     => $is_multisite ? 'local_multisite_diagnostics' : 'single_site',
        );

        if ( ! $is_multisite ) {
            $fingerprint = self::policy_fingerprint();
            $out['fingerprints'] = array( $fingerprint => 1 );
            $out['sites'][] = array(
                'blog_id'     => (int) get_current_blog_id(),
                'domain'      => (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ),
                'active'      => true,
                'fingerprint' => $fingerprint,
            );
            return $out;
        }

        $count = function_exists( 'get_sites' ) ? (int) get_sites( array( 'count' => true ) ) : 0;
        $site_ids = function_exists( 'get_sites' ) ? get_sites( array( 'number' => self::SITE_LIMIT, 'fields' => 'ids', 'orderby' => 'id', 'order' => 'ASC' ) ) : array();
        $site_ids = is_array( $site_ids ) ? array_map( 'intval', $site_ids ) : array();
        $out['site_count'] = max( $count, count( $site_ids ) );
        $out['scanned_sites'] = count( $site_ids );
        $out['truncated'] = $out['site_count'] > count( $site_ids );
        $out['active_sites'] = 0;
        $out['sites'] = array();
        $groups = array();
        $original_blog_id = (int) get_current_blog_id();

        foreach ( $site_ids as $site_id ) {
            switch_to_blog( $site_id );
            $active_plugins = get_option( 'active_plugins', array() );
            $active = $network_active || ( is_array( $active_plugins ) && in_array( $plugin, $active_plugins, true ) );
            if ( $active ) $out['active_sites']++;
            $fingerprint = $active ? self::policy_fingerprint() : '';
            if ( '' !== $fingerprint ) $groups[ $fingerprint ] = ( $groups[ $fingerprint ] ?? 0 ) + 1;
            $out['sites'][] = array(
                'blog_id'     => $site_id,
                'domain'      => (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ),
                'active'      => $active,
                'fingerprint' => $fingerprint,
            );
            restore_current_blog();
        }
        while ( get_current_blog_id() !== $original_blog_id && function_exists( 'restore_current_blog' ) ) {
            if ( ! restore_current_blog() ) break;
        }

        $out['fingerprints'] = $groups;
        $out['policy_groups'] = max( 0, count( $groups ) );
        $largest = $groups ? max( $groups ) : 0;
        $out['divergent_sites'] = max( 0, $out['active_sites'] - $largest );
        return $out;
    }

    private static function policy_fingerprint(): string {
        $settings = YSEC_Utils::settings();
        unset(
            $settings['ai_api_key'],
            $settings['captcha_secret_key'],
            $settings['captcha_site_key'],
            $settings['trusted_proxies'],
            $settings['ai_workspace_id']
        );
        $payload = array(
            'settings'          => $settings,
            'firewall_policy'   => YSEC_Firewall_Policy::exportable(),
            'conditional_rules' => YSEC_Conditional_Rules::exportable(),
            'version'           => defined( 'YSEC_VERSION' ) ? YSEC_VERSION : '',
        );
        self::ksort_recursive( $payload );
        return substr( hash( 'sha256', wp_json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ?: '' ), 0, 16 );
    }

    private static function ksort_recursive( array &$value ): void {
        foreach ( $value as &$item ) {
            if ( is_array( $item ) ) self::ksort_recursive( $item );
        }
        unset( $item );
        if ( ! YSEC_Utils::is_list_array( $value ) ) ksort( $value );
    }
}
