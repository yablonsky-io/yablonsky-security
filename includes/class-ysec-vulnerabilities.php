<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class YSEC_Vulnerabilities {
    private const CACHE_KEY = 'ysec_vulnerability_inventory_v2';

    public static function boot(): void {
        add_action( 'activated_plugin', array( __CLASS__, 'clear_cache' ) );
        add_action( 'deactivated_plugin', array( __CLASS__, 'clear_cache' ) );
        add_action( 'switch_theme', array( __CLASS__, 'clear_cache' ) );
        add_action( 'upgrader_process_complete', array( __CLASS__, 'clear_cache' ), 10, 0 );
    }

    public static function clear_cache(): void {
        try {
            delete_transient( self::CACHE_KEY );
        } catch ( Throwable $e ) {
            // Cache invalidation must never make a successful software update fatal.
        }
    }


    public static function advisory_applies( array $advisory, string $component, string $version, string $package_type = 'plugin' ): bool {
        $adv_component = (string) ( $advisory['component'] ?? $advisory['slug'] ?? '' );
        if ( '' === $adv_component || '' === $component || ! hash_equals( strtolower( $adv_component ), strtolower( $component ) ) ) return false;
        $adv_type = sanitize_key( (string) ( $advisory['package_type'] ?? 'unknown' ) );
        if ( 'unknown' !== $adv_type && '' !== $package_type && $adv_type !== sanitize_key( $package_type ) ) return false;
        if ( '' === $version ) return true;
        $min = (string) ( $advisory['min_version'] ?? '' );
        $max = (string) ( $advisory['max_version'] ?? '' );
        $fixed = (string) ( $advisory['fixed_in'] ?? '' );
        if ( '' !== $min && version_compare( $version, $min, '<' ) ) return false;
        if ( '' !== $fixed && version_compare( $version, $fixed, '>=' ) ) return false;
        if ( '' !== $max ) {
            $op = ! empty( $advisory['max_inclusive'] ) ? '>' : '>=';
            if ( version_compare( $version, $max, $op ) ) return false;
        }
        return true;
    }

    public static function matching_advisories( string $component, string $version, string $package_type = 'plugin' ): array {
        $inventory = self::inventory();
        $rows = isset( $inventory['advisories'] ) && is_array( $inventory['advisories'] ) ? $inventory['advisories'] : array();
        return array_values( array_filter( $rows, static fn( $row ) => is_array( $row ) && self::advisory_applies( $row, $component, $version, $package_type ) ) );
    }

    public static function inventory(): array {
        $cached = get_transient( self::CACHE_KEY );
        if ( is_array( $cached ) ) return apply_filters( 'ysec_vulnerability_inventory', $cached );

        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        require_once ABSPATH . 'wp-admin/includes/update.php';

        $plugins  = get_plugins();
        $pupdates = get_site_transient( 'update_plugins' );
        $themes   = wp_get_themes();
        $tupdates = get_site_transient( 'update_themes' );
        $core_updates = get_site_transient( 'update_core' );
        $core_update  = '';
        if ( is_object( $core_updates ) && ! empty( $core_updates->updates ) && is_array( $core_updates->updates ) ) {
            foreach ( $core_updates->updates as $candidate ) {
                if ( is_object( $candidate ) && 'upgrade' === ( $candidate->response ?? '' ) && ! empty( $candidate->current ) ) {
                    $core_update = (string) $candidate->current;
                    break;
                }
            }
        }

        $active_plugins = (array) get_option( 'active_plugins', array() );
        $active_theme   = get_stylesheet();
        $out = array(
            'core'    => array( 'version' => get_bloginfo( 'version' ), 'update' => $core_update ),
            'plugins' => array(),
            'themes'  => array(),
        );

        foreach ( $plugins as $file => $data ) {
            $out['plugins'][] = array(
                'file'    => $file,
                'name'    => $data['Name'],
                'version' => $data['Version'],
                'update'  => isset( $pupdates->response[ $file ] ) ? (string) $pupdates->response[ $file ]->new_version : '',
                'active'  => in_array( $file, $active_plugins, true ) || ( is_multisite() && is_plugin_active_for_network( $file ) ),
            );
        }
        foreach ( $themes as $slug => $theme ) {
            $out['themes'][] = array(
                'slug'    => $slug,
                'name'    => $theme->get( 'Name' ),
                'version' => $theme->get( 'Version' ),
                'update'  => isset( $tupdates->response[ $slug ] ) ? (string) $tupdates->response[ $slug ]['new_version'] : '',
                'active'  => $slug === $active_theme,
            );
        }
        $advisories = apply_filters( 'ysec_vulnerability_advisories', array(), $out );
        $advisories = is_array( $advisories ) ? $advisories : array();
        $out['advisory_provider'] = empty( $advisories ) ? 'none' : 'connected';
        $out['advisories'] = array_values( array_filter( $advisories, 'is_array' ) );

        set_transient( self::CACHE_KEY, $out, 30 );
        return apply_filters( 'ysec_vulnerability_inventory', $out );
    }
}
