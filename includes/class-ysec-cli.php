<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_CLI {
    public static function boot(): void {
        if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) return;
        WP_CLI::add_command( 'ysec status', static function() {
            WP_CLI::print_value( array( 'version'=>YSEC_VERSION, 'summary'=>YSEC_Events::summary(), 'environment'=>YSEC_Environment::detect() ), array( 'format'=>'json' ) );
        } );
        WP_CLI::add_command( 'ysec doctor', static function() {
            WP_CLI::print_value( YSEC_Doctor::report(), array( 'format'=>'json' ) );
        } );
        WP_CLI::add_command( 'ysec events', static function( array $args, array $assoc_args ) {
            $limit = max( 1, min( 100, absint( $assoc_args['limit'] ?? 25 ) ) );
            $severity = sanitize_key( (string) ( $assoc_args['severity'] ?? '' ) );
            $family = sanitize_key( (string) ( $assoc_args['family'] ?? '' ) );
            $result = YSEC_Events::query( array( 'page'=>1, 'per_page'=>$limit, 'severity'=>$severity, 'family'=>$family ) );
            $result['rows'] = array_map( array( __CLASS__, 'safe_event_row' ), $result['rows'] );
            WP_CLI::print_value( $result, array( 'format'=>'json' ) );
        } );
        WP_CLI::add_command( 'ysec blocks', static function( array $args, array $assoc_args ) {
            $limit = max( 10, min( 100, absint( $assoc_args['limit'] ?? 25 ) ) );
            $result = YSEC_Firewall::query_blocks( array( 'page'=>1, 'per_page'=>$limit ) );
            $result['rows'] = array_map( array( __CLASS__, 'safe_block_row' ), $result['rows'] );
            WP_CLI::print_value( $result, array( 'format'=>'json' ) );
        } );
        WP_CLI::add_command( 'ysec policy-summary', static function() {
            $policy = YSEC_Firewall_Policy::settings();
            $country = YSEC_Country_Policy::status();
            WP_CLI::print_value(
                array(
                    'waf_enabled'            => (bool) YSEC_Utils::option( 'waf_enabled', 1 ),
                    'firewall_profile'       => (string) YSEC_Utils::option( 'firewall_profile', 'minimal' ),
                    'allow_entries'          => self::line_count( (string) ( $policy['allowlist'] ?? '' ) ),
                    'permanent_block_entries'=> self::line_count( (string) ( $policy['blocklist'] ?? '' ) ),
                    'path_deny_entries'      => self::line_count( (string) ( $policy['path_blocklist'] ?? '' ) ),
                    'conditional_deny_rules' => count( YSEC_Conditional_Rules::all() ),
                    'country_policy_enabled' => ! empty( $country['enabled'] ),
                    'country_deny_entries'   => (int) ( $country['count'] ?? 0 ),
                    'country_scope'          => (string) ( $country['scope'] ?? 'public' ),
                ),
                array( 'format'=>'json' )
            );
        } );
        WP_CLI::add_command( 'ysec private-entry-status', static function() {
            WP_CLI::print_value( YSEC_Private_Login::status(), array( 'format'=>'json' ) );
        } );
        WP_CLI::add_command( 'ysec emergency-unblock', static function( array $args, array $assoc_args ) {
            if ( empty( $assoc_args['all'] ) ) {
                WP_CLI::error( 'Use --all to confirm clearing every active temporary source block.' );
            }
            $changed = YSEC_Firewall::unblock_all();
            WP_CLI::success( sprintf( 'Cleared %d active YSec temporary source blocks.', $changed ) );
        } );
        WP_CLI::add_command( 'ysec allow-source', static function( array $args ) {
            $entry = isset( $args[0] ) ? trim( (string) $args[0] ) : '';
            if ( '' === $entry || ! YSEC_Firewall_Policy::add_allowlist_entry( $entry ) ) {
                WP_CLI::error( 'Provide one valid IPv4, IPv6 or CIDR entry.' );
            }
            YSEC_Managed_MU::refresh_policy();
            WP_CLI::success( 'Trusted source added to the durable YSec allowlist and compiled MU policy refreshed.' );
        } );
        WP_CLI::add_command( 'ysec emergency-remove-mu', static function() {
            $result = YSEC_Managed_MU::remove();
            if ( empty( $result['ok'] ) ) WP_CLI::error( (string) ( $result['message'] ?? 'Managed MU runtime removal failed.' ) );
            WP_CLI::success( 'Managed YSec MU runtime removed. Normal plugin runtime remains available.' );
        } );
        WP_CLI::add_command( 'ysec private-entry-disable', static function() {
            $settings = YSEC_Utils::settings();
            $settings['private_login_enabled'] = 0;
            $settings['private_login_mode'] = 'off';
            update_option( 'ysec_settings', $settings, false );
            WP_CLI::success( 'Yablonsky Security private administration entry disabled. Standard WordPress login routing is restored.' );
        } );
        WP_CLI::add_command( 'ysec integrity-scan', static function() { WP_CLI::print_value( YSEC_Integrity::scan(), array( 'format'=>'json' ) ); } );
        WP_CLI::add_command( 'ysec malware-scan', static function() { WP_CLI::print_value( YSEC_Malware::scan(), array( 'format'=>'json' ) ); } );
    }

    public static function safe_event_row( array $row ): array {
        unset( $row['source_enc'] );
        if ( isset( $row['source_hash'] ) && is_string( $row['source_hash'] ) ) $row['source_hash'] = substr( $row['source_hash'], 0, 12 );
        return $row;
    }

    public static function safe_block_row( array $row ): array {
        unset( $row['source_enc'] );
        if ( isset( $row['source_hash'] ) && is_string( $row['source_hash'] ) ) $row['source_hash'] = substr( $row['source_hash'], 0, 12 );
        return $row;
    }

    private static function line_count( string $text ): int {
        $rows = array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $text ) ?: array() ) );
        return count( array_unique( $rows ) );
    }
}
