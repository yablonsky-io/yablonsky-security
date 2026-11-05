<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class YSEC_Policy_Portability {
    private const SNAPSHOT_OPTION = 'ysec_policy_import_rollback_v1';

    public static function package(): array {
        $settings = YSEC_Utils::settings();
        foreach ( self::secret_keys() as $key ) unset( $settings[$key] );
        return array(
            'schema'       => 'yablonsky.security.policy.v2',
            'generated_at' => gmdate( 'c' ),
            'plugin'       => 'Yablonsky Security',
            'version'      => YSEC_VERSION,
            'settings'     => $settings,
            'firewall'     => YSEC_Firewall_Policy::exportable(),
            'conditional_rules' => class_exists( 'YSEC_Conditional_Rules' ) ? YSEC_Conditional_Rules::exportable() : array(),
            'security_headers' => class_exists( 'YSEC_Security_Headers' ) ? YSEC_Security_Headers::policy() : array(),
        );
    }

    public static function preview_json( string $json ) {
        $data = json_decode( $json, true );
        if ( ! is_array( $data ) || ! in_array( (string) ( $data['schema'] ?? '' ), array( 'yablonsky.security.policy.v1','yablonsky.security.policy.v2' ), true ) ) {
            return new WP_Error( 'ysec_policy_schema', __( 'Policy import was rejected because the schema is not supported.', 'yablonsky-security' ) );
        }
        $settings = is_array( $data['settings'] ?? null ) ? $data['settings'] : array();
        $current = YSEC_Utils::settings();
        foreach ( self::secret_keys() as $key ) $settings[$key] = $current[$key] ?? '';
        $sanitized = YSEC_Utils::sanitize_settings( $settings );
        $policy_input = is_array( $data['firewall'] ?? null ) ? $data['firewall'] : array();
        $policy = YSEC_Firewall_Policy::sanitize( $policy_input );
        if ( is_wp_error( $policy ) ) return $policy;
        $rules = isset( $data['conditional_rules'] ) && is_array( $data['conditional_rules'] ) ? $data['conditional_rules'] : YSEC_Conditional_Rules::exportable();
        $current_rules = YSEC_Conditional_Rules::exportable();
        $current_headers = YSEC_Security_Headers::policy();
        $headers_input = isset( $data['security_headers'] ) && is_array( $data['security_headers'] ) ? $data['security_headers'] : $current_headers;
        $security_headers = YSEC_Security_Headers::sanitize_policy( $headers_input );
        if ( is_wp_error( $security_headers ) ) return $security_headers;
        $settings_changes = self::diff_count( $current, $sanitized );
        $firewall_changes = self::diff_count( YSEC_Firewall_Policy::settings(), $policy );
        $rules_changed = wp_json_encode( $current_rules ) !== wp_json_encode( $rules );
        $preview = array(
            'schema'=>'yablonsky.security.policy.preview.v1',
            'created_at'=>gmdate( 'c' ),
            'source_schema'=>(string) $data['schema'],
            'settings'=>$sanitized,
            'firewall'=>$policy,
            'conditional_rules'=>$rules,
            'security_headers'=>$security_headers,
            'summary'=>array(
                'settings_changes'=>$settings_changes,
                'firewall_changes'=>$firewall_changes,
                'conditional_rules'=>count( $rules ),
                'conditional_rules_changed'=>$rules_changed,
                'security_headers_changes'=>self::diff_count( $current_headers, $security_headers ),
                'secrets_preserved'=>count( self::secret_keys() ),
            ),
        );
        $preview['digest'] = hash( 'sha256', wp_json_encode( $preview, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ?: '' );
        return $preview;
    }

    public static function apply_preview( array $preview ): array {
        if ( 'yablonsky.security.policy.preview.v1' !== ( $preview['schema'] ?? '' ) || empty( $preview['digest'] ) ) {
            return array( 'ok'=>false, 'message'=>__( 'Policy preview is missing or invalid.', 'yablonsky-security' ) );
        }
        $snapshot = array(
            'created_at'=>gmdate( 'c' ),
            'settings'=>get_option( 'ysec_settings', array() ),
            'firewall'=>get_option( 'ysec_firewall_policy', array() ),
            'conditional_rules'=>YSEC_Conditional_Rules::exportable(),
            'security_headers'=>get_option( 'ysec_security_headers_policy', array() ),
        );
        update_option( self::SNAPSHOT_OPTION, $snapshot, false );
        update_option( 'ysec_settings', is_array( $preview['settings'] ?? null ) ? $preview['settings'] : array(), false );
        update_option( 'ysec_firewall_policy', is_array( $preview['firewall'] ?? null ) ? $preview['firewall'] : array(), false );
        update_option( 'ysec_security_headers_policy', is_array( $preview['security_headers'] ?? null ) ? $preview['security_headers'] : array(), false );
        $rules_result = YSEC_Conditional_Rules::replace_imported( is_array( $preview['conditional_rules'] ?? null ) ? $preview['conditional_rules'] : array() );
        if ( is_wp_error( $rules_result ) ) {
            self::restore_snapshot( $snapshot );
            return array( 'ok'=>false, 'message'=>$rules_result->get_error_message() );
        }
        YSEC_Events::log( 'security_policy_imported', array( 'severity'=>'medium', 'family'=>'configuration', 'details'=>array( 'actor'=>get_current_user_id(), 'digest'=>(string)$preview['digest'] ) ) );
        return array( 'ok'=>true, 'message'=>__( 'Verified policy preview applied. A one-step rollback snapshot was created first.', 'yablonsky-security' ) );
    }

    public static function import_json( string $json ): array {
        $preview = self::preview_json( $json );
        if ( is_wp_error( $preview ) ) return array( 'ok'=>false, 'message'=>$preview->get_error_message() );
        return self::apply_preview( $preview );
    }

    public static function has_rollback(): bool {
        $snapshot = get_option( self::SNAPSHOT_OPTION, array() );
        return is_array( $snapshot ) && ! empty( $snapshot['created_at'] );
    }

    public static function rollback(): array {
        $snapshot = get_option( self::SNAPSHOT_OPTION, array() );
        if ( ! is_array( $snapshot ) || empty( $snapshot['created_at'] ) ) return array( 'ok'=>false, 'message'=>__( 'No policy-import rollback snapshot is available.', 'yablonsky-security' ) );
        self::restore_snapshot( $snapshot );
        delete_option( self::SNAPSHOT_OPTION );
        YSEC_Events::log( 'security_policy_import_rolled_back', array( 'severity'=>'medium','family'=>'configuration','details'=>array( 'actor'=>get_current_user_id() ) ) );
        return array( 'ok'=>true, 'message'=>__( 'The previous local security policy was restored.', 'yablonsky-security' ) );
    }

    private static function restore_snapshot( array $snapshot ): void {
        update_option( 'ysec_settings', is_array( $snapshot['settings'] ?? null ) ? $snapshot['settings'] : array(), false );
        update_option( 'ysec_firewall_policy', is_array( $snapshot['firewall'] ?? null ) ? $snapshot['firewall'] : array(), false );
        update_option( 'ysec_security_headers_policy', is_array( $snapshot['security_headers'] ?? null ) ? $snapshot['security_headers'] : array(), false );
        YSEC_Conditional_Rules::replace_imported( is_array( $snapshot['conditional_rules'] ?? null ) ? $snapshot['conditional_rules'] : array() );
    }

    private static function diff_count( array $before, array $after ): int {
        $keys = array_unique( array_merge( array_keys( $before ), array_keys( $after ) ) );
        $count = 0;
        foreach ( $keys as $key ) if ( ( $before[$key] ?? null ) !== ( $after[$key] ?? null ) ) $count++;
        return $count;
    }

    private static function secret_keys(): array {
        return array( 'captcha_site_key','captcha_secret_key','trusted_proxies','ai_api_key','ai_endpoint','ai_workspace_id','ai_model_id','ai_reasoning','ai_enabled','private_login_enabled','private_login_mode','private_login_slug','private_admin_slug','alerts_email' );
    }
}
