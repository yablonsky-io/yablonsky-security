<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Bounded deny-only firewall rules. No rule created here can create an allow/bypass path. */
final class YSEC_Conditional_Rules {
    private const OPTION = 'ysec_conditional_rules_v1';
    private const MAX_RULES = 50;

    public static function all(): array {
        $rules = get_option( self::OPTION, array() );
        return is_array( $rules ) ? array_values( array_filter( $rules, 'is_array' ) ) : array();
    }

    public static function add( array $input ) {
        $rule = self::sanitize_rule( $input );
        if ( is_wp_error( $rule ) ) return $rule;
        $rules = self::all();
        if ( count( $rules ) >= self::MAX_RULES ) return new WP_Error( 'ysec_rule_limit', __( 'Conditional firewall rule limit reached.', 'yablonsky-security' ) );
        $rule['id'] = wp_generate_uuid4();
        $rule['created_at'] = gmdate( 'c' );
        $rule['actor'] = get_current_user_id();
        $rules[] = $rule;
        update_option( self::OPTION, $rules, false );
        YSEC_Events::log( 'conditional_rule_created', array( 'severity'=>'info','family'=>'configuration','details'=>array( 'id'=>$rule['id'], 'label'=>$rule['label'] ) ) );
        return $rule;
    }

    public static function toggle( string $id, bool $enabled ): bool {
        $rules = self::all();
        $changed = false;
        foreach ( $rules as &$rule ) {
            if ( $id !== (string) ( $rule['id'] ?? '' ) ) continue;
            $rule['enabled'] = $enabled ? 1 : 0;
            $rule['updated_at'] = gmdate( 'c' );
            $changed = true;
            break;
        }
        unset( $rule );
        if ( $changed ) {
            update_option( self::OPTION, $rules, false );
            YSEC_Events::log( 'conditional_rule_toggled', array( 'severity'=>'info','family'=>'configuration','details'=>array( 'id'=>$id,'enabled'=>$enabled ) ) );
        }
        return $changed;
    }

    public static function delete( string $id ): bool {
        $rules = self::all();
        $next = array_values( array_filter( $rules, static fn( $rule ) => $id !== (string) ( $rule['id'] ?? '' ) ) );
        if ( count( $next ) === count( $rules ) ) return false;
        update_option( self::OPTION, $next, false );
        YSEC_Events::log( 'conditional_rule_deleted', array( 'severity'=>'info','family'=>'configuration','details'=>array( 'id'=>$id ) ) );
        return true;
    }

    public static function match_current_request( string $uri, string $ip = '' ): array {
        $path = YSEC_Utils::normalize_path( $uri );
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        $logged_in = is_user_logged_in();
        foreach ( self::all() as $rule ) {
            if ( empty( $rule['enabled'] ) ) continue;
            $rule_method = strtoupper( (string) ( $rule['method'] ?? 'ANY' ) );
            if ( 'ANY' !== $rule_method && $rule_method !== $method ) continue;
            $auth = sanitize_key( (string) ( $rule['auth'] ?? 'any' ) );
            if ( 'anonymous' === $auth && $logged_in ) continue;
            if ( 'authenticated' === $auth && ! $logged_in ) continue;
            $network = trim( (string) ( $rule['source_network'] ?? '' ) );
            if ( '' !== $network && ! self::ip_matches( $ip, $network ) ) continue;
            $rule_path = (string) ( $rule['path'] ?? '' );
            $mode = (string) ( $rule['path_mode'] ?? 'exact' );
            if ( 'prefix' === $mode ? str_starts_with( $path, $rule_path ) : hash_equals( $rule_path, $path ) ) return $rule;
        }
        return array();
    }

    public static function exportable(): array {
        $out = array();
        foreach ( self::all() as $rule ) {
            unset( $rule['actor'] );
            $out[] = $rule;
        }
        return $out;
    }

    public static function replace_imported( array $rules ) {
        if ( count( $rules ) > self::MAX_RULES ) return new WP_Error( 'ysec_rule_limit', __( 'Imported conditional firewall policy contains too many rules.', 'yablonsky-security' ) );
        $out = array();
        foreach ( $rules as $row ) {
            if ( ! is_array( $row ) ) continue;
            $clean = self::sanitize_rule( $row );
            if ( is_wp_error( $clean ) ) return $clean;
            $clean['id'] = sanitize_text_field( (string) ( $row['id'] ?? wp_generate_uuid4() ) );
            $clean['created_at'] = sanitize_text_field( (string) ( $row['created_at'] ?? gmdate( 'c' ) ) );
            $out[] = $clean;
        }
        update_option( self::OPTION, $out, false );
        return count( $out );
    }

    private static function sanitize_rule( array $input ) {
        $label = YSEC_Utils::log_string( sanitize_text_field( (string) ( $input['label'] ?? '' ) ), 100 );
        $method = strtoupper( sanitize_text_field( (string) ( $input['method'] ?? 'ANY' ) ) );
        $path_mode = sanitize_key( (string) ( $input['path_mode'] ?? 'exact' ) );
        $path = sanitize_text_field( (string) ( $input['path'] ?? '' ) );
        $auth = sanitize_key( (string) ( $input['auth'] ?? 'any' ) );
        $network = trim( sanitize_text_field( (string) ( $input['source_network'] ?? '' ) ) );
        if ( '' === $label ) $label = __( 'Custom deny rule', 'yablonsky-security' );
        if ( ! in_array( $method, array( 'ANY','GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS' ), true ) ) return new WP_Error( 'ysec_rule_method', __( 'Conditional rule method is invalid.', 'yablonsky-security' ) );
        if ( ! in_array( $path_mode, array( 'exact','prefix' ), true ) ) return new WP_Error( 'ysec_rule_mode', __( 'Conditional rule path mode is invalid.', 'yablonsky-security' ) );
        if ( '' === $path || '/' !== $path[0] || strlen( $path ) > 256 || preg_match( '/[\x00-\x1F\x7F]/', $path ) ) return new WP_Error( 'ysec_rule_path', __( 'Conditional rule path must be an absolute request path.', 'yablonsky-security' ) );
        if ( ! in_array( $auth, array( 'any','anonymous','authenticated' ), true ) ) $auth = 'any';
        if ( '' !== $network && ! self::valid_network( $network ) ) return new WP_Error( 'ysec_rule_network', __( 'Conditional rule source must be an IP address or CIDR network.', 'yablonsky-security' ) );
        return array( 'label'=>$label, 'enabled'=>empty( $input['enabled'] ) ? 0 : 1, 'method'=>$method, 'path_mode'=>$path_mode, 'path'=>$path, 'auth'=>$auth, 'source_network'=>$network );
    }

    private static function valid_network( string $entry ): bool {
        if ( filter_var( $entry, FILTER_VALIDATE_IP ) ) return true;
        if ( false === strpos( $entry, '/' ) ) return false;
        list( $ip, $bits ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! ctype_digit( $bits ) ) return false;
        $max = false !== strpos( $ip, ':' ) ? 128 : 32;
        return (int)$bits >= 0 && (int)$bits <= $max;
    }

    private static function ip_matches( string $ip, string $network ): bool {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;
        if ( $ip === $network ) return true;
        if ( false === strpos( $network, '/' ) ) return false;
        list( $subnet, $bits ) = array_pad( explode( '/', $network, 2 ), 2, '' );
        $a = @inet_pton( $ip ); $b = @inet_pton( $subnet );
        if ( false === $a || false === $b || strlen( $a ) !== strlen( $b ) ) return false;
        $bits = (int)$bits; $bytes = intdiv( $bits, 8 ); $rem = $bits % 8;
        if ( $bytes && substr( $a, 0, $bytes ) !== substr( $b, 0, $bytes ) ) return false;
        if ( $rem ) { $mask = ( 0xFF << ( 8 - $rem ) ) & 0xFF; if ( ( ord( $a[$bytes] ) & $mask ) !== ( ord( $b[$bytes] ) & $mask ) ) return false; }
        return true;
    }
}
