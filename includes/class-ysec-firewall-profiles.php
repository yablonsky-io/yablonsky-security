<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Clean-room request policy profiles inspired by the familiar 5G/6G/7G/8G naming
 * used in the WordPress security ecosystem. No third-party rules are copied.
 */
final class YSEC_Firewall_Profiles {
    public static function profiles(): array {
        return array(
            'minimal' => array( 'label' => 'Minimal', 'level' => 0, 'description' => __( 'Only the core high-confidence Yablonsky classifier and active source blocks.', 'yablonsky-security' ) ),
            '5g'      => array( 'label' => '5G-class', 'level' => 1, 'description' => __( 'Immediate deny for high-confidence secret, traversal and sensitive-file probes.', 'yablonsky-security' ) ),
            '6g'      => array( 'label' => '6G-class', 'level' => 2, 'description' => __( 'Adds framework, database-admin, backup/dump and development-surface probes.', 'yablonsky-security' ) ),
            '7g'      => array( 'label' => '7G-class', 'level' => 3, 'description' => __( 'Adds broader reconnaissance and exposed-management surface protection.', 'yablonsky-security' ) ),
            '8g'      => array( 'label' => '8G-class', 'level' => 4, 'description' => __( 'Adds abusive HTTP methods, scanner user agents and exploit-like query/cookie signals.', 'yablonsky-security' ) ),
        );
    }

    public static function current(): string {
        $profile = sanitize_key( (string) YSEC_Utils::option( 'firewall_profile', 'minimal' ) );
        return isset( self::profiles()[ $profile ] ) ? $profile : 'minimal';
    }

    public static function evaluate(): array {
        $profile = self::current();
        $uri = isset( $_SERVER['REQUEST_URI'] ) ? YSEC_Utils::log_string( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 4096 ) : '/';
        $query = YSEC_Utils::redacted_query();
        $ua = YSEC_Utils::user_agent();
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        $cookie_names = array_keys( is_array( $_COOKIE ?? null ) ? $_COOKIE : array() );
        return self::evaluate_values( $profile, $uri, $query, $ua, $method, $cookie_names );
    }

    public static function evaluate_values( string $profile, string $path, string $query = '', string $ua = '', string $method = 'GET', array $cookie_names = array() ): array {
        $profile = sanitize_key( $profile );
        $level = (int) ( self::profiles()[ $profile ]['level'] ?? 0 );
        if ( $level < 1 ) return array();
        $path = strtolower( YSEC_Utils::normalize_path( $path ) );
        $query = strtolower( $query );
        $ua = strtolower( $ua );
        $method = strtoupper( sanitize_key( $method ) );
        $cookie_name_string = strtolower( implode( ';', array_map( 'sanitize_key', $cookie_names ) ) );

        $groups = array(
            1 => array(
                'credentials_secrets' => array(
                    '#(?:^|/)(?:\.env(?:\.|$)|\.git(?:/|$)|wp-config(?:\.|-|$)|composer\.(?:json|lock)|auth\.json|\.npmrc|\.pypirc|\.aws(?:/|$)|\.azure(?:/|$)|\.ssh(?:/|$)|id_rsa(?:\.|$)|server\.key$|private\.key$)#i',
                ),
                'path_traversal' => array(
                    '#(?:\.\./|\.\.\\|%2e%2e|%252e%252e|/proc/self/environ|/etc/passwd|@fs/)#i',
                ),
            ),
            2 => array(
                'framework_probe' => array(
                    '#/(?:actuator(?:/|$)|jenkins(?:/|$)|solr(?:/|$)|swagger(?:/|$)|openapi(?:\.|/|$)|vendor/phpunit(?:/|$)|debug(?:/|$)|server-status(?:/|$))#i',
                ),
                'database_admin' => array(
                    '#/(?:phpmyadmin|pma|adminer)(?:\.|/|$)#i',
                ),
                'backup_dump' => array(
                    '#/(?:backup|database|dump|mysql|wordpress)[^/]*\.(?:sql|sql\.gz|sqlite|sqlite3|bak)(?:$|[/?])#i',
                ),
            ),
            3 => array(
                'reconnaissance' => array(
                    '#/(?:console(?:/|$)|webui(?:/|$)|manager(?:/|$)|manage(?:/|$)|graphql/console|cgi-bin/|\.git-credentials$|\.gitconfig$|docker-compose\.ya?ml$|package-lock\.json$|yarn\.lock$)#i',
                ),
            ),
        );

        for ( $tier = 1; $tier <= min( 3, $level ); $tier++ ) {
            foreach ( $groups[ $tier ] as $family => $patterns ) {
                foreach ( $patterns as $pattern ) {
                    if ( preg_match( $pattern, $path ) ) {
                        return self::signal( $family, $tier >= 3 ? 'high' : 'critical', $profile, 'path' );
                    }
                }
            }
        }

        if ( $level >= 4 ) {
            if ( in_array( $method, array( 'TRACE', 'TRACK', 'CONNECT', 'DEBUG' ), true ) ) return self::signal( 'abusive_method', 'critical', $profile, 'method' );
            if ( preg_match( '/(?:sqlmap|nikto|nuclei|masscan|zgrab|gobuster|dirbuster|wpscan|acunetix|nessus|openvas|whatweb|feroxbuster)/i', $ua ) ) return self::signal( 'scanner_user_agent', 'high', $profile, 'user_agent' );
            if ( preg_match( '/(?:union(?:\+|%20|\s)+select|sleep\s*\(|benchmark\s*\(|base64_decode\s*\(|(?:\$\{|%24%7b)jndi:|<script|%3cscript|\.\.\/)/i', $query ) ) return self::signal( 'exploit_query', 'critical', $profile, 'query' );
            if ( preg_match( '/(?:wp-config|passwd|\.env|jndi|phpunit|base64)/i', $cookie_name_string ) ) return self::signal( 'suspicious_cookie_name', 'high', $profile, 'cookie_name' );
        }
        return array();
    }

    private static function signal( string $family, string $severity, string $profile, string $surface ): array {
        return array(
            'severity' => $severity,
            'confidence' => 'high',
            'state' => 'blocked',
            'family' => sanitize_key( $family ),
            'rule' => 'profile_' . sanitize_key( $profile ),
            'details' => array( 'profile' => $profile, 'surface' => $surface, 'first_hit' => true ),
        );
    }

    public static function observe_adaptive_recon( string $ip, array $signals ): void {
        if ( '' === $ip || empty( $signals ) || ! YSEC_Utils::option( 'adaptive_404_shield', 1 ) ) return;
        $source = YSEC_Utils::source_identity( $ip );
        $key = 'ysec_adaptive_' . substr( $source, 0, 32 );
        $bucket = get_transient( $key );
        if ( ! is_array( $bucket ) ) $bucket = array( 'started' => time(), 'paths' => array(), 'families' => array() );
        $window = max( 1, min( 60, absint( YSEC_Utils::option( 'adaptive_recon_window', 10 ) ) ) );
        if ( time() - (int) ( $bucket['started'] ?? 0 ) > $window * MINUTE_IN_SECONDS ) $bucket = array( 'started' => time(), 'paths' => array(), 'families' => array() );
        $path = isset( $_SERVER['REQUEST_URI'] ) ? YSEC_Utils::normalize_path( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) ) : '/';
        $bucket['paths'][ substr( hash( 'sha256', $path ), 0, 20 ) ] = 1;
        foreach ( $signals as $signal ) $bucket['families'][ sanitize_key( (string) ( $signal['family'] ?? 'reconnaissance' ) ) ] = 1;
        set_transient( $key, $bucket, $window * MINUTE_IN_SECONDS );
        $threshold = max( 5, min( 200, absint( YSEC_Utils::option( 'adaptive_recon_threshold', 15 ) ) ) );
        if ( count( $bucket['paths'] ) >= $threshold && YSEC_Utils::option( 'auto_block', 0 ) ) {
            $activated = YSEC_Adaptive_Response::activate_scoped_containment(
                $ip,
                'adaptive_reconnaissance',
                array_keys( $bucket['families'] ),
                count( $bucket['paths'] )
            );
            if ( $activated ) {
                YSEC_Events::log( 'response_adaptive_recon_contained', array( 'severity'=>'high', 'confidence'=>'high', 'state'=>'campaign_contained', 'family'=>'reconnaissance', 'details'=>array( 'distinct_paths'=>count($bucket['paths']), 'families'=>array_keys($bucket['families']), 'window_minutes'=>$window, 'public_discovery_preserved'=>(bool)YSEC_Utils::option('preserve_public_discovery',1) ) ) );
            }
        }
    }

    public static function generate_fast_path_rules(): array {
        $profile = self::current();
        $comment = '# Generated by Yablonsky Security ' . YSEC_VERSION . ' — profile ' . $profile . '. Review before deployment.';
        $nginx = $comment . "
# Verification marker: keep this with the rules so YSec can prove the include is active.
location = /.__ysec_fastpath_probe__ { add_header X-Yablonsky-Security-Fast-Path \"1\" always; return 403; }
# Deny high-confidence secret/config and source-control metadata before WordPress/PHP.
location ~* (^|/)(\\.env([./]|$)|\\.git/|\\.svn/|\\.hg/|wp-config[^/]*|\\.aws/credentials|\\.azure/credentials) { return 403; }
# Deny common database dump/backup artifacts and public debug/diagnostic scripts.
location ~* (^|/)(backup|database|dump)[^/]*\\.(sql|sqlite|sqlite3)(\\.(gz|zip|bak))?$ { return 403; }
location = /wp-content/debug.log { return 403; }
location ~* (^|/)(phpinfo|info)\\.php$ { return 403; }
location ~* /(proc/self/environ|etc/passwd) { return 403; }
";
        $apache = $comment . "
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule ^\\.__ysec_fastpath_probe__$ - [F,L,E=YSEC_FASTPATH:1]
RewriteCond %{REQUEST_URI} (^|/)(\\.env([./]|$)|\\.git/|\\.svn/|\\.hg/|wp-config[^/]*|\\.aws/credentials|\\.azure/credentials) [NC,OR]
RewriteCond %{REQUEST_URI} (^|/)(backup|database|dump)[^/]*\\.(sql|sqlite|sqlite3)(\\.(gz|zip|bak))?$ [NC,OR]
RewriteCond %{REQUEST_URI} ^/wp-content/debug\\.log$ [NC,OR]
RewriteCond %{REQUEST_URI} (^|/)(phpinfo|info)\\.php$ [NC,OR]
RewriteCond %{REQUEST_URI} /(proc/self/environ|etc/passwd) [NC]
RewriteRule ^ - [F,L]
</IfModule>
<IfModule mod_headers.c>
Header always set X-Yablonsky-Security-Fast-Path \"1\" env=YSEC_FASTPATH
</IfModule>
";
        return array( 'nginx'=>$nginx, 'apache'=>$apache );
    }
}
