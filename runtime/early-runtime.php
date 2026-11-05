<?php
/**
 * Yablonsky Security early runtime.
 *
 * Loaded only through the managed MU bridge. Keep this file independent from the
 * normal plugin bootstrap: no database access, remote calls, AI, UI or WordPress
 * option reads are allowed on the inline path.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

if ( ! function_exists( 'ysec_early_runtime_boot' ) ) {
    function ysec_early_runtime_boot( array $context ) {
        $GLOBALS['ysec_early_security_verdict_v1'] = array( 'verdict'=>'UNKNOWN', 'phase'=>10, 'authority'=>'ysec' );
        if ( defined( 'YSEC_EMERGENCY_BYPASS' ) && true === YSEC_EMERGENCY_BYPASS ) return;
        if ( 'cli' === PHP_SAPI ) return;
        if ( 1 !== (int) ( $context['abi'] ?? 0 ) ) return;

        $policy_path = isset( $context['policy_path'] ) ? (string) $context['policy_path'] : '';
        $record = ysec_early_read_policy( $policy_path );
        if ( ! is_array( $record ) ) return;

        $payload = is_array( $record['payload'] ?? null ) ? $record['payload'] : array();
        $signature = isset( $record['signature'] ) ? (string) $record['signature'] : '';
        if ( 1 !== (int) ( $payload['abi'] ?? 0 ) || empty( $payload['enabled'] ) ) return;
        if ( ! ysec_early_verify_signature( $payload, $signature ) ) return;
        if ( empty( $payload['waf_enabled'] ) ) return;

        $method_input = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
        $method = strtoupper( (string) preg_replace( '/[^A-Z]/', '', $method_input ) );
        // Keep the encoded request target intact for traversal/query detection; normalization below bounds the value before matching.
        $uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( (string) $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Raw encoded request target is the security input being classified.
        $path = ysec_early_normalize_path( $uri );
        $query = '';
        $question = strpos( $uri, '?' );
        if ( false !== $question ) $query = strtolower( substr( $uri, $question + 1, 8192 ) );

        // Deterministic live canary. It never reaches the normal plugin when MU is active.
        if ( '/.__ysec_mu_probe__' === $path ) {
            ysec_early_deny( 'mu_runtime_probe' );
        }

        // Mirror durable human-owned source policy before the normal plugin loads. The
        // client address contract trusts proxy headers only when the direct peer itself
        // is in the compiled trusted/Cloudflare proxy boundary.
        $source_ip = ysec_early_client_ip( $payload );
        if ( '' !== $source_ip && ysec_early_ip_in_list( $source_ip, (array) ( $payload['source_allowlist'] ?? array() ) ) ) { ysec_early_publish_verdict( 'ALLOW', 'source_allowlist' ); return; }
        if ( '' !== $source_ip && ysec_early_ip_in_list( $source_ip, (array) ( $payload['source_blocklist'] ?? array() ) ) ) {
            ysec_early_deny( 'permanent_policy' );
        }

        // A deliberately narrow Layer-7 burst shield protects only authentication,
        // comment-submit and REST-write surfaces. It is active only when a persistent
        // object-cache backend is already available; there is no database/transient or
        // filesystem fallback that could amplify an origin-saturation incident.
        if ( ! empty( $payload['early_burst_guard'] ) && '' !== $source_ip && ysec_early_sensitive_surface( $path, $method ) ) {
            $threshold = max( 120, min( 2000, (int) ( $payload['early_burst_threshold'] ?? 160 ) ) );
            $window = max( 30, min( 300, (int) ( $payload['early_burst_window'] ?? 60 ) ) );
            $count = ysec_early_burst_count( $source_ip, $path, $window );
            if ( $count > $threshold ) ysec_early_deny( 'early_burst_guard', 429 );
        }

        // Human-owned manual path policy stays stronger than automatic profile exceptions.
        foreach ( (array) ( $payload['path_blocklist'] ?? array() ) as $rule ) {
            $rule = (string) $rule;
            if ( '' === $rule || '/' !== substr( $rule, 0, 1 ) ) continue;
            if ( '*' === substr( $rule, -1 ) ) {
                $prefix = substr( $rule, 0, -1 );
                if ( '' !== $prefix && 0 === strpos( $path, strtolower( $prefix ) ) ) {
                    ysec_early_deny( 'custom_policy' );
                }
            } elseif ( hash_equals( strtolower( $rule ), $path ) ) {
                ysec_early_deny( 'custom_policy' );
            }
        }

        // Exact administrator exceptions bypass only the compiled automatic profile.
        $request_key = $method . ' ' . $path;
        foreach ( (array) ( $payload['request_allowlist'] ?? array() ) as $exception ) {
            if ( hash_equals( (string) $exception, $request_key ) ) return;
        }

        $level = max( 0, min( 4, (int) ( $payload['profile_level'] ?? 0 ) ) );
        if ( $level < 1 ) { ysec_early_publish_verdict( 'ALLOW', 'profile_observe' ); return; }

        $tier1 = array(
            'credentials_secrets' => '#(?:^|/)(?:\.env(?:\.|/|$)|\.git(?:/|$)|wp-config(?:\.|-|$)|composer\.(?:json|lock)|auth\.json|\.npmrc|\.pypirc|\.aws(?:/|$)|\.azure(?:/|$)|\.ssh(?:/|$)|id_rsa(?:\.|$)|server\.key$|private\.key$)#i',
            'path_traversal'      => '#(?:\.\./|\.\.\\|%2e%2e|%252e%252e|/proc/self/environ|/etc/passwd|@fs/)#i',
        );
        foreach ( $tier1 as $family => $pattern ) {
            if ( preg_match( $pattern, $path ) ) ysec_early_deny( $family );
        }

        if ( $level >= 2 ) {
            $tier2 = array(
                'framework_probe' => '#/(?:actuator(?:/|$)|jenkins(?:/|$)|solr(?:/|$)|swagger(?:/|$)|openapi(?:\.|/|$)|vendor/phpunit(?:/|$)|debug(?:/|$)|server-status(?:/|$))#i',
                'database_admin'  => '#/(?:phpmyadmin|pma|adminer)(?:\.|/|$)#i',
                'backup_dump'     => '#/(?:backup|database|dump|mysql|wordpress)[^/]*\.(?:sql|sql\.gz|sqlite|sqlite3|bak)(?:$|[/?])#i',
            );
            foreach ( $tier2 as $family => $pattern ) {
                if ( preg_match( $pattern, $path ) ) ysec_early_deny( $family );
            }
        }

        if ( $level >= 3 ) {
            // Intentionally excludes robots.txt, security.txt, sitemaps and crawler endpoints.
            if ( preg_match( '#/(?:console(?:/|$)|webui(?:/|$)|manager(?:/|$)|manage(?:/|$)|graphql/console|cgi-bin/|\.git-credentials$|\.gitconfig$|docker-compose\.ya?ml$|package-lock\.json$|yarn\.lock$)#i', $path ) ) {
                ysec_early_deny( 'reconnaissance' );
            }
        }

        if ( $level >= 4 ) {
            if ( in_array( $method, array( 'TRACE', 'TRACK', 'CONNECT', 'DEBUG' ), true ) ) {
                ysec_early_deny( 'abusive_method' );
            }
            if ( preg_match( '/(?:union(?:\+|%20|\s)+select|sleep\s*\(|benchmark\s*\(|base64_decode\s*\(|(?:\$\{|%24%7b)jndi:|<script|%3cscript|\.\.\/)/i', $query ) ) {
                ysec_early_deny( 'exploit_query' );
            }
            $cookie_names = is_array( $_COOKIE ?? null ) ? strtolower( implode( ';', array_keys( $_COOKIE ) ) ) : '';
            if ( '' !== $cookie_names && preg_match( '/(?:wp-config|passwd|\.env|jndi|phpunit|base64)/i', $cookie_names ) ) {
                ysec_early_deny( 'suspicious_cookie_name' );
            }
        }
        // There is deliberately no User-Agent-only deny here. Claimed Google/AI crawler
        // identity grants no security bypass, but crawler identity alone is never punished.
        ysec_early_publish_verdict( 'ALLOW', 'request_safety' );
    }


    function ysec_early_publish_verdict( $verdict, $family ) {
        $GLOBALS['ysec_early_security_verdict_v1'] = array(
            'verdict'   => strtoupper( preg_replace( '/[^A-Z_]/', '', (string) $verdict ) ),
            'family'    => preg_replace( '/[^a-z0-9_-]/', '', strtolower( (string) $family ) ),
            'phase'     => 10,
            'authority' => 'ysec',
        );
        if ( function_exists( 'do_action' ) ) do_action( 'ysec_early_security_verdict_v1', $GLOBALS['ysec_early_security_verdict_v1'] );
    }

    function ysec_early_read_policy( $path ) {
        if ( ! is_string( $path ) || '' === $path || ! is_readable( $path ) ) return null;
        $raw = @file_get_contents( $path );
        if ( ! is_string( $raw ) || '' === $raw ) return null;
        $marker = "<?php exit; ?>\n";
        if ( 0 !== strpos( $raw, $marker ) ) return null;
        $decoded = json_decode( substr( $raw, strlen( $marker ) ), true );
        return is_array( $decoded ) ? $decoded : null;
    }

    function ysec_early_signature_key() {
        $parts = array();
        foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY' ) as $constant ) {
            if ( defined( $constant ) ) $parts[] = (string) constant( $constant );
        }
        if ( ! $parts && defined( 'ABSPATH' ) ) $parts[] = (string) ABSPATH;
        return hash( 'sha256', implode( '|', $parts ) . '|ysec-managed-mu-runtime-v1' );
    }

    function ysec_early_verify_signature( array $payload, $signature ) {
        if ( ! is_string( $signature ) || ! preg_match( '/^[a-f0-9]{64}$/', $signature ) ) return false;
        $json = json_encode( $payload, JSON_UNESCAPED_SLASHES );
        if ( ! is_string( $json ) ) return false;
        $expected = hash_hmac( 'sha256', $json, ysec_early_signature_key() );
        return hash_equals( $expected, $signature );
    }

    function ysec_early_normalize_path( $uri ) {
        $path = explode( '?', (string) $uri, 2 )[0];
        $decoded = rawurldecode( $path );
        $decoded = preg_replace( '#/+#', '/', $decoded );
        if ( ! is_string( $decoded ) || '' === $decoded ) return '/';
        return strtolower( substr( $decoded, 0, 2048 ) );
    }

    function ysec_early_client_ip( array $payload ) {
        $remote_raw = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) ) : '';
        $remote = filter_var( $remote_raw, FILTER_VALIDATE_IP ) ? $remote_raw : '';
        if ( '' === $remote ) return '';
        $proxy = is_array( $payload['proxy_contract'] ?? null ) ? $payload['proxy_contract'] : array();
        $cloudflare = (array) ( $proxy['cloudflare'] ?? array() );
        if ( ysec_early_ip_in_list( $remote, $cloudflare ) ) {
            $cf_raw = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '';
            if ( filter_var( $cf_raw, FILTER_VALIDATE_IP ) ) return $cf_raw;
        }
        $trusted = (array) ( $proxy['trusted'] ?? array() );
        if ( ! ysec_early_ip_in_list( $remote, $trusted ) ) return $remote;
        $xff_raw = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '';
        if ( '' === $xff_raw ) return $remote;
        $chain = array_filter( array_map( 'trim', explode( ',', $xff_raw ) ) );
        $chain[] = $remote;
        for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
            $candidate = filter_var( (string) $chain[ $i ], FILTER_VALIDATE_IP ) ? (string) $chain[ $i ] : '';
            if ( '' !== $candidate && ! ysec_early_ip_in_list( $candidate, $trusted ) ) return $candidate;
        }
        return $remote;
    }

    function ysec_early_ip_in_list( $ip, array $list ) {
        if ( ! is_string( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;
        foreach ( $list as $entry ) {
            $entry = trim( (string) $entry );
            if ( '' === $entry ) continue;
            if ( hash_equals( $entry, $ip ) ) return true;
            if ( false === strpos( $entry, '/' ) ) continue;
            list( $subnet, $bits ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
            $ip_bin = @inet_pton( $ip );
            $subnet_bin = @inet_pton( $subnet );
            if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) || ! ctype_digit( (string) $bits ) ) continue;
            $bits = (int) $bits;
            $max = strlen( $ip_bin ) * 8;
            if ( $bits < 0 || $bits > $max ) continue;
            $bytes = intdiv( $bits, 8 );
            $remainder = $bits % 8;
            if ( $bytes && substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) continue;
            if ( $remainder ) {
                $mask = ( 0xFF << ( 8 - $remainder ) ) & 0xFF;
                if ( ( ord( $ip_bin[ $bytes ] ) & $mask ) !== ( ord( $subnet_bin[ $bytes ] ) & $mask ) ) continue;
            }
            return true;
        }
        return false;
    }

    function ysec_early_sensitive_surface( $path, $method ) {
        $path = strtolower( (string) $path );
        $method = strtoupper( (string) $method );
        if ( '/wp-login.php' === $path || '/xmlrpc.php' === $path ) return true;
        if ( '/wp-comments-post.php' === $path && 'POST' === $method ) return true;
        if ( 0 === strpos( $path, '/wp-json/' ) && ! in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true ) ) return true;
        return false;
    }

    function ysec_early_burst_count( $source_ip, $path, $window ) {
        if ( ! function_exists( 'wp_using_ext_object_cache' ) || ! wp_using_ext_object_cache() ) return 0;
        if ( ! function_exists( 'wp_cache_get' ) || ! function_exists( 'wp_cache_add' ) || ! function_exists( 'wp_cache_incr' ) ) return 0;
        $surface = '/wp-login.php' === $path ? 'login' : ( '/xmlrpc.php' === $path ? 'xmlrpc' : ( '/wp-comments-post.php' === $path ? 'comment' : 'rest_write' ) );
        $bucket = (int) floor( time() / max( 30, (int) $window ) );
        $source = hash_hmac( 'sha256', 'burst|' . (string) $source_ip, ysec_early_signature_key() );
        $key = 'burst_' . hash( 'sha256', $source . '|' . $surface . '|' . $bucket );
        $group = 'ysec_early';
        if ( false === wp_cache_get( $key, $group ) ) wp_cache_add( $key, 0, $group, (int) $window + 15 );
        $count = wp_cache_incr( $key, 1, $group );
        return false === $count ? 1 : (int) $count;
    }

    function ysec_early_deny( $family, $status = 403 ) {
        $family = preg_replace( '/[^a-z0-9_-]/', '', strtolower( (string) $family ) );
        $status = 429 === (int) $status ? 429 : 403;
        if ( ! headers_sent() ) {
            http_response_code( $status );
            header( 'X-Yablonsky-Security-Early: 1' );
            header( 'X-Yablonsky-Security-Family: ' . $family );
            // A signed proof is returned only for the dedicated synthetic test path.
            // Normal denials reveal no proof material and do not perform HMAC work.
            // Only the synthetic proof route needs these values; never modify the
            // raw request target used by the actual early firewall classifier.
            $proof_uri = isset( $_SERVER['REQUEST_URI'] )
                ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) )
                : '/';
            $proof_path = ysec_early_normalize_path( $proof_uri );
            $proof_token = isset( $_SERVER['HTTP_X_YSEC_PROOF_TOKEN'] )
                ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_X_YSEC_PROOF_TOKEN'] ) )
                : '';
            if ( ( '/.__ysec_mu_probe__' === $proof_path || false !== strpos( $proof_path, '__ysec-profile-proof__' ) )
                && 1 === preg_match( '/^[A-Za-z0-9]{32}$/D', $proof_token ) ) {
                $secret_parts = array();
                foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY' ) as $key_name ) {
                    if ( defined( $key_name ) ) $secret_parts[] = (string) constant( $key_name );
                }
                if ( $secret_parts ) {
                    $secret_key = hash( 'sha256', implode( '|', $secret_parts ) . '|ysec-managed-mu-runtime-v1' );
                    header( 'X-Yablonsky-Security-Signature: ' . hash_hmac( 'sha256', $proof_token . '|' . $family, $secret_key ) );
                }
            }
            header( 'Cache-Control: no-store, max-age=0' );
            if ( 429 === $status ) header( 'Retry-After: 60' );
            header( 'Content-Type: text/plain; charset=UTF-8' );
        }
        echo 429 === $status ? 'Request rate limited.' : 'Request denied.'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fixed literal early-response body.
        exit;
    }
}
