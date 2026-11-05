<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Managed MU bridge for deterministic early security decisions. */
final class YSEC_Managed_MU {
    public const ABI = 1;
    private const LOADER = 'yablonsky-security-runtime.php';
    private const OWNER_MARKER = 'YSEC_MANAGED_MU_RUNTIME_ABI=1';

    public static function boot(): void {
        add_action( 'update_option_ysec_settings', array( __CLASS__, 'policy_option_changed' ), 20, 3 );
        add_action( 'update_option_ysec_firewall_policy', array( __CLASS__, 'policy_option_changed' ), 20, 3 );
        add_action( 'admin_init', array( __CLASS__, 'refresh_stale_policy_after_update' ), 20 );
    }

    public static function policy_option_changed( $old_value, $value, $option ): void {
        unset( $old_value, $value, $option );
        if ( self::is_installed() ) self::refresh_policy();
    }


    /** Refresh the compiled snapshot once after a plugin update while preserving ABI 1. */
    public static function refresh_stale_policy_after_update(): void {
        if ( ! current_user_can( 'manage_options' ) || ! self::is_installed() ) return;
        $record = self::read_policy();
        $payload = is_array( $record['payload'] ?? null ) ? $record['payload'] : array();
        if ( YSEC_VERSION !== (string) ( $payload['plugin_version'] ?? '' ) ) self::refresh_policy();
        $path = self::loader_path();
        $current = is_readable( $path ) ? file_get_contents( $path ) : '';
        $desired = self::loader_source();
        if ( is_string( $current ) && is_string( $desired ) && ! hash_equals( hash( 'sha256', $desired ), hash( 'sha256', $current ) ) ) {
            self::atomic_write( $path, $desired );
        }
    }

    /** Return the initialized WordPress Filesystem object when direct managed writes are available. */
    private static function filesystem() {
        if ( ! function_exists( 'WP_Filesystem' ) ) require_once ABSPATH . 'wp-admin/includes/file.php';
        global $wp_filesystem;
        if ( ! WP_Filesystem() || ! is_object( $wp_filesystem ) ) return null;
        return $wp_filesystem;
    }

    public static function mu_dir(): string {
        return defined( 'WPMU_PLUGIN_DIR' ) ? (string) WPMU_PLUGIN_DIR : trailingslashit( WP_CONTENT_DIR ) . 'mu-plugins';
    }

    public static function loader_path(): string {
        return trailingslashit( self::mu_dir() ) . self::LOADER;
    }

    public static function state_dir(): string {
        return trailingslashit( WP_CONTENT_DIR ) . 'ysec-runtime';
    }

    public static function policy_path(): string {
        return trailingslashit( self::state_dir() ) . 'policy.php';
    }

    public static function evidence_path(): string {
        return trailingslashit( self::state_dir() ) . 'early-evidence.php';
    }

    public static function is_installed(): bool {
        $path = self::loader_path();
        return is_readable( $path ) && self::owned_loader( $path );
    }

    private static function owned_loader( string $path ): bool {
        if ( ! is_readable( $path ) ) return false;
        $head = file_get_contents( $path, false, null, 0, 4096 );
        return is_string( $head ) && false !== strpos( $head, self::OWNER_MARKER );
    }

    private static function signature_key(): string {
        $parts = array();
        foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY' ) as $constant ) {
            if ( defined( $constant ) ) $parts[] = (string) constant( $constant );
        }
        if ( ! $parts ) $parts[] = (string) ABSPATH;
        return hash( 'sha256', implode( '|', $parts ) . '|ysec-managed-mu-runtime-v1' );
    }

    /** Same request-bound HMAC used by the early runtime; no secret is sent to the client. */
    public static function proof_signature( string $token, string $family ): string {
        return hash_hmac( 'sha256', $token . '|' . sanitize_key( $family ), self::signature_key() );
    }

    private static function payload(): array {
        $profiles = YSEC_Firewall_Profiles::profiles();
        $profile = YSEC_Firewall_Profiles::current();
        $policy = YSEC_Firewall_Policy::settings();
        $path_rules = array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n]+/', (string) ( $policy['path_blocklist'] ?? '' ) ) ?: array() ) ) );
        $request_allowlist = array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n]+/', (string) ( $policy['request_allowlist'] ?? '' ) ) ?: array() ) ) );
        $source_allowlist = self::network_lines( (string) ( $policy['allowlist'] ?? '' ) );
        $source_blocklist = self::network_lines( (string) ( $policy['blocklist'] ?? '' ) );
        $login_limit = max( 2, min( 50, absint( YSEC_Utils::option( 'login_limit', 8 ) ) ) );
        return array(
            'schema'                    => 'ysec-managed-mu-policy/1',
            'abi'                       => self::ABI,
            'plugin_version'            => YSEC_VERSION,
            'generated_at'              => gmdate( 'c' ),
            'enabled'                   => true,
            'waf_enabled'               => (bool) YSEC_Utils::option( 'waf_enabled', 1 ),
            'profile'                   => $profile,
            'profile_level'             => (int) ( $profiles[ $profile ]['level'] ?? 0 ),
            'preserve_public_discovery' => (bool) YSEC_Utils::option( 'preserve_public_discovery', 1 ),
            'path_blocklist'            => array_slice( $path_rules, 0, 100 ),
            'request_allowlist'         => array_slice( $request_allowlist, 0, 100 ),
            'source_allowlist'          => array_slice( $source_allowlist, 0, 100 ),
            'source_blocklist'          => array_slice( $source_blocklist, 0, 100 ),
            'proxy_contract'            => YSEC_Utils::early_proxy_contract(),
            'early_burst_guard'         => (bool) YSEC_Utils::option( 'waf_enabled', 1 ),
            'early_burst_threshold'     => max( 120, $login_limit * 20 ),
            'early_burst_window'        => 60,
            'request_contract'          => array(
                'version'           => '1.1.0',
                'security_phase'    => 10,
                'security_priority' => -1000,
                'capacity_phase'    => 20,
                'capacity_priority' => -900,
                'security_authority'=> 'ysec',
                'performance_owner' => 'yperf',
                'publication_owner' => 'yseo_or_site_policy',
            ),
            'crawler_contract'           => array(
                'security_basis'      => 'request_behavior',
                'user_agent_bypass'   => false,
                'user_agent_only_deny'=> false,
                'publication_owner'   => 'yseo_or_site_policy',
                'performance_owner'   => 'yperf',
            ),
        );
    }

    private static function network_lines( string $raw ): array {
        $out = array();
        foreach ( preg_split( '/[\r\n,]+/', $raw ) ?: array() as $entry ) {
            $entry = trim( $entry );
            if ( '' !== $entry ) $out[] = $entry;
            if ( count( $out ) >= 100 ) break;
        }
        return array_values( array_unique( $out ) );
    }

    private static function policy_record(): array {
        $payload = self::payload();
        $json = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
        return array(
            'payload'   => $payload,
            'signature' => hash_hmac( 'sha256', (string) $json, self::signature_key() ),
        );
    }

    public static function refresh_policy(): array {
        if ( ! self::is_installed() ) return array( 'ok'=>false, 'message'=>__( 'Managed MU runtime is not installed.', 'yablonsky-security' ) );
        if ( ! self::ensure_state_dir() ) return array( 'ok'=>false, 'message'=>__( 'YSec could not create or write its managed runtime state directory.', 'yablonsky-security' ) );
        $json = wp_json_encode( self::policy_record(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
        if ( ! is_string( $json ) ) return array( 'ok'=>false, 'message'=>__( 'Managed MU policy could not be encoded.', 'yablonsky-security' ) );
        $ok = self::atomic_write( self::policy_path(), "<?php exit; ?>\n" . $json . "\n" );
        if ( ! $ok ) return array( 'ok'=>false, 'message'=>__( 'Managed MU policy could not be written atomically.', 'yablonsky-security' ) );
        self::cleanup_legacy_evidence();
        $status = self::status();
        return array( 'ok'=>! empty( $status['policy_valid'] ), 'message'=>! empty( $status['policy_valid'] ) ? __( 'Managed MU policy refreshed and verified.', 'yablonsky-security' ) : __( 'Managed MU policy was written but failed read-back verification.', 'yablonsky-security' ), 'status'=>$status );
    }

    public static function install(): array {
        $filesystem = self::filesystem();
        if ( ! $filesystem ) return array( 'ok'=>false, 'message'=>__( 'WordPress Filesystem is unavailable for the Managed MU runtime.', 'yablonsky-security' ) );
        $dir = self::mu_dir();
        if ( ! $filesystem->is_dir( $dir ) && ! $filesystem->mkdir( $dir, defined( 'FS_CHMOD_DIR' ) ? FS_CHMOD_DIR : 0755 ) ) return array( 'ok'=>false, 'message'=>__( 'WordPress mu-plugins directory could not be created.', 'yablonsky-security' ) );
        if ( ! $filesystem->is_writable( $dir ) ) return array( 'ok'=>false, 'message'=>__( 'WordPress mu-plugins directory is not writable.', 'yablonsky-security' ) );
        $path = self::loader_path();
        $previous = is_file( $path ) ? file_get_contents( $path ) : null;
        if ( is_file( $path ) && ! self::owned_loader( $path ) ) return array( 'ok'=>false, 'message'=>__( 'A non-YSec file already uses the managed MU loader filename. YSec will not overwrite it.', 'yablonsky-security' ) );
        if ( ! self::atomic_write( $path, self::loader_source() ) ) return array( 'ok'=>false, 'message'=>__( 'Managed MU loader could not be installed atomically.', 'yablonsky-security' ) );
        $policy = self::refresh_policy();
        if ( empty( $policy['ok'] ) ) {
            if ( is_string( $previous ) ) self::atomic_write( $path, $previous ); else $filesystem->delete( $path, false, 'f' );
            return array( 'ok'=>false, 'message'=>(string) ( $policy['message'] ?? __( 'Managed MU policy verification failed; loader rollback completed.', 'yablonsky-security' ) ) );
        }
        YSEC_Events::log( 'managed_mu_runtime_installed', array( 'severity'=>'info', 'family'=>'configuration', 'details'=>array( 'abi'=>self::ABI, 'actor'=>get_current_user_id() ) ) );
        return array( 'ok'=>true, 'message'=>__( 'Managed MU runtime installed. Run live verification to prove early execution.', 'yablonsky-security' ), 'status'=>self::status() );
    }

    public static function remove(): array {
        $path = self::loader_path();
        if ( is_file( $path ) && ! self::owned_loader( $path ) ) return array( 'ok'=>false, 'message'=>__( 'YSec refused to remove a MU file it does not own.', 'yablonsky-security' ) );
        $filesystem = self::filesystem();
        if ( ! $filesystem ) return array( 'ok'=>false, 'message'=>__( 'WordPress Filesystem is unavailable, so YSec left the managed MU runtime untouched.', 'yablonsky-security' ) );
        if ( is_file( $path ) && ! $filesystem->delete( $path, false, 'f' ) ) return array( 'ok'=>false, 'message'=>__( 'Managed MU loader could not be removed.', 'yablonsky-security' ) );
        self::delete_state_artifacts( $filesystem );
        YSEC_Events::log( 'managed_mu_runtime_removed', array( 'severity'=>'info', 'family'=>'configuration', 'details'=>array( 'actor'=>get_current_user_id() ) ) );
        return array( 'ok'=>true, 'message'=>__( 'Managed MU runtime removed cleanly.', 'yablonsky-security' ), 'status'=>self::status() );
    }

    public static function deactivate(): void {
        $path = self::loader_path();
        $filesystem = self::filesystem();
        if ( ! $filesystem ) return;
        if ( is_file( $path ) && self::owned_loader( $path ) ) $filesystem->delete( $path, false, 'f' );
        self::delete_state_artifacts( $filesystem );
    }

    public static function verify_live(): array {
        if ( ! self::is_installed() ) return array( 'ok'=>false, 'code'=>0, 'message'=>__( 'Managed MU runtime is not installed.', 'yablonsky-security' ) );
        $token = wp_generate_password( 32, false, false );
        $response = wp_safe_remote_get( home_url( '/.__ysec_mu_probe__' ), array(
            'timeout'=>8, 'redirection'=>0, 'sslverify'=>true,
            'headers'=>array( 'User-Agent'=>'Yablonsky-Security-MU-Verify/' . YSEC_VERSION, 'X-YSEC-Proof-Token'=>$token, 'Cache-Control'=>'no-cache, no-store' ),
        ) );
        if ( is_wp_error( $response ) ) return array( 'ok'=>false, 'code'=>0, 'message'=>$response->get_error_message(), 'checked_at'=>current_time( 'mysql', true ) );
        $code = (int) wp_remote_retrieve_response_code( $response );
        $header = trim( (string) wp_remote_retrieve_header( $response, 'x-yablonsky-security-early' ) );
        $family = trim( (string) wp_remote_retrieve_header( $response, 'x-yablonsky-security-family' ) );
        $signature = (string) wp_remote_retrieve_header( $response, 'x-yablonsky-security-signature' );
        $expected = self::proof_signature( $token, 'mu_runtime_probe' );
        $ok = 403 === $code && '1' === $header && 'mu_runtime_probe' === $family && '' !== $signature && hash_equals( $expected, $signature );
        $result = array(
            'ok'=>$ok,
            'code'=>$code,
            'header'=>$header,
            'family'=>$family,
            'checked_at'=>current_time( 'mysql', true ),
            'message'=>$ok ? __( 'Managed MU runtime answered before the normal plugin path with HTTP 403.', 'yablonsky-security' ) : __( 'Managed MU live proof was not observed. Refresh policy or review the loader state.', 'yablonsky-security' ),
        );
        set_transient( 'ysec_mu_verify_result', $result, 30 * MINUTE_IN_SECONDS );
        return $result;
    }

    public static function status(): array {
        $path = self::loader_path();
        $installed = is_file( $path );
        $owned = $installed && self::owned_loader( $path );
        $record = self::read_policy();
        $policy_valid = false;
        $policy_version = '';
        $payload = array();
        if ( is_array( $record ) ) {
            $payload = is_array( $record['payload'] ?? null ) ? $record['payload'] : array();
            $signature = (string) ( $record['signature'] ?? '' );
            $json = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
            $expected = is_string( $json ) ? hash_hmac( 'sha256', $json, self::signature_key() ) : '';
            $policy_valid = 1 === (int) ( $payload['abi'] ?? 0 ) && '' !== $expected && hash_equals( $expected, $signature );
            $policy_version = sanitize_text_field( (string) ( $payload['plugin_version'] ?? '' ) );
        }
        $filesystem = self::filesystem();
        $mu_dir = self::mu_dir();
        $mu_dir_writable = $filesystem ? ( $filesystem->is_dir( $mu_dir ) ? $filesystem->is_writable( $mu_dir ) : $filesystem->is_writable( dirname( $mu_dir ) ) ) : false;
        return array(
            'mu_dir'          => $mu_dir,
            'mu_dir_writable' => $mu_dir_writable,
            'installed'       => $installed,
            'owned'           => $owned,
            'runtime_readable'=> is_readable( YSEC_DIR . 'runtime/early-runtime.php' ),
            'policy_valid'    => $policy_valid,
            'policy_version'  => $policy_version,
            'abi'             => self::ABI,
            'duplicates'      => self::duplicate_providers(),
            'source_allow_rules' => count( (array) ( $payload['source_allowlist'] ?? array() ) ),
            'source_block_rules' => count( (array) ( $payload['source_blocklist'] ?? array() ) ),
            'early_burst_configured' => ! empty( $payload['early_burst_guard'] ),
            'persistent_object_cache' => function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache(),
        );
    }

    public static function duplicate_providers(): array {
        $dir = self::mu_dir();
        if ( ! is_dir( $dir ) ) return array();
        $out = array();
        foreach ( glob( trailingslashit( $dir ) . '*.php' ) ?: array() as $file ) {
            if ( basename( $file ) === self::LOADER ) continue;
            $name = strtolower( basename( $file ) );
            if ( false === strpos( $name, 'security' ) && false === strpos( $name, 'firewall' ) && false === strpos( $name, 'guard' ) && false === strpos( $name, 'aios' ) ) continue;
            $out[] = array(
                'file'=>basename( $file ),
                'sha256'=>is_readable( $file ) ? hash_file( 'sha256', $file ) : '',
                'provider'=>false !== strpos( $name, 'aios' ) ? 'aios' : 'unknown_security_runtime',
            );
            if ( count( $out ) >= 20 ) break;
        }
        return $out;
    }

    private static function read_policy(): ?array {
        $path = self::policy_path();
        if ( ! is_readable( $path ) ) return null;
        $raw = file_get_contents( $path );
        $marker = "<?php exit; ?>\n";
        if ( ! is_string( $raw ) || 0 !== strpos( $raw, $marker ) ) return null;
        $decoded = json_decode( substr( $raw, strlen( $marker ) ), true );
        return is_array( $decoded ) ? $decoded : null;
    }

    private static function ensure_state_dir(): bool {
        $filesystem = self::filesystem();
        if ( ! $filesystem ) return false;
        $dir = self::state_dir();
        if ( ! $filesystem->is_dir( $dir ) && ! $filesystem->mkdir( $dir, defined( 'FS_CHMOD_DIR' ) ? FS_CHMOD_DIR : 0755 ) ) return false;
        if ( ! $filesystem->is_writable( $dir ) ) return false;
        $index = trailingslashit( $dir ) . 'index.php';
        if ( ! is_file( $index ) ) self::atomic_write( $index, "<?php\nhttp_response_code(404);\nexit;\n" );
        return true;
    }

    private static function atomic_write( string $path, string $contents ): bool {
        $filesystem = self::filesystem();
        if ( ! $filesystem ) return false;
        $dir = dirname( $path );
        if ( ! $filesystem->is_dir( $dir ) || ! $filesystem->is_writable( $dir ) ) return false;
        $tmp = trailingslashit( $dir ) . '.ysec-' . wp_generate_uuid4() . '.tmp';
        $mode = defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644;
        if ( ! $filesystem->put_contents( $tmp, $contents, $mode ) ) return false;
        $ok = $filesystem->move( $tmp, $path, true );
        if ( $filesystem->exists( $tmp ) ) $filesystem->delete( $tmp, false, 'f' );
        return (bool) $ok;
    }

    private static function cleanup_legacy_evidence(): void {
        $filesystem = self::filesystem();
        if ( ! $filesystem ) return;
        $legacy = self::evidence_path();
        if ( $filesystem->is_file( $legacy ) ) $filesystem->delete( $legacy, false, 'f' );
    }

    private static function delete_state_artifacts( $filesystem ): void {
        foreach ( array( self::policy_path(), self::evidence_path(), trailingslashit( self::state_dir() ) . 'index.php' ) as $owned ) {
            if ( $filesystem->is_file( $owned ) ) $filesystem->delete( $owned, false, 'f' );
        }
        $dir = self::state_dir();
        if ( $filesystem->is_dir( $dir ) ) $filesystem->rmdir( $dir, false );
    }

    private static function loader_source(): string {
        return <<<'PHP'
<?php
/**
 * Yablonsky Security Managed MU Runtime Loader.
 * YSEC_MANAGED_MU_RUNTIME_ABI=1
 * This file is owned by Yablonsky Security. It is a thin fail-safe bridge only.
 */
if ( ! defined( 'ABSPATH' ) || 'cli' === PHP_SAPI ) { return; }
$ysec_runtime = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR . '/yablonsky-security/runtime/early-runtime.php' : '';
if ( '' === $ysec_runtime || ! is_readable( $ysec_runtime ) ) { return; }
require_once $ysec_runtime;
if ( ! function_exists( 'ysec_early_runtime_boot' ) ) { return; }
$GLOBALS['ysec_mu_coordination_v1'] = array(
    'security_phase'    => 10,
    'security_priority' => -1000,
    'capacity_phase'    => 20,
    'capacity_priority' => -900,
);
add_action( 'muplugins_loaded', static function() {
    ysec_early_runtime_boot( array(
        'abi'         => 1,
        'policy_path' => WP_CONTENT_DIR . '/ysec-runtime/policy.php',
        'phase'       => 10,
        'priority'    => -1000,
    ) );
}, -1000 );
PHP;
    }
}
