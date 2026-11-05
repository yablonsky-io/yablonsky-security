<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Local-first protection for anonymous WordPress/WooCommerce comments.
 *
 * The form proof is deliberately stateless and cache-compatible: it binds the
 * rendered form to a post and a bounded day bucket without storing a session or
 * writing a transient for every page view. Current and recent buckets remain
 * valid so full-page caches do not turn a security control into a UX failure.
 */
final class YSEC_Comment_Guard {
    private const PROOF_VERSION = 'v1';
    private const PROOF_MAX_AGE_DAYS = 7;

    public static function boot(): void {
        add_action( 'comment_form_after_fields', array( __CLASS__, 'form_fields' ) );
        add_filter( 'preprocess_comment', array( __CLASS__, 'verify' ), 5 );
        add_action( 'comment_post', array( __CLASS__, 'record' ), 10, 3 );
    }

    public static function form_fields(): void {
        if ( is_user_logged_in() ) return;
        if ( YSEC_Utils::option( 'comment_honeypot', 1 ) ) {
            echo '<p class="ysec-comment-trap" style="position:absolute;left:-10000px" aria-hidden="true"><label>' . esc_html__( 'Leave this field empty', 'yablonsky-security' ) . '<input type="text" name="ysec_comment_company" value="" tabindex="-1" autocomplete="off"></label></p>';
        }
        if ( ! YSEC_Utils::option( 'comment_form_proof', 1 ) ) return;
        $post_id = (int) get_the_ID();
        if ( $post_id <= 0 ) return;
        $bucket = self::current_bucket();
        echo '<input type="hidden" name="ysec_comment_bucket" value="' . esc_attr( (string) $bucket ) . '">';
        echo '<input type="hidden" name="ysec_comment_proof" value="' . esc_attr( self::proof_token( $post_id, $bucket ) ) . '">';
    }

    public static function verify( array $commentdata ): array {
        if ( is_user_logged_in() || ! self::is_standard_public_comment_post() ) return $commentdata;

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Standard anonymous WordPress comment submissions do not use a YSec action nonce; these fields are abuse signals verified below.
        $trap = isset( $_POST['ysec_comment_company'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_comment_company'] ) ) : '';
        if ( YSEC_Utils::option( 'comment_honeypot', 1 ) && '' !== $trap ) {
            self::deny( 'honeypot', 403 );
        }

        if ( YSEC_Utils::option( 'comment_form_proof', 1 ) ) {
            $post_id = absint( $commentdata['comment_post_ID'] ?? 0 );
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The form proof is the validated local anti-automation credential for this public form.
            $bucket = isset( $_POST['ysec_comment_bucket'] ) ? absint( wp_unslash( $_POST['ysec_comment_bucket'] ) ) : 0;
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- See explanation above; this value is authenticated with hash_equals().
            $proof = isset( $_POST['ysec_comment_proof'] ) ? sanitize_text_field( wp_unslash( $_POST['ysec_comment_proof'] ) ) : '';
            $reason = self::proof_failure_reason( $post_id, $bucket, $proof );
            if ( '' !== $reason ) self::deny( $reason, 403 );
        }

        if ( ! YSEC_Utils::option( 'comment_rate_enforce', 0 ) ) return $commentdata;
        $ip = YSEC_Utils::client_ip();
        if ( '' === $ip ) return $commentdata;
        $window = max( 1, min( 60, absint( YSEC_Utils::option( 'comment_rate_window', 10 ) ) ) );
        $limit = max( 3, min( 100, absint( YSEC_Utils::option( 'comment_rate_limit', 10 ) ) ) );
        $key = 'ysec_comment_' . substr( YSEC_Utils::source_identity( $ip ), 0, 40 );
        $bucket_data = get_transient( $key );
        $count = is_array( $bucket_data ) ? (int) ( $bucket_data['count'] ?? 0 ) : 0;
        if ( $count >= $limit ) self::deny( 'rate_limit', 429, array( 'limit'=>$limit, 'window_minutes'=>$window ) );
        return $commentdata;
    }

    public static function record( int $comment_id, $approved, array $commentdata ): void {
        if ( is_user_logged_in() || ! YSEC_Utils::option( 'comment_rate_enforce', 0 ) ) return;
        $ip = YSEC_Utils::client_ip();
        if ( '' === $ip ) return;
        $window = max( 1, min( 60, absint( YSEC_Utils::option( 'comment_rate_window', 10 ) ) ) );
        $key = 'ysec_comment_' . substr( YSEC_Utils::source_identity( $ip ), 0, 40 );
        $bucket_data = get_transient( $key );
        $count = is_array( $bucket_data ) ? (int) ( $bucket_data['count'] ?? 0 ) : 0;
        set_transient( $key, array( 'count'=>$count+1 ), $window * MINUTE_IN_SECONDS );
    }

    public static function proof_self_test(): bool {
        $post_id = 1;
        $bucket = self::current_bucket();
        $token = self::proof_token( $post_id, $bucket );
        return '' === self::proof_failure_reason( $post_id, $bucket, $token );
    }

    public static function summary(): array {
        global $wpdb;
        $table = YSEC_DB::table( 'events' );
        $since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
        $counts = array(
            'honeypot'      => 0,
            'missing_proof' => 0,
            'invalid_proof' => 0,
            'expired_proof' => 0,
            'rate_limit'    => 0,
            'legacy_rate'   => 0,
            'legacy_honey'  => 0,
        );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Read-only 24h security telemetry summary from YSec's dedicated event table.
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT type,details,SUM(hit_count) hits FROM %i WHERE observed_at >= %s AND ((type='request_decision' AND family='spam_abuse') OR type IN (%s,%s)) GROUP BY type,details",
                $table,
                $since,
                'comment_honeypot_blocked',
                'comment_rate_limited'
            ),
            ARRAY_A
        ) ?: array();
        foreach ( $rows as $row ) {
            $hits = absint( $row['hits'] ?? 0 );
            $type = sanitize_key( (string) ( $row['type'] ?? '' ) );
            if ( 'comment_honeypot_blocked' === $type ) { $counts['legacy_honey'] += $hits; continue; }
            if ( 'comment_rate_limited' === $type ) { $counts['legacy_rate'] += $hits; continue; }
            $detail = json_decode( (string) ( $row['details'] ?? '' ), true );
            $reason = is_array( $detail ) ? sanitize_key( (string) ( $detail['reason'] ?? '' ) ) : '';
            if ( isset( $counts[ $reason ] ) ) $counts[ $reason ] += $hits;
        }
        $honeypot = $counts['honeypot'] + $counts['legacy_honey'];
        $rate = $counts['rate_limit'] + $counts['legacy_rate'];
        $proof = $counts['missing_proof'] + $counts['invalid_proof'] + $counts['expired_proof'];
        return array(
            'proof_enabled'      => (bool) YSEC_Utils::option( 'comment_form_proof', 1 ),
            'honeypot_enabled'   => (bool) YSEC_Utils::option( 'comment_honeypot', 1 ),
            'rate_enabled'       => (bool) YSEC_Utils::option( 'comment_rate_enforce', 0 ),
            'rate_limit'         => max( 3, min( 100, absint( YSEC_Utils::option( 'comment_rate_limit', 10 ) ) ) ),
            'rate_window'        => max( 1, min( 60, absint( YSEC_Utils::option( 'comment_rate_window', 10 ) ) ) ),
            'proof_blocks_24h'   => $proof,
            'honeypot_24h'       => $honeypot,
            'rate_limited_24h'   => $rate,
            'blocked_24h'        => $proof + $honeypot + $rate,
            'missing_proof_24h'  => $counts['missing_proof'],
            'invalid_proof_24h'  => $counts['invalid_proof'],
            'expired_proof_24h'  => $counts['expired_proof'],
        );
    }

    private static function deny( string $reason, int $status, array $extra = array() ): void {
        $reason = sanitize_key( $reason );
        $details = array_merge( array( 'decision'=>'comment_denied', 'reason'=>$reason, 'surface'=>'wp_comments_post' ), $extra );
        YSEC_Events::log(
            'request_decision',
            array(
                'severity'       => 'medium',
                'confidence'     => 'high',
                'family'         => 'spam_abuse',
                'state'          => 'blocked',
                'path'           => '/wp-comments-post.php',
                'method'         => 'post',
                'status_code'    => $status,
                'details'        => $details,
                'aggregate'      => true,
                'aggregate_seed' => $reason,
            )
        );
        $message = 'rate_limit' === $reason
            ? __( 'Too many comments from this source. Please try again later.', 'yablonsky-security' )
            : __( 'Comment rejected by abuse protection. Reload the page and try again if you are a human visitor.', 'yablonsky-security' );
        if ( 429 === $status ) {
            wp_die( esc_html( $message ), '', array( 'response'=>429 ) );
        }
        wp_die( esc_html( $message ), '', array( 'response'=>403 ) );
    }

    private static function current_bucket(): int {
        return (int) floor( time() / DAY_IN_SECONDS );
    }

    private static function proof_token( int $post_id, int $bucket ): string {
        $payload = self::PROOF_VERSION . '|' . max( 0, $post_id ) . '|' . max( 0, $bucket );
        return hash_hmac( 'sha256', $payload, wp_salt( 'nonce' ) );
    }

    private static function proof_failure_reason( int $post_id, int $bucket, string $proof ): string {
        if ( $post_id <= 0 || $bucket <= 0 || '' === $proof ) return 'missing_proof';
        $age = self::current_bucket() - $bucket;
        if ( $age < 0 || $age > self::PROOF_MAX_AGE_DAYS ) return 'expired_proof';
        return hash_equals( self::proof_token( $post_id, $bucket ), $proof ) ? '' : 'invalid_proof';
    }

    private static function is_standard_public_comment_post(): bool {
        if ( 'POST' !== strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) ) return false;
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) return false;
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) return false;
        if ( defined( 'WP_CLI' ) && WP_CLI ) return false;
        $script = sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ?? '' ) );
        $uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) );
        return 'wp-comments-post.php' === wp_basename( $script ) || false !== strpos( $uri, '/wp-comments-post.php' );
    }
}
