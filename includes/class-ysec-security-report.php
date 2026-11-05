<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Bounded local posture report for review/support/release handoff.
 * It intentionally excludes API secrets, raw source IP evidence, user agents and event rows.
 */
final class YSEC_Security_Report {
    public static function build(): array {
        $posture = YSEC_Posture::report();
        $doctor = YSEC_Doctor::report();
        $compatibility = array();
        foreach ( YSEC_Compatibility::report() as $item ) {
            $compatibility[] = array(
                'name'           => (string) ( $item['name'] ?? '' ),
                'active'         => ! empty( $item['active'] ),
                'overlap'        => array_values( array_map( 'strval', (array) ( $item['overlap'] ?? array() ) ) ),
                'migration_areas'=> array_values( array_map( 'strval', (array) ( $item['migration'] ?? array() ) ) ),
            );
        }
        return array(
            'schema'              => 'yablonsky.security.posture-report.v1',
            'generated_at'        => gmdate( 'c' ),
            'plugin'              => 'Yablonsky Security',
            'version'             => YSEC_VERSION,
            'site'                => array(
                'url_hash'       => hash( 'sha256', strtolower( untrailingslashit( home_url( '/' ) ) ) ),
                'multisite'      => is_multisite(),
                'wordpress'      => get_bloginfo( 'version' ),
                'php'            => PHP_VERSION,
            ),
            'posture'             => array(
                'score'          => (int) ( $posture['score'] ?? 0 ),
                'coverage'       => (int) ( $posture['coverage'] ?? 0 ),
                'exposure'       => (int) ( $posture['exposure'] ?? 0 ),
                'threat_pressure'=> (int) ( $posture['threat_pressure'] ?? 0 ),
            ),
            'operations_24h'      => YSEC_Operations::snapshot( 24 ),
            'doctor'              => $doctor,
            'exposure_audit'      => YSEC_Exposure::audit(),
            'comment_abuse'       => YSEC_Comment_Guard::summary(),
            'country_policy'      => YSEC_Country_Policy::status(),
            'security_headers'    => YSEC_Security_Headers::summary(),
            'alerts'              => array(
                'enabled'        => (bool) YSEC_Utils::option( 'alerts_enabled', 0 ),
                'admin_changes'  => (bool) YSEC_Utils::option( 'alerts_admin_changes', 1 ),
                'admin_login'    => (bool) YSEC_Utils::option( 'alerts_admin_login', 1 ),
                'critical_events'=> (bool) YSEC_Utils::option( 'alerts_critical_events', 1 ),
                'daily_digest'   => (bool) YSEC_Utils::option( 'alerts_daily_digest', 1 ),
                'recipient_included' => false,
            ),
            'private_entry'       => array(
                'configured' => YSEC_Private_Login::configured(),
                'enforcing'  => YSEC_Private_Login::enforcing(),
                'state'      => (string) ( YSEC_Private_Login::status()['state'] ?? 'off' ),
                'urls_included' => false,
            ),
            'migration_readiness' => YSEC_Migration::readiness(),
            'takeover_closeout'   => YSEC_Takeover::status(),
            'compatibility'       => $compatibility,
            'privacy'             => array(
                'raw_event_rows_included' => false,
                'raw_ip_evidence_included'=> false,
                'user_agents_included'    => false,
                'api_secrets_included'    => false,
                'private_entry_urls_included'=> false,
            ),
        );
    }
}
