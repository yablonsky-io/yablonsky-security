<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class YSEC_Posture {
    public static function report(): array {
        $s = YSEC_Utils::settings();
        $baseline = get_option( 'ysec_integrity_baseline', array() );
        $baseline_ok = is_array( $baseline ) && ! empty( $baseline['files'] );
        $captcha = class_exists( 'YSEC_Captcha' ) && YSEC_Captcha::configured();
        $totp = YSEC_Login::enabled_count() > 0;
        $controls = array(
            array( 'key'=>'waf', 'label'=>__( 'Application firewall', 'yablonsky-security' ), 'points'=>15, 'on'=>! empty( $s['waf_enabled'] ), 'why'=>__( 'Blocks high-confidence exploit patterns at the WordPress application layer.', 'yablonsky-security' ) ),
            array( 'key'=>'telemetry', 'label'=>__( 'Security request observation', 'yablonsky-security' ), 'points'=>10, 'on'=>! empty( $s['observe_requests'] ), 'why'=>__( 'Preserves bounded evidence needed to recognize campaigns and verify response.', 'yablonsky-security' ) ),
            array( 'key'=>'response', 'label'=>__( 'Guarded automatic response', 'yablonsky-security' ), 'points'=>10, 'on'=>! empty( $s['auto_block'] ), 'why'=>__( 'Contains repeated high-confidence sources with reversible time-bounded blocks.', 'yablonsky-security' ) ),
            array( 'key'=>'rate_limit', 'label'=>__( 'Login rate limiting', 'yablonsky-security' ), 'points'=>10, 'on'=>absint( $s['login_limit'] ?? 0 ) > 0, 'why'=>__( 'Limits repeated credential attempts independently of CAPTCHA or 2FA.', 'yablonsky-security' ) ),
            array( 'key'=>'captcha', 'label'=>__( 'Human verification', 'yablonsky-security' ), 'points'=>15, 'on'=>$captcha, 'why'=>__( 'Adds challenge verification to enabled login, registration and recovery surfaces.', 'yablonsky-security' ) ),
            array( 'key'=>'totp', 'label'=>__( 'TOTP two-factor authentication', 'yablonsky-security' ), 'points'=>10, 'on'=>$totp, 'why'=>__( 'At least one WordPress account is protected by Yablonsky authenticator-based 2FA.', 'yablonsky-security' ) ),
            array( 'key'=>'headers', 'label'=>__( 'Security headers', 'yablonsky-security' ), 'points'=>10, 'on'=>! empty( $s['security_headers'] ), 'why'=>__( 'Sends conservative response hardening headers.', 'yablonsky-security' ) ),
            array( 'key'=>'https', 'label'=>__( 'HTTPS transport', 'yablonsky-security' ), 'points'=>10, 'on'=>is_ssl(), 'why'=>__( 'Protects credentials and session traffic in transit.', 'yablonsky-security' ) ),
            array( 'key'=>'integrity', 'label'=>__( 'Integrity baseline', 'yablonsky-security' ), 'points'=>5, 'on'=>$baseline_ok, 'why'=>__( 'Enables local drift comparison against a trusted baseline.', 'yablonsky-security' ) ),
            array( 'key'=>'file_editor', 'label'=>__( 'Built-in file editor restricted', 'yablonsky-security' ), 'points'=>5, 'on'=>defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT, 'why'=>__( 'Reduces a common post-compromise code-editing path in wp-admin.', 'yablonsky-security' ) ),
        );
        $score = 0;
        foreach ( $controls as $control ) if ( $control['on'] ) $score += $control['points'];
        $summary = YSEC_Events::summary();
        $summary_valid = ! array_key_exists( 'valid', $summary ) || ! empty( $summary['valid'] );
        $critical = absint( $summary['critical'] ?? 0 );
        $high = absint( $summary['high'] ?? 0 );
        $pressure = $summary_valid ? min( 100, ( $critical * 5 ) + min( 50, $high ) ) : null;
        $findings = YSEC_Hardening::findings();
        $penalty = 0;
        foreach ( $findings as $finding ) {
            $penalty += array( 'high'=>25, 'medium'=>15, 'low'=>7, 'info'=>2 )[ $finding['severity'] ?? 'info' ] ?? 2;
        }
        $exposure = max( 0, 100 - min( 100, $penalty ) );
        $coverage = min( 100, (int) round( $score / 100 * 100 ) );
        return array( 'score'=>$score, 'controls'=>$controls, 'coverage'=>$coverage, 'exposure'=>$exposure, 'threat_pressure'=>$pressure );
    }
}
