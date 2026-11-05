<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Plugin  {
    private static ?self $instance=null;
    public static function instance():self {
        return self::$instance??=new self();
    }
    /**
     * WordPress's own translation registry keeps authority. The built-in
     * fallback below consults only YSec's bundled catalog when WordPress
     * returns the original English string; this avoids unloading or replacing
     * other language domains and avoids deprecated domain registration.
     */
    /**
     * Read-only bundled-MO recovery for environments where another plugin
     * short-circuits or resets the YSec domain after normal textdomain loading.
     * No external requests; no cross-plugin domain or locale mutations.
     * Do not register broad gettext filters: use the domain-specific hooks.
     */
    private static array $fallback_catalogs = array();

    private static function fallback_catalog() {
        $locale = ( is_admin() && function_exists( 'get_user_locale' ) &&
            ( ! function_exists( 'is_locale_switched' ) || ! is_locale_switched() ) )
            ? (string) get_user_locale() : (string) determine_locale();
        if ( ! preg_match( '/^[A-Za-z0-9_@.-]+$/', $locale ) ) {
            return null;
        }
        if ( array_key_exists( $locale, self::$fallback_catalogs ) ) {
            return self::$fallback_catalogs[ $locale ];
        }
        $path = YSEC_DIR . 'languages/yablonsky-security-' . $locale . '.mo';
        // English is the native source, not a generated translation.
        if ( ! is_readable( $path ) ) {
            self::$fallback_catalogs[ $locale ] = null;
            return null;
        }
        $catalog = new YSEC_Bundled_MO();
        if ( ! $catalog->import_from_file( $path ) ) {
            self::$fallback_catalogs[ $locale ] = null;
            return null;
        }
        self::$fallback_catalogs[ $locale ] = $catalog;
        return $catalog;
    }

    public static function fallback_gettext( $translation, $original, $domain ) {
        if ( 'yablonsky-security' !== $domain || $translation !== $original ) {
            return $translation;
        }
        $catalog = self::fallback_catalog();
        return $catalog ? $catalog->translate( $original ) : $translation;
    }

    public static function fallback_gettext_context( $translation, $original, $context, $domain ) {
        if ( 'yablonsky-security' !== $domain || $translation !== $original ) {
            return $translation;
        }
        $catalog = self::fallback_catalog();
        return $catalog ? $catalog->translate( $original, $context ) : $translation;
    }

    public static function fallback_ngettext( $translation, $single, $plural, $number, $domain ) {
        if ( 'yablonsky-security' !== $domain ||
            ( $translation !== $single && $translation !== $plural ) ) {
            return $translation;
        }
        $catalog = self::fallback_catalog();
        return $catalog ? $catalog->translate_plural( $single, $plural, $number ) : $translation;
    }

    public static function fallback_ngettext_context( $translation, $single, $plural, $number, $context, $domain ) {
        if ( 'yablonsky-security' !== $domain ||
            ( $translation !== $single && $translation !== $plural ) ) {
            return $translation;
        }
        $catalog = self::fallback_catalog();
        return $catalog ? $catalog->translate_plural( $single, $plural, $number, $context ) : $translation;
    }

    public function boot():void {
        // Scope to this exact domain, after generic gettext filters. Lazy MO
        // parsing occurs only if WordPress actually returns an untranslated
        // YSec string (the failure visible on WPML-enabled MonParle).
        if ( is_admin() ) {
            add_filter( 'gettext', array( __CLASS__, 'fallback_gettext' ), PHP_INT_MAX, 3 );
            add_filter( 'ngettext', array( __CLASS__, 'fallback_ngettext' ), PHP_INT_MAX, 5 );
        }
        add_filter( 'gettext_yablonsky-security', array( __CLASS__, 'fallback_gettext' ), PHP_INT_MAX, 3 );
        add_filter( 'gettext_with_context_yablonsky-security', array( __CLASS__, 'fallback_gettext_context' ), PHP_INT_MAX, 4 );
        add_filter( 'ngettext_yablonsky-security', array( __CLASS__, 'fallback_ngettext' ), PHP_INT_MAX, 5 );
        add_filter( 'ngettext_with_context_yablonsky-security', array( __CLASS__, 'fallback_ngettext_context' ), PHP_INT_MAX, 6 );
        // Run a guarded schema upgrade before any front-end telemetry can write new columns.
        YSEC_DB::maybe_upgrade();
        add_action('template_redirect',array('YSEC_Events','observe_request'),999);
        add_action('shutdown',array('YSEC_Events','flush_request_record'),PHP_INT_MAX);
        add_action('ysec_hourly_cleanup',array('YSEC_DB','cleanup'));
        add_action( 'ysec_hourly_cleanup', array( 'YSEC_Crawler_Verification', 'refresh_due' ), 70 );
        add_action('ysec_integrity_rebaseline',array('YSEC_Integrity','baseline'));
        YSEC_Managed_MU::boot();
        YSEC_Firewall::boot();
        YSEC_Private_Login::boot();
        YSEC_Jobs::boot();
        YSEC_Login::boot();
        YSEC_Captcha::boot();
        YSEC_Comment_Guard::boot();
        YSEC_Uploads::boot();
        YSEC_File_Ingress::boot();
        YSEC_Integrity::boot();
        add_action('ysec_daily_maintenance',array('YSEC_Permissions','scheduled'),30);
        YSEC_Audit::boot();
        YSEC_Alerts::boot();
        YSEC_Hardening::boot();
        YSEC_Security_Headers::boot();
        YSEC_Technology_Exposure::boot();
        YSEC_Vulnerabilities::boot();
        YSEC_Advisories::boot();
        YSEC_REST::boot();
        YSEC_Privacy::boot();
        YSEC_Compatibility::boot();
        YSEC_CLI::boot();
        if(is_admin()){
            YSEC_Admin_Tables::boot();
            YSEC_Admin::boot();
        }
    }
}
