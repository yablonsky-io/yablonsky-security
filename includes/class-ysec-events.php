<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class YSEC_Events {
    private const AGGREGATION_WINDOW = 900;

    private static array $request_signals = array();
    private static bool $request_blocked = false;
    private static bool $request_flushed = false;

    public static function log( string $type, array $args = array() ): string {
        global $wpdb;

        $now      = current_time( 'mysql', true );
        $ip       = YSEC_Utils::client_ip();
        $uuid     = wp_generate_uuid4();
        $defaults = array(
            'severity'         => 'info',
            'confidence'       => 'medium',
            'state'            => 'observed',
            'family'           => 'general',
            'path'             => '',
            'method'           => '',
            'status_code'      => 0,
            'details'          => array(),
            'aggregate'        => false,
            'aggregate_window' => self::AGGREGATION_WINDOW,
            'aggregate_seed'   => '',
            'request_id'       => '',
            'query_redacted'   => null,
        );
        $a        = wp_parse_args( $args, $defaults );
        $details  = YSEC_Utils::redact( $a['details'] );
        $path     = YSEC_Utils::log_string( (string) $a['path'], 2048 );
        $method   = substr( sanitize_key( $a['method'] ), 0, 12 );
        $family   = sanitize_key( $a['family'] );
        $severity = sanitize_key( $a['severity'] );
        $state    = sanitize_key( $a['state'] );
        $source   = $ip ? YSEC_Utils::source_identity( $ip ) : '';
        $source_enc = $ip ? YSEC_Utils::encrypt( $ip ) : '';
        $user_agent = YSEC_Utils::user_agent();
        $country = YSEC_Utils::country_signal();
        $query_redacted = is_string( $a['query_redacted'] ) ? YSEC_Utils::log_string( $a['query_redacted'], 1024 ) : YSEC_Utils::redacted_query();
        $request  = '' !== (string) $a['request_id'] ? sanitize_text_field( (string) $a['request_id'] ) : YSEC_Utils::request_id();
        $agg_key  = null;

        if ( ! empty( $a['aggregate'] ) && '' !== $source ) {
            $window = max( 60, min( HOUR_IN_SECONDS, absint( $a['aggregate_window'] ) ?: self::AGGREGATION_WINDOW ) );
            $bucket = (int) floor( time() / $window );
            $seed   = implode(
                '|',
                array(
                    sanitize_key( $type ),
                    // Day-bound aggregation keys prevent a request after UTC
                    // midnight from mutating a row whose prior day is already
                    // finalized in immutable daily rollups.
                    gmdate( 'Y-m-d' ),
                    $family,
                    $severity,
                    $state,
                    $path,
                    $method,
                    $source,
                    sanitize_text_field( (string) $a['aggregate_seed'] ),
                    (string) $bucket,
                )
            );
            $agg_key = hash( 'sha256', $seed );
        }

        $data = array(
            'event_uuid'         => $uuid,
            'observed_at'        => $now,
            'first_seen_at'      => $now,
            'last_seen_at'       => $now,
            'hit_count'          => 1,
            'request_id'         => $request,
            'aggregation_key'    => $agg_key,
            'type'               => sanitize_key( $type ),
            'severity'           => $severity,
            'confidence'         => sanitize_key( $a['confidence'] ),
            'state'              => $state,
            'family'             => $family,
            'path'               => $path,
            'method'             => $method,
            'status_code'        => absint( $a['status_code'] ),
            'source_hash'        => $source,
            'source_enc'         => $source_enc,
            'user_agent'         => $user_agent,
            'country'            => $country,
            'query_redacted'     => $query_redacted,
            'classifier_version' => YSEC_Classifier::VERSION,
            'reviewed'           => 0,
            'archived'           => 0,
            'details'            => wp_json_encode( $details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ),
        );

        if ( null !== $agg_key ) {
            $sql = 'INSERT INTO %i (event_uuid,observed_at,first_seen_at,last_seen_at,hit_count,request_id,aggregation_key,type,severity,confidence,state,family,path,method,status_code,source_hash,source_enc,user_agent,country,query_redacted,classifier_version,reviewed,archived,details) VALUES (%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%s,%d,%d,%s) ON DUPLICATE KEY UPDATE observed_at=VALUES(observed_at),last_seen_at=VALUES(last_seen_at),hit_count=hit_count+1,request_id=VALUES(request_id),status_code=VALUES(status_code),source_enc=VALUES(source_enc),user_agent=VALUES(user_agent),country=VALUES(country),query_redacted=VALUES(query_redacted),details=VALUES(details)';
            $params = array(
                self::table_name(),
                $data['event_uuid'],
                $data['observed_at'],
                $data['first_seen_at'],
                $data['last_seen_at'],
                $data['hit_count'],
                $data['request_id'],
                $data['aggregation_key'],
                $data['type'],
                $data['severity'],
                $data['confidence'],
                $data['state'],
                $data['family'],
                $data['path'],
                $data['method'],
                $data['status_code'],
                $data['source_hash'],
                $data['source_enc'],
                $data['user_agent'],
                $data['country'],
                $data['query_redacted'],
                $data['classifier_version'],
                $data['reviewed'],
                $data['archived'],
                $data['details'],
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Atomic request-evidence upsert against the dedicated table; identifier and values are prepared.
            $wpdb->query( $wpdb->prepare( $sql, $params ) );
            return $uuid;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Dedicated security event table requires immediate writes.
        $wpdb->insert(
            self::table_name(),
            $data,
            array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s' )
        );
        return $uuid;
    }

    public static function capture_waf_signals( array $signals, bool $blocked = false ): void {
        foreach ( $signals as $signal ) {
            if ( ! is_array( $signal ) ) {
                continue;
            }
            self::$request_signals[] = array(
                'origin'     => 'waf',
                'class'      => sanitize_key( (string) ( $signal['class'] ?? 'probe' ) ),
                'family'     => sanitize_key( (string) ( $signal['family'] ?? 'reconnaissance' ) ),
                'confidence' => sanitize_key( (string) ( $signal['confidence'] ?? 'medium' ) ),
                'severity'   => sanitize_key( (string) ( $signal['severity'] ?? 'medium' ) ),
            );
        }
        if ( $blocked ) {
            self::$request_blocked = true;
        }
    }

    public static function flush_request_record(): void {
        if ( self::$request_flushed || empty( self::$request_signals ) ) {
            return;
        }
        self::$request_flushed = true;

        $signals = array();
        foreach ( self::$request_signals as $signal ) {
            $key = implode( '|', array( $signal['class'], $signal['family'], $signal['confidence'], $signal['severity'] ) );
            $signals[ $key ] = $signal;
        }
        $signals = array_values( $signals );
        usort(
            $signals,
            static function ( array $a, array $b ): int {
                return self::severity_rank( $b['severity'] ) <=> self::severity_rank( $a['severity'] );
            }
        );

        $primary = $signals[0];
        $path    = YSEC_Utils::normalize_path( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/' );
        $method  = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
        $blocked = self::$request_blocked || 'critical' === $primary['severity'];
        $state   = $blocked ? 'blocked' : ( self::contains_probe( $signals ) ? 'suspicious' : 'observed' );
        $families = array_values( array_unique( array_column( $signals, 'family' ) ) );
        $request_id = YSEC_Utils::request_id();
        YSEC_Discovery_Interop::publish_security_signal(
            array(
                'decision'   => $blocked ? 'request_denied' : ( 'suspicious' === $state ? 'observed_suspicious' : 'observed' ),
                'blocked'    => $blocked,
                'family'     => $primary['family'],
                'families'   => $families,
                'method'     => $method,
                'path'       => $path,
                'request_id' => $request_id,
            )
        );

        self::log(
            'request_decision',
            array(
                'severity'         => $primary['severity'],
                'confidence'       => $primary['confidence'],
                'state'            => $state,
                'family'           => $primary['family'],
                'path'             => $path,
                'method'           => $method,
                'status_code'      => $blocked ? 403 : (int) http_response_code(),
                'aggregate'        => true,
                'aggregate_window' => self::AGGREGATION_WINDOW,
                'aggregate_seed'   => implode( ',', $families ),
                'request_id'       => $request_id,
                'details'          => array_merge(
                    array(
                        'decision'      => $blocked ? 'request_denied' : ( 'suspicious' === $state ? 'observed_suspicious' : 'observed' ),
                        'signal_count'  => count( $signals ),
                        'families'      => $families,
                        'signals'       => $signals,
                        'referer'       => YSEC_Utils::safe_url_for_log( isset( $_SERVER['HTTP_REFERER'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '' ),
                        'extended_mode' => (bool) YSEC_Utils::option( 'extended_telemetry', 0 ),
                    ),
                    YSEC_Discovery_Interop::evidence_context()
                ),
            )
        );
    }

    public static function recent( int $limit = 100, string $severity = '' ): array {
        $result = self::query(
            array(
                'page'     => 1,
                'per_page' => $limit,
                'severity' => $severity,
            )
        );
        return $result['rows'];
    }

    public static function query( array $args = array() ): array {
        global $wpdb;
        $args = wp_parse_args(
            $args,
            array(
                'page'          => 1,
                'per_page'      => 25,
                'search'        => '',
                'severity'      => '',
                'family'        => '',
                'state'         => '',
                'date_from'     => '',
                'date_to'       => '',
                'orderby'       => 'observed_at',
                'order'         => 'DESC',
                'record_status' => 'active',
                'enforcement_only' => 0,
            )
        );
        $page     = max( 1, absint( $args['page'] ) );
        $per_page = max( 10, min( 100, absint( $args['per_page'] ) ?: 25 ) );
        $table    = self::table_name();
        $where    = '';
        $params   = array( $table );

        $record_status = sanitize_key( (string) ( $args['record_status'] ?? 'active' ) );
        if ( 'archived' === $record_status ) {
            $where .= ' AND archived=1';
        } elseif ( 'reviewed' === $record_status ) {
            $where .= ' AND archived=0 AND reviewed=1';
        } elseif ( 'all' !== $record_status ) {
            $where .= ' AND archived=0';
        }

        if ( in_array( $args['severity'], array( 'critical', 'high', 'medium', 'low', 'info' ), true ) ) {
            $where   .= ' AND severity=%s';
            $params[] = $args['severity'];
        }
        if ( '' !== $args['family'] ) {
            $where   .= ' AND family=%s';
            $params[] = sanitize_key( $args['family'] );
        }
        if ( ! empty( $args['enforcement_only'] ) ) {
            $where .= " AND state IN ('blocked','request_denied','source_blocked','campaign_contained')";
        }
        if ( '' !== $args['state'] ) {
            $where   .= ' AND state=%s';
            $params[] = sanitize_key( $args['state'] );
        }
        if ( '' !== $args['date_from'] ) {
            $where   .= ' AND observed_at >= %s';
            $params[] = self::date_boundary( $args['date_from'], false );
        }
        if ( '' !== $args['date_to'] ) {
            $where   .= ' AND observed_at <= %s';
            $params[] = self::date_boundary( $args['date_to'], true );
        }
        $search = trim( sanitize_text_field( (string) $args['search'] ) );
        if ( '' !== $search ) {
            $like = '%' . $wpdb->esc_like( $search ) . '%';
            if ( filter_var( $search, FILTER_VALIDATE_IP ) ) {
                $where .= ' AND (type LIKE %s OR family LIKE %s OR path LIKE %s OR state LIKE %s OR method LIKE %s OR source_hash=%s)';
                array_push( $params, $like, $like, $like, $like, $like, YSEC_Utils::source_identity( $search ) );
            } else {
                $where .= ' AND (type LIKE %s OR family LIKE %s OR path LIKE %s OR state LIKE %s OR method LIKE %s OR country LIKE %s OR user_agent LIKE %s)';
                array_push( $params, $like, $like, $like, $like, $like, $like, $like );
            }
        }

        $order_map = array(
            'observed_at' => 'observed_at',
            'hit_count'   => 'hit_count',
            'severity'    => 'severity',
            'family'      => 'family',
            'path'        => 'path',
            'state'       => 'state',
            'type'        => 'type',
            'status_code' => 'status_code',
            'id'          => 'id',
        );
        $orderby = $order_map[ $args['orderby'] ] ?? 'observed_at';
        $order   = 'ASC' === strtoupper( (string) $args['order'] ) ? 'ASC' : 'DESC';

        $offset       = ( $page - 1 ) * $per_page;
        $query_args   = $params;
        $query_args[] = $per_page;
        $query_args[] = $offset;
        $columns = 'id,observed_at,first_seen_at,last_seen_at,hit_count,request_id,type,severity,state,family,path,method,status_code,source_hash,source_enc,user_agent,country,query_redacted,reviewed,archived,details';
        $sql = 'SELECT ' . $columns . ' FROM %i WHERE 1=1' . $where . ' ORDER BY ' . $orderby . ' ' . $order . ', id DESC LIMIT %d OFFSET %d';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Identifier and all values are prepared; ORDER BY and selected columns use strict internal allowlists.
        $rows = $wpdb->get_results( $wpdb->prepare( $sql, $query_args ), ARRAY_A ) ?: array();

        if ( 1 === $page && count( $rows ) < $per_page ) {
            $total = count( $rows );
        } else {
            $count_sql = 'SELECT COUNT(*) FROM %i WHERE 1=1' . $where;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Exact pagination count is required only when the first page is full or a later page is requested.
            $total = (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) );
        }

        return array( 'rows' => $rows, 'total' => $total, 'page' => $page, 'per_page' => $per_page );
    }

    public static function filter_options(): array {
        $cached=get_transient('ysec_event_filter_options_v2');
        if(is_array($cached))return $cached;
        global $wpdb;
        $table = self::table_name();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short-lived admin filter cache; refreshed automatically.
        $families = $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT family FROM %i WHERE family<>%s ORDER BY family ASC LIMIT 200', $table, '' ) ) ?: array();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short-lived admin filter cache; refreshed automatically.
        $states = $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT state FROM %i WHERE state<>%s ORDER BY state ASC LIMIT 50', $table, '' ) ) ?: array();
        $out=array( 'families' => $families, 'states' => $states );
        set_transient('ysec_event_filter_options_v2',$out,60);
        return $out;
    }

    public static function summary(): array {
        $cached=get_transient('ysec_event_summary_24h_v2');
        if(is_array($cached))return $cached;
        global $wpdb;
        $table = self::table_name();
        $since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short-lived security summary cache reduces repeated full-range aggregation.
        $rows = $wpdb->get_results( $wpdb->prepare( 'SELECT severity,SUM(hit_count) c FROM %i WHERE observed_at >= %s GROUP BY severity', $table, $since ), ARRAY_A );
        // Unknown is not zero: return an explicit uncached failure and retry on
        // the next read. This summary also feeds posture, AI and REST reports.
        if ( ! is_array( $rows ) || ! empty( $wpdb->last_error ) ) {
            return array( 'valid'=>false, 'critical'=>null, 'high'=>null, 'medium'=>null, 'low'=>null, 'info'=>null );
        }
        $out  = array( 'valid'=>true, 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
        foreach ( $rows as $row ) {
            $out[ $row['severity'] ] = (int) $row['c'];
        }
        set_transient('ysec_event_summary_24h_v2',$out,15);
        return $out;
    }

    public static function firewall_decision_summary( int $hours = 24 ): array {
        $hours = max( 1, min( 168, $hours ) );
        $cache_key = 'ysec_firewall_decision_summary_v1_' . $hours;
        $cached = get_transient( $cache_key );
        if ( is_array( $cached ) ) return $cached;
        global $wpdb;
        $since = gmdate( 'Y-m-d H:i:s', time() - $hours * HOUR_IN_SECONDS );
        $table = self::table_name();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded response-state summary for firewall control plane.
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT state,SUM(hit_count) hits,COUNT(*) records FROM %i WHERE observed_at >= %s GROUP BY state", $table, $since ), ARRAY_A ) ?: array();
        $states = array(); $total = 0; $denied = 0;
        foreach ( $rows as $row ) {
            $state = sanitize_key( (string) $row['state'] );
            $hits = (int) $row['hits'];
            $states[ $state ] = $hits; $total += $hits;
            if ( in_array( $state, array( 'blocked','request_denied','source_blocked','campaign_contained' ), true ) ) $denied += $hits;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Recent denied-request sample for administrator explanation, bounded to 12 rows.
        $recent = $wpdb->get_results( $wpdb->prepare( "SELECT observed_at,last_seen_at,hit_count,family,path,method,status_code,state,country,source_enc FROM %i WHERE observed_at >= %s AND state IN ('blocked','request_denied','source_blocked','campaign_contained') ORDER BY id DESC LIMIT 12", $table, $since ), ARRAY_A ) ?: array();
        $request_denies = (int) ( $states['request_denied'] ?? 0 ) + (int) ( $states['blocked'] ?? 0 );
        $source_containments = (int) ( $states['source_blocked'] ?? 0 ) + (int) ( $states['campaign_contained'] ?? 0 );
        $out = array( 'states'=>$states, 'total_hits'=>$total, 'denied_hits'=>$denied, 'request_denies'=>$request_denies, 'source_containments'=>$source_containments, 'deny_ratio'=>$total>0?round(100*$denied/$total,1):0.0, 'recent'=>$recent, 'hours'=>$hours );
        set_transient( $cache_key, $out, 20 );
        return $out;
    }

    public static function crawler_claim_security_summary( int $hours = 24 ): array {
        $hours = max( 1, min( 168, $hours ) );
        $cache_key = 'ysec_crawler_claim_security_v1_' . $hours;
        $cached = get_transient( $cache_key );
        if ( is_array( $cached ) ) return $cached;
        global $wpdb;
        $since = gmdate( 'Y-m-d H:i:s', time() - $hours * HOUR_IN_SECONDS );
        $table = self::table_name();
        // Bounded hot-evidence query. User-Agent claims are mapped in PHP and never treated as verified identity.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short-lived local security summary over current request-decision evidence.
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT user_agent,SUM(hit_count) hits FROM %i WHERE observed_at >= %s AND type='request_decision' AND user_agent<>'' AND state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained') GROUP BY user_agent ORDER BY hits DESC LIMIT 300", $table, $since ), ARRAY_A ) ?: array();
        $agents = array(); $total = 0;
        foreach ( $rows as $row ) {
            $claim = YSEC_Discovery_Interop::claimed_crawler( (string) ( $row['user_agent'] ?? '' ) );
            if ( empty( $claim['claimed'] ) ) continue;
            $hits = max( 0, (int) ( $row['hits'] ?? 0 ) );
            $agent = (string) $claim['agent'];
            $agents[ $agent ] = ( $agents[ $agent ] ?? 0 ) + $hits;
            $total += $hits;
        }
        arsort( $agents );
        $out = array( 'hits'=>$total, 'agents'=>array_slice( $agents, 0, 8, true ), 'hours'=>$hours );
        set_transient( $cache_key, $out, 30 );
        return $out;
    }

    public static function recon_summary( int $hours = 24 ): array {
        $hours = max( 1, min( 168, $hours ) );
        $cache_key = 'ysec_recon_summary_v1_' . $hours;
        $cached = get_transient( $cache_key );
        if ( is_array( $cached ) ) return $cached;
        global $wpdb;
        $since = gmdate( 'Y-m-d H:i:s', time() - $hours * HOUR_IN_SECONDS );
        $table = self::table_name();
        $group = "SELECT source_hash,family,SUM(hit_count) requests,COUNT(DISTINCT path) paths,MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) risk FROM %i WHERE archived=0 AND source_hash<>'' AND state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained') AND observed_at >= %s GROUP BY source_hash,family HAVING SUM(hit_count)>=2";
        $sql = 'SELECT COUNT(*) campaigns,COALESCE(SUM(requests),0) requests,COALESCE(SUM(paths),0) paths,COALESCE(SUM(CASE WHEN risk>=4 THEN 1 ELSE 0 END),0) critical_campaigns FROM (' . $group . ') ysec_recon_summary';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Bounded derived campaign summary; identifier and date are prepared.
        $row = $wpdb->get_row( $wpdb->prepare( $sql, $table, $since ), ARRAY_A ) ?: array();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Hot-window distinct source metric for derived reconnaissance view.
        $sources = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT source_hash) FROM %i WHERE archived=0 AND source_hash<>'' AND state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained') AND observed_at >= %s", $table, $since ) );
        $out = array( 'campaigns'=>(int)($row['campaigns']??0), 'requests'=>(int)($row['requests']??0), 'paths'=>(int)($row['paths']??0), 'critical_campaigns'=>(int)($row['critical_campaigns']??0), 'sources'=>$sources, 'hours'=>$hours );
        set_transient( $cache_key, $out, 30 );
        return $out;
    }

    public static function campaigns( int $hours = 24 ): array {
        $result = self::campaigns_query(
            array(
                'date_from' => gmdate( 'Y-m-d', time() - HOUR_IN_SECONDS * max( 1, min( 168, $hours ) ) ),
                'page'      => 1,
                'per_page'  => 100,
            )
        );
        return $result['rows'];
    }

    public static function campaigns_query( array $args = array() ): array {
        global $wpdb;
        $args = wp_parse_args(
            $args,
            array(
                'page'      => 1,
                'per_page'  => 25,
                'search'        => '',
                'severity'      => '',
                'family'        => '',
                'state'         => '',
                'record_status' => 'active',
                'date_from'     => gmdate( 'Y-m-d', time() - DAY_IN_SECONDS ),
                'date_to'       => gmdate( 'Y-m-d' ),
                'orderby'       => 'risk',
                'order'         => 'DESC',
            )
        );
        $page     = max( 1, absint( $args['page'] ) );
        $per_page = max( 10, min( 100, absint( $args['per_page'] ) ?: 25 ) );
        $table    = self::table_name();
        $where    = " AND source_hash <> '' AND state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained')";
        $params   = array( $table );

        $record_status = sanitize_key( (string) ( $args['record_status'] ?? 'active' ) );
        if ( 'archived' === $record_status ) {
            $where .= ' AND archived=1';
        } elseif ( 'reviewed' === $record_status ) {
            $where .= ' AND archived=0 AND reviewed=1';
        } elseif ( 'all' !== $record_status ) {
            $where .= ' AND archived=0';
        }
        if ( in_array( (string) ( $args['severity'] ?? '' ), array( 'critical', 'high', 'medium', 'low', 'info' ), true ) ) {
            $where   .= ' AND severity=%s';
            $params[] = sanitize_key( (string) $args['severity'] );
        }
        if ( '' !== (string) ( $args['state'] ?? '' ) ) {
            $where   .= ' AND state=%s';
            $params[] = sanitize_key( (string) $args['state'] );
        }
        if ( '' !== $args['family'] ) {
            $where   .= ' AND family=%s';
            $params[] = sanitize_key( $args['family'] );
        }
        if ( '' !== $args['date_from'] ) {
            $where   .= ' AND observed_at >= %s';
            $params[] = self::date_boundary( $args['date_from'], false );
        }
        if ( '' !== $args['date_to'] ) {
            $where   .= ' AND observed_at <= %s';
            $params[] = self::date_boundary( $args['date_to'], true );
        }
        $search = trim( sanitize_text_field( (string) $args['search'] ) );
        if ( '' !== $search ) {
            $like = '%' . $wpdb->esc_like( $search ) . '%';
            if ( filter_var( $search, FILTER_VALIDATE_IP ) ) {
                $where .= ' AND (family LIKE %s OR path LIKE %s OR source_hash=%s)';
                array_push( $params, $like, $like, YSEC_Utils::source_identity( $search ) );
            } else {
                $where .= ' AND (family LIKE %s OR path LIKE %s OR source_hash LIKE %s OR country LIKE %s OR user_agent LIKE %s)';
                array_push( $params, $like, $like, $like, $like, $like );
            }
        }

        $order_map = array(
            'risk'       => 'risk',
            'requests'   => 'requests',
            'paths'      => 'paths',
            'first_seen' => 'first_seen',
            'last_seen'  => 'last_seen',
            'family'     => 'family',
        );
        $orderby = $order_map[ $args['orderby'] ] ?? 'risk';
        $order   = 'ASC' === strtoupper( (string) $args['order'] ) ? 'ASC' : 'DESC';

        $group_sql = 'SELECT source_hash,family,SUM(hit_count) requests,COUNT(DISTINCT path) paths,MIN(COALESCE(first_seen_at,observed_at)) first_seen,MAX(COALESCE(last_seen_at,observed_at)) last_seen,MAX(CASE severity WHEN \'critical\' THEN 4 WHEN \'high\' THEN 3 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 1 ELSE 0 END) risk,MAX(country) country,MAX(user_agent) user_agent,MAX(source_enc) source_enc,MAX(path) sample_path FROM %i WHERE 1=1' . $where . ' GROUP BY source_hash,family HAVING SUM(hit_count) >= 2';
        $offset       = ( $page - 1 ) * $per_page;
        $query_args   = $params;
        $query_args[] = $per_page;
        $query_args[] = $offset;
        $sql = $group_sql . ' ORDER BY ' . $orderby . ' ' . $order . ', last_seen DESC LIMIT %d OFFSET %d';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Identifier and all values are prepared; ORDER BY uses strict allowlist.
        $rows = $wpdb->get_results( $wpdb->prepare( $sql, $query_args ), ARRAY_A ) ?: array();

        if ( 1 === $page && count( $rows ) < $per_page ) {
            $total = count( $rows );
        } else {
            $count_sql = 'SELECT COUNT(*) FROM (' . $group_sql . ') ysec_campaigns';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Exact grouped pagination count is required only when the first page is full or a later page is requested.
            $total = (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) );
        }

        return array( 'rows' => $rows, 'total' => $total, 'page' => $page, 'per_page' => $per_page );
    }

    private static function job_event_where( array $args ): array {
        global $wpdb;
        $args=wp_parse_args($args,array('search'=>'','severity'=>'','family'=>'','state'=>'','date_from'=>'','date_to'=>'','record_status'=>'active','enforcement_only'=>0));
        $where='';$params=array();
        $record_status=sanitize_key((string)$args['record_status']);
        if('archived'===$record_status){$where.=' AND archived=1';}
        elseif('reviewed'===$record_status){$where.=' AND reviewed=1 AND archived=0';}
        elseif('all'!==$record_status){$where.=' AND archived=0';}
        if ( ! empty( $args['enforcement_only'] ) ) $where .= " AND state IN ('blocked','request_denied','source_blocked','campaign_contained')";
        foreach(array('severity','family','state') as $key){if(''!==(string)$args[$key]){$where.=' AND '.$key.'=%s';$params[]=sanitize_key((string)$args[$key]);}}
        if(''!==(string)$args['date_from']){$where.=' AND observed_at >= %s';$params[]=self::date_boundary((string)$args['date_from'],false);}
        if(''!==(string)$args['date_to']){$where.=' AND observed_at <= %s';$params[]=self::date_boundary((string)$args['date_to'],true);}
        $search=trim(sanitize_text_field((string)$args['search']));
        if(''!==$search){$like='%'.$wpdb->esc_like($search).'%';if(filter_var($search,FILTER_VALIDATE_IP)){$where.=' AND (type LIKE %s OR family LIKE %s OR path LIKE %s OR state LIKE %s OR method LIKE %s OR source_hash=%s)';array_push($params,$like,$like,$like,$like,$like,YSEC_Utils::source_identity($search));}else{$where.=' AND (type LIKE %s OR family LIKE %s OR path LIKE %s OR state LIKE %s OR method LIKE %s OR country LIKE %s OR user_agent LIKE %s)';array_push($params,$like,$like,$like,$like,$like,$like,$like);}}
        return array($where,$params);
    }

    public static function job_event_count(array $args): int {
        global $wpdb; list($where,$params)=self::job_event_where($args); $params=array_merge(array(self::table_name()),$params);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Background job scope count against dedicated event table; values prepared.
        return (int)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE 1=1'.$where,$params));
    }
    public static function job_event_max_id(array $args): int {
        global $wpdb; list($where,$params)=self::job_event_where($args); $params=array_merge(array(self::table_name()),$params);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Snapshot ceiling for resumable job.
        return (int)$wpdb->get_var($wpdb->prepare('SELECT COALESCE(MAX(id),0) FROM %i WHERE 1=1'.$where,$params));
    }
    public static function job_event_batch(array $args,int $after_id,int $max_id,int $limit=100,bool $full=true): array {
        global $wpdb; list($where,$params)=self::job_event_where($args); $limit=max(1,min(500,$limit));
        $where.=' AND id>%d AND id<=%d';$params[]=$after_id;$params[]=$max_id;
        $fields=$full?'*':'id,source_hash,family,state';
        $query_args=array_merge(array(self::table_name()),$params,array($limit));
        $sql='SELECT '.$fields.' FROM %i WHERE 1=1'.$where.' ORDER BY id ASC LIMIT %d';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Resumable ID-cursor batch against dedicated event table; values prepared.
        return $wpdb->get_results($wpdb->prepare($sql,$query_args),ARRAY_A)?:array();
    }
    public static function job_recon_count(array $args): int { $r=self::campaigns_query(array_merge($args,array('page'=>1,'per_page'=>10))); return (int)$r['total']; }
    public static function job_recon_batch(array $args,int $offset,int $limit=100): array {
        $limit=max(10,min(100,$limit));$page=intdiv(max(0,$offset),$limit)+1;
        $r=self::campaigns_query(array_merge($args,array('page'=>$page,'per_page'=>$limit,'orderby'=>'last_seen','order'=>'DESC')));
        return $r['rows'];
    }

    private static function job_source_where( string $dataset, array $args, bool $include_max = false, int $max_id = 0 ): array {
        global $wpdb;
        $dataset = in_array( $dataset, array( 'recon', 'firewall_actions' ), true ) ? $dataset : 'events';
        $args = wp_parse_args( $args, array( 'search'=>'', 'severity'=>'', 'family'=>'', 'state'=>'', 'date_from'=>'', 'date_to'=>'', 'record_status'=>'active', 'enforcement_only'=>0 ) );
        $where = " AND source_hash<>''";
        if ( 'firewall_actions' === $dataset || ! empty( $args['enforcement_only'] ) ) {
            $where .= " AND state IN ('blocked','request_denied','source_blocked','campaign_contained')";
        } elseif ( 'recon' === $dataset ) {
            $where .= " AND state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained')";
        } else {
            $where .= " AND state IN ('suspicious','blocked')";
        }
        $params = array();
        $record_status = sanitize_key( (string) $args['record_status'] );
        if ( 'archived' === $record_status ) $where .= ' AND archived=1';
        elseif ( 'reviewed' === $record_status ) $where .= ' AND reviewed=1 AND archived=0';
        elseif ( 'all' !== $record_status ) $where .= ' AND archived=0';
        if ( in_array( (string) $args['severity'], array( 'critical','high','medium','low','info' ), true ) ) { $where .= ' AND severity=%s'; $params[] = $args['severity']; }
        if ( '' !== (string) $args['state'] ) { $where .= ' AND state=%s'; $params[] = sanitize_key( (string) $args['state'] ); }
        if ( '' !== (string) $args['family'] ) { $where .= ' AND family=%s'; $params[] = sanitize_key( (string) $args['family'] ); }
        if ( '' !== (string) $args['date_from'] ) { $where .= ' AND observed_at >= %s'; $params[] = self::date_boundary( (string) $args['date_from'], false ); }
        if ( '' !== (string) $args['date_to'] ) { $where .= ' AND observed_at <= %s'; $params[] = self::date_boundary( (string) $args['date_to'], true ); }
        $search = trim( sanitize_text_field( (string) $args['search'] ) );
        if ( '' !== $search ) {
            $like = '%' . $wpdb->esc_like( $search ) . '%';
            if ( filter_var( $search, FILTER_VALIDATE_IP ) ) {
                $where .= ' AND (family LIKE %s OR path LIKE %s OR source_hash=%s)';
                array_push( $params, $like, $like, YSEC_Utils::source_identity( $search ) );
            } else {
                $where .= ' AND (family LIKE %s OR path LIKE %s OR country LIKE %s OR user_agent LIKE %s)';
                array_push( $params, $like, $like, $like, $like );
            }
        }
        if ( $include_max && $max_id > 0 ) { $where .= ' AND id<=%d'; $params[] = $max_id; }
        return array( $where, $params );
    }

    public static function job_source_max_id( string $dataset, array $args ): int {
        global $wpdb;
        list( $where, $params ) = self::job_source_where( $dataset, $args );
        $params = array_merge( array( self::table_name() ), $params );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Stable snapshot ceiling for all-matching source response job.
        return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COALESCE(MAX(id),0) FROM %i WHERE 1=1' . $where, $params ) );
    }

    public static function job_source_count( string $dataset, array $args, int $max_id ): int {
        global $wpdb;
        list( $where, $params ) = self::job_source_where( $dataset, $args, true, $max_id );
        $params = array_merge( array( self::table_name() ), $params );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Exact all-matching distinct-source count for administrator background response job.
        return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(DISTINCT source_hash) FROM %i WHERE 1=1' . $where, $params ) );
    }

    public static function job_source_batch( string $dataset, array $args, int $offset, int $max_id, int $limit = 250 ): array {
        global $wpdb;
        $limit = max( 10, min( 1000, $limit ) );
        $offset = max( 0, $offset );
        list( $where, $params ) = self::job_source_where( $dataset, $args, true, $max_id );
        $query_args = array_merge( array( self::table_name() ), $params, array( $limit, $offset ) );
        $sql = 'SELECT source_hash,MAX(family) family,MAX(source_enc) source_enc,MAX(country) country,MAX(user_agent) user_agent,MAX(path) sample_path FROM %i WHERE 1=1' . $where . ' GROUP BY source_hash ORDER BY source_hash ASC LIMIT %d OFFSET %d';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Distinct-source page over a frozen max-id snapshot for a resumable administrator action.
        return $wpdb->get_results( $wpdb->prepare( $sql, $query_args ), ARRAY_A ) ?: array();
    }

    /** A failed dashboard query cannot become a healthy-looking cached trend. */
    private static function analytics_unavailable( int $days ): array {
        return array(
            'valid'=>false, 'days'=>array(), 'families'=>array(), 'countries'=>array(),
            'paths'=>array(), 'methods'=>array(), 'total_hits'=>null,
            'blocked_hits'=>null, 'block_rate'=>null, 'unique_sources_hot'=>null,
            'window_days'=>$days,
        );
    }

    /** Return null only for a failed SQL read; an empty result set is valid. */
    private static function analytics_rows( string $sql ): ?array {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- All eight private analytics callers supply $wpdb->prepare() output; the resulting dashboard aggregate is cached for 60 seconds at analytics().
        $rows = $wpdb->get_results( $sql, ARRAY_A );
        return is_array( $rows ) && empty( $wpdb->last_error ) ? $rows : null;
    }

    public static function analytics( int $days = 7 ): array {
        $days = max( 2, min( 30, $days ) );
        $cache_key = 'ysec_threat_analytics_v1_' . $days;
        $cached = get_transient( $cache_key );
        if ( is_array( $cached ) ) return $cached;
        global $wpdb;
        $events = self::table_name();
        $rollups = YSEC_DB::table( 'event_rollups' );
        $markers = YSEC_DB::table( 'rollup_days' );
        $start_day = gmdate( 'Y-m-d', time() - DAY_IN_SECONDS * ( $days - 1 ) );
        $start_time = $start_day . ' 00:00:00';

        $series = array();
        for ( $i = 0; $i < $days; $i++ ) {
            $day = gmdate( 'Y-m-d', strtotime( $start_day . ' +' . $i . ' day' ) );
            $series[ $day ] = array( 'day'=>$day, 'hits'=>0, 'blocked'=>0 );
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short-lived dashboard analytics over compact rollups.
        $rolled = self::analytics_rows( $wpdb->prepare( 'SELECT day,SUM(hits) hits,SUM(blocked_hits) blocked FROM %i WHERE day >= %s GROUP BY day ORDER BY day ASC', $rollups, $start_day ) );
        if ( null === $rolled ) return self::analytics_unavailable( $days );
        foreach ( $rolled as $row ) if ( isset( $series[ $row['day'] ] ) ) { $series[$row['day']]['hits']+=(int)$row['hits']; $series[$row['day']]['blocked']+=(int)$row['blocked']; }
        // Raw evidence contributes only for days that have not been finalized into rollups, preventing double-counting.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed allowlisted state expression; identifiers and date are prepared.
        $raw = self::analytics_rows( $wpdb->prepare( "SELECT DATE(e.observed_at) day,SUM(e.hit_count) hits,SUM(CASE WHEN e.state IN ('blocked','request_denied','source_blocked','campaign_contained') THEN e.hit_count ELSE 0 END) blocked FROM %i e LEFT JOIN %i d ON DATE(e.observed_at)=d.day WHERE e.observed_at >= %s AND d.day IS NULL GROUP BY DATE(e.observed_at) ORDER BY DATE(e.observed_at) ASC", $events, $markers, $start_time ) );
        if ( null === $raw ) return self::analytics_unavailable( $days );
        foreach ( $raw as $row ) if ( isset( $series[ $row['day'] ] ) ) { $series[$row['day']]['hits']+=(int)$row['hits']; $series[$row['day']]['blocked']+=(int)$row['blocked']; }

        $family = array(); $country = array();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Compact rollup dimensions for dashboard.
        $dimension_rows_0 = self::analytics_rows( $wpdb->prepare( 'SELECT family,SUM(hits) hits FROM %i WHERE day >= %s GROUP BY family', $rollups, $start_day ) );
        if ( null === $dimension_rows_0 ) return self::analytics_unavailable( $days );
        foreach ( $dimension_rows_0 as $row ) $family[(string)$row['family']] = ($family[(string)$row['family']]??0)+(int)$row['hits'];
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Compact rollup dimensions for dashboard.
        $dimension_rows_1 = self::analytics_rows( $wpdb->prepare( "SELECT country,SUM(hits) hits FROM %i WHERE day >= %s AND country<>'' GROUP BY country", $rollups, $start_day ) );
        if ( null === $dimension_rows_1 ) return self::analytics_unavailable( $days );
        foreach ( $dimension_rows_1 as $row ) $country[(string)$row['country']] = ($country[(string)$row['country']]??0)+(int)$row['hits'];
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Unfinalized hot-day family dimensions; marker join avoids rollup duplication.
        $dimension_rows_2 = self::analytics_rows( $wpdb->prepare( "SELECT e.family,SUM(e.hit_count) hits FROM %i e LEFT JOIN %i d ON DATE(e.observed_at)=d.day WHERE e.observed_at >= %s AND d.day IS NULL GROUP BY e.family", $events, $markers, $start_time ) );
        if ( null === $dimension_rows_2 ) return self::analytics_unavailable( $days );
        foreach ( $dimension_rows_2 as $row ) $family[(string)$row['family']] = ($family[(string)$row['family']]??0)+(int)$row['hits'];
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Unfinalized hot-day country dimensions; marker join avoids rollup duplication.
        $dimension_rows_3 = self::analytics_rows( $wpdb->prepare( "SELECT e.country,SUM(e.hit_count) hits FROM %i e LEFT JOIN %i d ON DATE(e.observed_at)=d.day WHERE e.observed_at >= %s AND d.day IS NULL AND e.country<>'' GROUP BY e.country", $events, $markers, $start_time ) );
        if ( null === $dimension_rows_3 ) return self::analytics_unavailable( $days );
        foreach ( $dimension_rows_3 as $row ) $country[(string)$row['country']] = ($country[(string)$row['country']]??0)+(int)$row['hits'];
        arsort( $family ); arsort( $country );
        $total_hits = 0; $blocked_hits = 0;
        foreach ( $series as $day_row ) { $total_hits += (int) $day_row['hits']; $blocked_hits += (int) $day_row['blocked']; }
        $block_rate = $total_hits > 0 ? round( 100 * $blocked_hits / $total_hits, 1 ) : 0.0;
        // Unique-source and method counts intentionally use only hot evidence. Rollups do not retain source identity or request-method detail.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded hot-window distinct-source metric.
        $unique_sources_result = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT source_hash) FROM %i WHERE observed_at >= %s AND source_hash<>'' AND state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained')", $events, $start_time ) );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded hot-window method distribution.
        if ( null === $unique_sources_result || ! empty( $wpdb->last_error ) ) return self::analytics_unavailable( $days );
        $unique_sources = (int) $unique_sources_result;
        $method_rows = self::analytics_rows( $wpdb->prepare( "SELECT method,SUM(hit_count) hits FROM %i WHERE observed_at >= %s AND method<>'' GROUP BY method ORDER BY hits DESC LIMIT 6", $events, $start_time ) );
        if ( null === $method_rows ) return self::analytics_unavailable( $days );
        $methods = array(); foreach ( $method_rows as $method_row ) $methods[(string)$method_row['method']] = (int)$method_row['hits'];
        // Paths intentionally stay hot-evidence only: long-term analytics stores dimensions, not potentially sensitive raw request paths.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded hot-evidence top-path query for local dashboard.
        $paths = self::analytics_rows( $wpdb->prepare( "SELECT path,SUM(hit_count) hits FROM %i WHERE observed_at >= %s AND path<>'' AND state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained') GROUP BY path ORDER BY hits DESC LIMIT 8", $events, $start_time ) );
        if ( null === $paths ) return self::analytics_unavailable( $days );
        $out = array(
            'valid' => true,
            'days' => array_values( $series ),
            'families' => array_slice( $family, 0, 8, true ),
            'countries' => array_slice( $country, 0, 8, true ),
            'paths' => $paths,
            'methods' => $methods,
            'total_hits' => $total_hits,
            'blocked_hits' => $blocked_hits,
            'block_rate' => $block_rate,
            'unique_sources_hot' => $unique_sources,
            'window_days' => $days,
        );
        set_transient( $cache_key, $out, 60 );
        return $out;
    }

    public static function analytics_range( array $args = array(), string $scope = 'events' ): array {
        $scope = in_array( $scope, array( 'events', 'recon', 'firewall' ), true ) ? $scope : 'events';
        $valid_date = static function( $value ): string {
            $value = preg_replace( '/[^0-9\-]/', '', (string) $value );
            if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $value ) ) return '';
            $parts = array_map( 'intval', explode( '-', $value ) );
            return 3 === count( $parts ) && checkdate( $parts[1], $parts[2], $parts[0] ) ? $value : '';
        };
        $date_to = $valid_date( $args['date_to'] ?? '' );
        if ( '' === $date_to ) $date_to = gmdate( 'Y-m-d' );
        $date_from = $valid_date( $args['date_from'] ?? '' );
        if ( '' === $date_from ) $date_from = gmdate( 'Y-m-d', strtotime( $date_to . ' -6 days' ) );
        if ( $date_from > $date_to ) {
            $swap = $date_from;
            $date_from = $date_to;
            $date_to = $swap;
        }

        $history_days = max( 7, min( 1095, absint( YSEC_Utils::option( 'rollup_days', 365 ) ) ) );
        $earliest = gmdate( 'Y-m-d', strtotime( $date_to . ' -' . ( $history_days - 1 ) . ' days' ) );
        $clamped = false;
        if ( $date_from < $earliest ) {
            $date_from = $earliest;
            $clamped = true;
        }
        $start_ts = strtotime( $date_from . ' 00:00:00 UTC' );
        $end_ts = strtotime( $date_to . ' 00:00:00 UTC' );
        $window_days = max( 1, (int) floor( ( $end_ts - $start_ts ) / DAY_IN_SECONDS ) + 1 );

        $series = array();
        for ( $i = 0; $i < $window_days; $i++ ) {
            $day = gmdate( 'Y-m-d', $start_ts + $i * DAY_IN_SECONDS );
            $series[ $day ] = array(
                'day'                => $day,
                'primary'            => 0,
                'secondary'          => 0,
                'event_hits'         => 0,
                'recon_hits'         => 0,
                'request_denies'     => 0,
                'source_containment' => 0,
            );
        }

        global $wpdb;
        $events = self::table_name();
        $rollups = YSEC_DB::table( 'event_rollups' );
        $markers = YSEC_DB::table( 'rollup_days' );
        $rollup_where = 'r.day >= %s AND r.day <= %s';
        $rollup_params = array( $rollups, $date_from, $date_to );
        $raw_where = 'e.observed_at >= %s AND e.observed_at <= %s AND d.day IS NULL';
        $raw_params = array( $events, $markers, $date_from . ' 00:00:00', $date_to . ' 23:59:59' );

        $family = sanitize_key( (string) ( $args['family'] ?? '' ) );
        $severity = sanitize_key( (string) ( $args['severity'] ?? '' ) );
        $state = sanitize_key( (string) ( $args['state'] ?? '' ) );
        if ( '' !== $family ) {
            $rollup_where .= ' AND r.family=%s';
            $rollup_params[] = $family;
            $raw_where .= ' AND e.family=%s';
            $raw_params[] = $family;
        }
        if ( in_array( $severity, array( 'critical', 'high', 'medium', 'low', 'info' ), true ) ) {
            $rollup_where .= ' AND r.severity=%s';
            $rollup_params[] = $severity;
            $raw_where .= ' AND e.severity=%s';
            $raw_params[] = $severity;
        }
        if ( '' !== $state ) {
            $rollup_where .= ' AND r.state=%s';
            $rollup_params[] = $state;
            $raw_where .= ' AND e.state=%s';
            $raw_params[] = $state;
        }
        $rollup_sql = 'SELECT r.day,r.state,SUM(r.hits) hits FROM %i r WHERE ' . $rollup_where . ' GROUP BY r.day,r.state';
        $raw_sql = 'SELECT DATE(e.observed_at) day,e.state,SUM(e.hit_count) hits FROM %i e LEFT JOIN %i d ON DATE(e.observed_at)=d.day WHERE ' . $raw_where . ' GROUP BY DATE(e.observed_at),e.state';
        $combined_sql = "SELECT day,SUM(hits) event_hits,SUM(CASE WHEN state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained') THEN hits ELSE 0 END) recon_hits,SUM(CASE WHEN state IN ('blocked','request_denied') THEN hits ELSE 0 END) request_denies,SUM(CASE WHEN state IN ('source_blocked','campaign_contained') THEN hits ELSE 0 END) source_containment FROM (" . $rollup_sql . ' UNION ALL ' . $raw_sql . ') ysec_daily GROUP BY day ORDER BY day ASC';
        $combined_params = array_merge( $rollup_params, $raw_params );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- One bounded aggregate combines compact rollups with unfinalized hot evidence; all identifiers and values are prepared and fixed state expressions are internal constants.
        $daily = $wpdb->get_results( $wpdb->prepare( $combined_sql, $combined_params ), ARRAY_A ) ?: array();
        foreach ( $daily as $row ) {
            $day = (string) ( $row['day'] ?? '' );
            if ( ! isset( $series[ $day ] ) ) continue;
            $series[ $day ]['event_hits'] += max( 0, (int) ( $row['event_hits'] ?? 0 ) );
            $series[ $day ]['recon_hits'] += max( 0, (int) ( $row['recon_hits'] ?? 0 ) );
            $series[ $day ]['request_denies'] += max( 0, (int) ( $row['request_denies'] ?? 0 ) );
            $series[ $day ]['source_containment'] += max( 0, (int) ( $row['source_containment'] ?? 0 ) );
        }

        $primary_total = 0;
        $secondary_total = 0;
        foreach ( $series as &$row ) {
            if ( 'firewall' === $scope ) {
                $row['primary'] = (int) $row['request_denies'];
                $row['secondary'] = (int) $row['source_containment'];
            } elseif ( 'recon' === $scope ) {
                $row['primary'] = (int) $row['recon_hits'];
                $row['secondary'] = (int) $row['request_denies'] + (int) $row['source_containment'];
            } else {
                $row['primary'] = (int) $row['event_hits'];
                $row['secondary'] = (int) $row['request_denies'] + (int) $row['source_containment'];
            }
            $primary_total += (int) $row['primary'];
            $secondary_total += (int) $row['secondary'];
        }
        unset( $row );
        if ( 'firewall' === $scope ) {
            $denominator = $primary_total + $secondary_total;
            $ratio = $denominator > 0 ? round( 100 * $secondary_total / $denominator, 1 ) : 0.0;
            $primary_label = __( 'Request denies', 'yablonsky-security' );
            $secondary_label = __( 'Source containment', 'yablonsky-security' );
            $ratio_label = __( 'Containment share', 'yablonsky-security' );
        } elseif ( 'recon' === $scope ) {
            $ratio = $primary_total > 0 ? round( 100 * $secondary_total / $primary_total, 1 ) : 0.0;
            $primary_label = __( 'Reconnaissance hits', 'yablonsky-security' );
            $secondary_label = __( 'Contained reconnaissance', 'yablonsky-security' );
            $ratio_label = __( 'Containment ratio', 'yablonsky-security' );
        } else {
            $ratio = $primary_total > 0 ? round( 100 * $secondary_total / $primary_total, 1 ) : 0.0;
            $primary_label = __( 'Security event hits', 'yablonsky-security' );
            $secondary_label = __( 'Blocked / contained', 'yablonsky-security' );
            $ratio_label = __( 'Response ratio', 'yablonsky-security' );
        }

        $period_label = $date_from === $date_to
            ? wp_date( 'M j, Y', $start_ts )
            : wp_date( 'M j', $start_ts ) . ' – ' . wp_date( 'M j, Y', $end_ts );
        return array(
            'days' => array_values( $series ),
            'primary_total' => $primary_total,
            'secondary_total' => $secondary_total,
            'ratio' => $ratio,
            'primary_label' => $primary_label,
            'secondary_label' => $secondary_label,
            'ratio_label' => $ratio_label,
            'date_from' => $date_from,
            'date_to' => $date_to,
            'period_label' => $period_label,
            'window_days' => $window_days,
            'scope' => $scope,
            'clamped' => $clamped,
        );
    }

    public static function storage_summary(): array {
        $cached=get_transient('ysec_event_storage_summary_v2');
        if(is_array($cached))return $cached;
        global $wpdb;
        $table = self::table_name();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short-lived storage summary cache avoids repeating a full-table aggregate during navigation.
        $row = $wpdb->get_row( $wpdb->prepare( 'SELECT COUNT(*) total,SUM(hit_count) hits,SUM(CASE WHEN archived=0 THEN 1 ELSE 0 END) active,SUM(CASE WHEN archived=1 THEN 1 ELSE 0 END) archived,SUM(CASE WHEN reviewed=1 AND archived=0 THEN 1 ELSE 0 END) reviewed FROM %i', $table ), ARRAY_A );
        // Unknown is not zero. A failed DB read must never create a healthy-looking
        // cached storage summary; the next request can immediately retry.
        if ( ! is_array( $row ) || ! empty( $wpdb->last_error ) ) {
            return array( 'valid'=>false, 'total'=>0, 'hits'=>0, 'compressed'=>0, 'active'=>0, 'archived'=>0, 'reviewed'=>0 );
        }
        $total = (int) ( $row['total'] ?? 0 );
        $hits  = (int) ( $row['hits'] ?? 0 );
        $out=array(
            'valid'      => true,
            'total'      => $total,
            'hits'       => $hits,
            'compressed' => max( 0, $hits - $total ),
            'active'     => (int) ( $row['active'] ?? 0 ),
            'archived'   => (int) ( $row['archived'] ?? 0 ),
            'reviewed'   => (int) ( $row['reviewed'] ?? 0 ),
        );
        set_transient('ysec_event_storage_summary_v2',$out,15);
        return $out;
    }

    private static function table_name(): string {
        return YSEC_DB::table( 'events' );
    }

    public static function bulk_action( array $ids, string $action ): int {
        global $wpdb;
        $ids = array_values( array_unique( array_filter( array_map( 'absint', $ids ) ) ) );
        if ( ! $ids ) return 0;
        $ids = array_slice( $ids, 0, 100 );
        $table = self::table_name();
        $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
        if ( 'review' === $action ) {
            $sql = "UPDATE %i SET reviewed=1 WHERE id IN ($placeholders)";
            $params = array_merge( array( $table ), $ids );
        } elseif ( 'archive' === $action ) {
            $sql = "UPDATE %i SET archived=1 WHERE id IN ($placeholders)";
            $params = array_merge( array( $table ), $ids );
        } elseif ( 'delete' === $action ) {
            $sql = "DELETE FROM %i WHERE id IN ($placeholders)";
            $params = array_merge( array( $table ), $ids );
        } else {
            return 0;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Administrator-confirmed maintenance against dedicated plugin table; identifiers and IDs are prepared.
        $changed = $wpdb->query( $wpdb->prepare( $sql, $params ) );
        return false === $changed ? 0 : (int) $changed;
    }

    public static function mark_false_positive( array $ids ): int {
        global $wpdb;
        $ids = array_values( array_unique( array_filter( array_map( 'absint', $ids ) ) ) );
        if ( ! $ids ) return 0;
        $ids = array_slice( $ids, 0, 100 );
        $changed = 0;
        foreach ( $ids as $id ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Administrator-selected evidence disposition in the dedicated event table.
            $raw = $wpdb->get_var( $wpdb->prepare( 'SELECT details FROM %i WHERE id=%d', self::table_name(), $id ) );
            $details = json_decode( (string) $raw, true );
            if ( ! is_array( $details ) ) $details = array();
            $details['disposition'] = 'false_positive';
            $details['disposition_at'] = current_time( 'mysql', true );
            $details['disposition_actor'] = get_current_user_id();
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Administrator-selected evidence disposition in the dedicated event table.
            $ok = $wpdb->update( self::table_name(), array( 'reviewed'=>1, 'details'=>wp_json_encode( $details ) ), array( 'id'=>$id ), array( '%d','%s' ), array( '%d' ) );
            if ( false !== $ok ) $changed += (int) $ok;
        }
        return $changed;
    }


    /**
     * Reconcile historical malware-finding evidence after a persisted finding is
     * proven to be a bounded runtime artifact by the current scanner contract.
     *
     * The raw event is preserved as archived verified evidence. If its day has
     * already been compacted into analytics rollups, move the aggregate from the
     * original suspicious state into a verified state so historical event volume
     * is preserved without inflating reconnaissance pressure.
     */
    public static function resolve_verified_malware_artifacts( array $paths ): int {
        global $wpdb;
        $paths = array_values( array_unique( array_filter( array_map( static function ( $path ) {
            $path = ltrim( wp_normalize_path( (string) $path ), '/' );
            return '' !== $path && 0 === strpos( $path, 'wp-content/' ) ? $path : '';
        }, $paths ) ) ) );
        if ( ! $paths ) return 0;

        $changed = 0;
        $events = self::table_name();
        $rollups = YSEC_DB::table( 'event_rollups' );
        $markers = YSEC_DB::table( 'rollup_days' );

        foreach ( array_chunk( $paths, 100 ) as $chunk ) {
            $placeholders = implode( ',', array_fill( 0, count( $chunk ), '%s' ) );
            $params = array_merge( array( $events ), $chunk );
            $sql = "SELECT id,observed_at,hit_count,severity,state,country,path,details FROM %i WHERE archived=0 AND type='malware_finding' AND family='malware' AND path IN ($placeholders)";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- One-time evidence reconciliation against exact scanner-verified plugin paths; identifier and values are prepared.
            $rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A ) ?: array();

            foreach ( $rows as $row ) {
                $details = json_decode( (string) ( $row['details'] ?? '' ), true );
                if ( ! is_array( $details ) ) $details = array();
                $rule = (string) ( $details['rule'] ?? '' );
                if ( ! in_array( $rule, array( 'executable_in_uploads', 'webshell_signature' ), true ) ) continue;

                $id = absint( $row['id'] ?? 0 );
                if ( ! $id ) continue;
                $old_state = sanitize_key( (string) ( $row['state'] ?? 'suspicious' ) );
                $severity = sanitize_key( (string) ( $row['severity'] ?? 'high' ) );
                $country = strtoupper( substr( preg_replace( '/[^A-Za-z]/', '', (string) ( $row['country'] ?? '' ) ), 0, 2 ) );
                $hits = max( 0, (int) ( $row['hit_count'] ?? 0 ) );
                $day = substr( (string) ( $row['observed_at'] ?? '' ), 0, 10 );

                $details['disposition'] = 'verified_runtime_artifact';
                $details['disposition_at'] = current_time( 'mysql', true );
                $details['disposition_actor'] = get_current_user_id();

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Scanner-verified evidence disposition in the plugin-owned event table.
                $updated = $wpdb->update(
                    $events,
                    array( 'state'=>'verified', 'reviewed'=>1, 'archived'=>1, 'details'=>wp_json_encode( $details ) ),
                    array( 'id'=>$id ),
                    array( '%s','%d','%d','%s' ),
                    array( '%d' )
                );
                if ( false === $updated ) continue;
                $changed += (int) $updated;

                if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $day ) ) continue;
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Determine whether this exact day has already been finalized into compact rollups.
                $finalized = (bool) $wpdb->get_var( $wpdb->prepare( 'SELECT 1 FROM %i WHERE day=%s LIMIT 1', $markers, $day ) );
                if ( ! $finalized ) continue;

                // Move, rather than delete, the compact historical evidence:
                // event volume remains true while threat-pressure states are corrected.
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Exact rollup correction after bounded false-positive reconciliation.
                $wpdb->query( $wpdb->prepare(
                    'UPDATE %i SET hits=GREATEST(0,hits-%d),records=GREATEST(0,records-1),blocked_hits=GREATEST(0,blocked_hits-%d) WHERE day=%s AND family=%s AND severity=%s AND state=%s AND country=%s',
                    $rollups,
                    $hits,
                    in_array( $old_state, array( 'blocked','request_denied','source_blocked','campaign_contained' ), true ) ? $hits : 0,
                    $day,
                    'malware',
                    $severity,
                    $old_state,
                    $country
                ) );
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Remove empty compact dimension after exact evidence move.
                $wpdb->query( $wpdb->prepare(
                    'DELETE FROM %i WHERE day=%s AND family=%s AND severity=%s AND state=%s AND country=%s AND hits=0 AND records=0',
                    $rollups, $day, 'malware', $severity, $old_state, $country
                ) );
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Preserve historical event volume in a verified, non-threat compact dimension.
                $wpdb->query( $wpdb->prepare(
                    'INSERT INTO %i (day,family,severity,state,country,hits,records,blocked_hits) VALUES (%s,%s,%s,%s,%s,%d,1,0) ON DUPLICATE KEY UPDATE hits=hits+VALUES(hits),records=records+1',
                    $rollups, $day, 'malware', $severity, 'verified', $country, $hits
                ) );
            }
        }

        if ( $changed > 0 ) {
            delete_transient( 'ysec_event_filter_options_v2' );
            delete_transient( 'ysec_event_summary_24h_v2' );
            delete_transient( 'ysec_event_storage_summary_v2' );
            delete_transient( 'ysec_recon_summary_v1_24' );
            delete_transient( 'ysec_threat_analytics_v1_7' );
            delete_transient( 'ysec_threat_analytics_v1_30' );
        }
        return $changed;
    }

    public static function sources_for_ids( array $ids ): array {
        global $wpdb;
        $ids = array_values( array_unique( array_filter( array_map( 'absint', $ids ) ) ) );
        if ( ! $ids ) return array();
        $ids = array_slice( $ids, 0, 100 );
        $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
        $params = array_merge( array( self::table_name() ), $ids );
        $sql = "SELECT DISTINCT source_hash,family FROM %i WHERE id IN ($placeholders) AND source_hash<>'' AND state IN ('suspicious','blocked','request_denied','source_blocked','campaign_contained')";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Administrator-selected event IDs; identifier and values are prepared.
        return $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A ) ?: array();
    }

    public static function requests_for_ids( array $ids ): array {
        global $wpdb;
        $ids = array_values( array_unique( array_filter( array_map( 'absint', $ids ) ) ) );
        if ( ! $ids ) return array();
        $ids = array_slice( $ids, 0, 100 );
        $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
        $params = array_merge( array( self::table_name() ), $ids );
        $sql = "SELECT id,method,path,family,state FROM %i WHERE id IN ($placeholders) AND state IN ('blocked','request_denied','source_blocked','campaign_contained')";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Administrator-selected event IDs; identifier and values are prepared.
        return $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A ) ?: array();
    }

    public static function archive_campaign( string $source_hash, string $family ): int {
        global $wpdb;
        if ( ! preg_match( '/^[a-f0-9]{64}$/', $source_hash ) ) return 0;
        $family = sanitize_key( $family );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Administrator-confirmed archive of a derived campaign in the dedicated event table.
        $changed = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET archived=1 WHERE source_hash=%s AND family=%s AND archived=0', self::table_name(), $source_hash, $family ) );
        return false === $changed ? 0 : (int) $changed;
    }

    public static function archive_before( string $date ): int {
        global $wpdb;
        $cut = self::date_boundary( $date, false );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Administrator-confirmed archive maintenance on dedicated event table.
        $changed = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET archived=1 WHERE archived=0 AND COALESCE(last_seen_at,observed_at) < %s', self::table_name(), $cut ) );
        return false === $changed ? 0 : (int) $changed;
    }

    public static function delete_archived(): int {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Administrator-confirmed purge of archived records from dedicated event table.
        $changed = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE archived=1', self::table_name() ) );
        return false === $changed ? 0 : (int) $changed;
    }

    private static function date_boundary( string $date, bool $end ): string {
        $date = preg_replace( '/[^0-9\-]/', '', $date );
        if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date ) ) {
            return $end ? '9999-12-31 23:59:59' : '1970-01-01 00:00:00';
        }
        try {
            $local = new DateTimeImmutable( $date . ( $end ? ' 23:59:59' : ' 00:00:00' ), wp_timezone() );
            return $local->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s' );
        } catch ( Exception $e ) {
            return $end ? $date . ' 23:59:59' : $date . ' 00:00:00';
        }
    }

    public static function observe_request(): void {
        if ( is_admin() ) {
            return;
        }

        if ( YSEC_Utils::option( 'observe_requests', 1 ) ) {
            $path   = YSEC_Utils::normalize_path( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/' );
            $method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
            $c      = YSEC_Classifier::classify( $path, $method );
            $extended = (bool) YSEC_Utils::option( 'extended_telemetry', 0 );

            if ( 'probe' === $c['class'] || ( $extended && ( 'technical' === $c['class'] || ( 'content' === $c['class'] && is_404() ) ) ) ) {
                self::$request_signals[] = array(
                    'origin'     => 'observer',
                    'class'      => sanitize_key( $c['class'] ),
                    'family'     => sanitize_key( $c['family'] ),
                    'confidence' => sanitize_key( $c['confidence'] ),
                    'severity'   => sanitize_key( $c['severity'] ),
                );
            }

            if ( 'probe' === $c['class'] && $ip = YSEC_Utils::client_ip() ) {
                YSEC_Firewall::observe_recon( YSEC_Utils::fingerprint( $ip ), $c );
            }
        }
    }

    private static function severity_rank( string $severity ): int {
        return array( 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 )[ $severity ] ?? 0;
    }

    private static function contains_probe( array $signals ): bool {
        foreach ( $signals as $signal ) {
            if ( 'probe' === ( $signal['class'] ?? '' ) || 'waf' === ( $signal['origin'] ?? '' ) ) {
                return true;
            }
        }
        return false;
    }
}
