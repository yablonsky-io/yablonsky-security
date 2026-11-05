<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Account-scope querying and bounded administrative actions.
 * Keeps account bulk operations independent from table pagination.
 */
final class YSEC_Accounts {
    public static function filtered_ids( array $filters = array() ): array {
        $search = trim( sanitize_text_field( (string) ( $filters['search'] ?? '' ) ) );
        $role = sanitize_key( (string) ( $filters['role'] ?? '' ) );
        $session_status = sanitize_key( (string) ( $filters['session_status'] ?? '' ) );
        $two_factor = sanitize_key( (string) ( $filters['two_factor'] ?? '' ) );
        $account_state = sanitize_key( (string) ( $filters['account_state'] ?? '' ) );
        $orderby = in_array( $filters['orderby'] ?? '', array( 'display_name', 'user_login', 'ID' ), true ) ? (string) $filters['orderby'] : 'display_name';
        $order = 'DESC' === strtoupper( (string) ( $filters['order'] ?? 'ASC' ) ) ? 'DESC' : 'ASC';

        $query_args = array( 'number'=>-1, 'fields'=>'ID', 'orderby'=>$orderby, 'order'=>$order, 'count_total'=>false );
        if ( '' !== $search ) $query_args['search'] = '*' . $search . '*';
        if ( '' !== $role && isset( wp_roles()->roles[ $role ] ) ) $query_args['role'] = $role;
        $candidate_ids = ( new WP_User_Query( $query_args ) )->get_results();
        $filtered = array();
        $now = time();
        foreach ( $candidate_ids as $candidate_id ) {
            $user_id = absint( $candidate_id );
            if ( ! $user_id ) continue;
            if ( '' !== $two_factor ) {
                $has_2fa = '' !== (string) get_user_meta( $user_id, 'ysec_totp_secret', true );
                if ( 'enabled' === $two_factor && ! $has_2fa ) continue;
                if ( 'disabled' === $two_factor && $has_2fa ) continue;
            }
            if ( '' !== $account_state ) {
                $pending = (bool) get_user_meta( $user_id, 'ysec_registration_pending', true );
                $locked_until = absint( get_user_meta( $user_id, 'ysec_account_locked_until', true ) );
                if ( $locked_until && $locked_until <= $now ) {
                    delete_user_meta( $user_id, 'ysec_account_locked_until' );
                    $locked_until = 0;
                }
                $state = $pending ? 'pending' : ( $locked_until > $now ? 'locked' : 'active' );
                if ( $state !== $account_state ) continue;
            }
            if ( '' !== $session_status ) {
                $has_sessions = ! empty( self::active_sessions( $user_id ) );
                if ( 'active' === $session_status && ! $has_sessions ) continue;
                if ( 'none' === $session_status && $has_sessions ) continue;
            }
            $filtered[] = $user_id;
        }
        return $filtered;
    }


    public static function query_page( array $filters, int $page, int $per_page ): array {
        $page = max( 1, $page );
        $per_page = max( 10, min( 100, $per_page ) );
        $session_status = sanitize_key( (string) ( $filters['session_status'] ?? '' ) );
        $two_factor = sanitize_key( (string) ( $filters['two_factor'] ?? '' ) );
        $account_state = sanitize_key( (string) ( $filters['account_state'] ?? '' ) );

        // Default directory browsing, search and role filtering can stay inside
        // WP_User_Query pagination. Only the security-state filters require a
        // bounded in-PHP post-filter because WordPress sessions are not queryable
        // in one portable SQL expression.
        if ( '' === $session_status && '' === $two_factor && '' === $account_state ) {
            $search = trim( sanitize_text_field( (string) ( $filters['search'] ?? '' ) ) );
            $role = sanitize_key( (string) ( $filters['role'] ?? '' ) );
            $orderby = in_array( $filters['orderby'] ?? '', array( 'display_name', 'user_login', 'ID' ), true ) ? (string) $filters['orderby'] : 'display_name';
            $order = 'DESC' === strtoupper( (string) ( $filters['order'] ?? 'ASC' ) ) ? 'DESC' : 'ASC';
            $args = array(
                'number'      => $per_page,
                'offset'      => ( $page - 1 ) * $per_page,
                'fields'      => 'ID',
                'orderby'     => $orderby,
                'order'       => $order,
                'count_total' => true,
            );
            if ( '' !== $search ) $args['search'] = '*' . $search . '*';
            if ( '' !== $role && isset( wp_roles()->roles[ $role ] ) ) $args['role'] = $role;
            $query = new WP_User_Query( $args );
            return array(
                'ids'   => array_values( array_map( 'absint', $query->get_results() ) ),
                'total' => max( 0, (int) $query->get_total() ),
            );
        }

        $ids = self::filtered_ids( $filters );
        return array(
            'ids'   => array_slice( $ids, ( $page - 1 ) * $per_page, $per_page ),
            'total' => count( $ids ),
        );
    }

    public static function count( array $filters = array() ): int {
        return count( self::filtered_ids( $filters ) );
    }

    public static function batch( array $filters, int $offset, int $limit ): array {
        $ids = self::filtered_ids( $filters );
        return array_slice( $ids, max( 0, $offset ), max( 1, min( 1000, $limit ) ) );
    }

    public static function apply( int $user_id, string $action ): bool {
        if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) return false;
        $actor = get_current_user_id();
        switch ( $action ) {
            case 'revoke_sessions':
                $manager = WP_Session_Tokens::get_instance( $user_id );
                if ( $user_id === $actor ) $manager->destroy_others( wp_get_session_token() );
                else $manager->destroy_all();
                return true;
            case 'lock_60':
            case 'lock_240':
            case 'lock_1440':
                if ( $user_id === $actor ) return false;
                $minutes = (int) substr( $action, 5 );
                $until = time() + $minutes * MINUTE_IN_SECONDS;
                update_user_meta( $user_id, 'ysec_account_locked_until', $until );
                WP_Session_Tokens::get_instance( $user_id )->destroy_all();
                return true;
            case 'unlock':
                delete_user_meta( $user_id, 'ysec_account_locked_until' );
                return true;
            case 'approve':
                if ( ! get_user_meta( $user_id, 'ysec_registration_pending', true ) ) return false;
                delete_user_meta( $user_id, 'ysec_registration_pending' );
                return true;
        }
        return false;
    }

    public static function allowed_bulk_action( string $action ): bool {
        return in_array( $action, array( 'revoke_sessions', 'lock_60', 'lock_240', 'lock_1440', 'unlock', 'approve' ), true );
    }

    public static function label_for_action( string $action ): string {
        $labels = array(
            'revoke_sessions' => __( 'Revoke sessions', 'yablonsky-security' ),
            'lock_60'         => __( 'Lock 60 minutes', 'yablonsky-security' ),
            'lock_240'        => __( 'Lock 4 hours', 'yablonsky-security' ),
            'lock_1440'       => __( 'Lock 24 hours', 'yablonsky-security' ),
            'unlock'          => __( 'Unlock accounts', 'yablonsky-security' ),
            'approve'         => __( 'Approve pending registrations', 'yablonsky-security' ),
        );
        return $labels[ $action ] ?? $action;
    }

    private static function active_sessions( int $user_id ): array {
        $sessions = WP_Session_Tokens::get_instance( $user_id )->get_all();
        $now = time();
        return array_values( array_filter( $sessions, static fn( $session ) => ! empty( $session['expiration'] ) && (int) $session['expiration'] > $now ) );
    }
}
