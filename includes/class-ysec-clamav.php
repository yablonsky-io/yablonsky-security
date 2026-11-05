<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Optional local ClamAV/clamd signature provider. No remote service and no shell execution. */
final class YSEC_ClamAV {
    private const SOCKETS = array(
        '/run/clamav/clamd.ctl',
        '/var/run/clamav/clamd.ctl',
        '/run/clamd.scan/clamd.sock',
        '/var/run/clamd.scan/clamd.sock',
    );

    private const STREAM_CHUNK_BYTES = 16384;
    private const DEFAULT_STREAM_MAX_BYTES = 25165824; // 24 MiB; stays below common clamd StreamMaxLength defaults.
    private const INSTREAM_PREFERENCE_TRANSIENT = 'ysec_clamav_prefer_instream_v1';
    private static $prefer_instream = false;

    public static function socket_path(): string {
        if ( defined( 'YSEC_CLAMD_SOCKET' ) ) {
            $configured = (string) YSEC_CLAMD_SOCKET;
            if ( '' !== $configured ) return $configured;
        }
        foreach ( self::SOCKETS as $socket ) if ( file_exists( $socket ) ) return $socket;
        return '';
    }

    public static function status(): array {
        $socket = self::socket_path();
        $responsive = '' !== $socket ? self::ping( $socket ) : false;
        return array(
            'available'  => $responsive,
            'socket'     => $socket,
            'responsive' => $responsive,
            'mode'       => 'local_clamd',
        );
    }

    private static function ping( string $socket ): bool {
        $client = self::connect( $socket, 0.35, 1 );
        if ( ! is_resource( $client ) ) return false;
        $ok = self::write_all( $client, "zPING\0" );
        $reply = $ok ? @stream_socket_recvfrom( $client, 64 ) : false;
        self::close_stream( $client );
        return is_string( $reply ) && 'PONG' === trim( str_replace( "\0", '', $reply ) );
    }

    /**
     * Ask the local clamd daemon to scan a server-local path.
     *
     * Direct SCAN is preferred because clamd reads the file without copying it
     * through PHP. Virtual-host directory ACLs can make the socket reachable
     * while preventing the clamav daemon user from traversing a site's path.
     * In that case YSec falls back to clamd INSTREAM and sends bounded chunks
     * through the same local Unix socket, using the PHP-FPM process's existing
     * read access without loading the complete file into PHP memory.
     */
    public static function scan_file( string $path ): array {
        $socket = self::socket_path();
        if ( '' === $socket || ! is_file( $path ) || ! is_readable( $path ) ) return array( 'status'=>'standby', 'transport'=>'' );
        if ( false !== strpos( $path, "\0" ) || false !== strpos( $path, "\n" ) || false !== strpos( $path, "\r" ) ) return array( 'status'=>'unavailable', 'transport'=>'', 'error'=>'invalid_path' );

        $prefer_instream = self::$prefer_instream || (bool) get_transient( self::INSTREAM_PREFERENCE_TRANSIENT );
        $direct = $prefer_instream
            ? array( 'status'=>'unavailable', 'transport'=>'scan', 'error'=>'direct_path_access_unavailable' )
            : self::scan_path( $socket, $path );
        if ( in_array( (string) ( $direct['status'] ?? '' ), array( 'clean', 'infected' ), true ) ) return $direct;
        if ( self::is_path_access_error( $direct ) ) {
            self::$prefer_instream = true;
            set_transient( self::INSTREAM_PREFERENCE_TRANSIENT, 1, 30 * MINUTE_IN_SECONDS );
        }

        $size = @filesize( $path );
        $stream_limit = defined( 'YSEC_CLAMD_STREAM_MAX_BYTES' ) ? max( 1048576, (int) YSEC_CLAMD_STREAM_MAX_BYTES ) : self::DEFAULT_STREAM_MAX_BYTES;
        if ( false === $size || $size > $stream_limit ) {
            $direct['fallback'] = 'stream_size_limit';
            $direct['stream_limit'] = $stream_limit;
            return $direct;
        }

        $stream = self::scan_stream( $socket, $path );
        if ( in_array( (string) ( $stream['status'] ?? '' ), array( 'clean', 'infected' ), true ) ) {
            $stream['direct_status'] = (string) ( $direct['status'] ?? '' );
            $stream['direct_error'] = (string) ( $direct['error'] ?? $direct['raw'] ?? '' );
            return $stream;
        }

        if ( empty( $stream['error'] ) && ! empty( $direct['error'] ) ) $stream['error'] = (string) $direct['error'];
        return $stream;
    }

    private static function is_path_access_error( array $result ): bool {
        $message = strtolower( (string) ( $result['error'] ?? $result['raw'] ?? '' ) );
        return false !== strpos( $message, 'permission denied' )
            || false !== strpos( $message, 'access denied' )
            || false !== strpos( $message, 'lstat' )
            || false !== strpos( $message, 'cannot access' );
    }

    private static function scan_path( string $socket, string $path ): array {
        $client = self::connect( $socket, 0.75, 5 );
        if ( ! is_resource( $client ) ) return array( 'status'=>'unavailable', 'transport'=>'scan', 'error'=>'socket_connect_failed' );

        $command = "zSCAN " . $path . "\0";
        if ( ! self::write_all( $client, $command ) ) {
            self::close_stream( $client );
            return array( 'status'=>'unavailable', 'transport'=>'scan', 'error'=>'socket_write_failed' );
        }

        $reply = @stream_socket_recvfrom( $client, 8192 );
        self::close_stream( $client );
        return self::parse_reply( $reply, 'scan' );
    }

    private static function scan_stream( string $socket, string $path ): array {
        $handle = self::open_file_stream( $path );
        if ( ! is_resource( $handle ) ) return array( 'status'=>'unavailable', 'transport'=>'instream', 'error'=>'file_open_failed' );

        $client = self::connect( $socket, 0.75, 12 );
        if ( ! is_resource( $client ) ) {
            self::close_stream( $handle );
            return array( 'status'=>'unavailable', 'transport'=>'instream', 'error'=>'socket_connect_failed' );
        }

        if ( ! self::write_all( $client, "zINSTREAM\0" ) ) {
            self::close_stream( $handle );
            self::close_stream( $client );
            return array( 'status'=>'unavailable', 'transport'=>'instream', 'error'=>'socket_write_failed' );
        }

        $ok = true;
        while ( ! feof( $handle ) ) {
            $chunk = self::read_file_chunk( $handle, self::STREAM_CHUNK_BYTES );
            if ( false === $chunk ) {
                $ok = false;
                break;
            }
            if ( '' === $chunk ) continue;
            if ( ! self::write_all( $client, pack( 'N', strlen( $chunk ) ) . $chunk ) ) {
                $ok = false;
                break;
            }
        }
        self::close_stream( $handle );

        if ( $ok ) $ok = self::write_all( $client, pack( 'N', 0 ) );
        if ( ! $ok ) {
            self::close_stream( $client );
            return array( 'status'=>'unavailable', 'transport'=>'instream', 'error'=>'stream_write_failed' );
        }

        $reply = @stream_socket_recvfrom( $client, 8192 );
        self::close_stream( $client );
        return self::parse_reply( $reply, 'instream' );
    }

    private static function connect( string $socket, float $connect_timeout, int $read_timeout ) {
        $errno = 0;
        $errstr = '';
        $client = @stream_socket_client( 'unix://' . $socket, $errno, $errstr, $connect_timeout, STREAM_CLIENT_CONNECT );
        if ( ! is_resource( $client ) ) return false;
        stream_set_timeout( $client, $read_timeout );
        return $client;
    }

    private static function write_all( $stream, string $payload ): bool {
        $length = strlen( $payload );
        $offset = 0;
        while ( $offset < $length ) {
            $written = self::write_stream( $stream, substr( $payload, $offset ) );
            if ( false === $written || 0 === $written ) return false;
            $offset += $written;
        }
        return true;
    }

    /**
     * Native stream wrappers are intentionally used for the clamd Unix-socket
     * protocol and bounded file streaming. WP_Filesystem does not expose
     * Unix-domain socket I/O or chunked stream primitives, and loading a file
     * through get_contents() would defeat the scanner's bounded-memory model.
     */
    private static function close_stream( $stream ): void {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Required for Unix-socket/file stream lifecycle; WP_Filesystem has no resource close primitive.
        fclose( $stream );
    }

    private static function open_file_stream( string $path ) {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Required for bounded local INSTREAM reads; WP_Filesystem get_contents() would load the complete file.
        return @fopen( $path, 'rb' );
    }

    private static function read_file_chunk( $stream, int $length ) {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Required for bounded local INSTREAM chunks; WP_Filesystem has no chunked read API.
        return fread( $stream, $length );
    }

    private static function write_stream( $stream, string $payload ) {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Required by the clamd binary INSTREAM/Unix-socket protocol; WP_Filesystem cannot write socket resources.
        return @fwrite( $stream, $payload );
    }

    private static function parse_reply( $reply, string $transport ): array {
        if ( ! is_string( $reply ) || '' === $reply ) return array( 'status'=>'unknown', 'transport'=>$transport, 'raw'=>'', 'error'=>'empty_reply' );

        $reply = trim( str_replace( "\0", '', $reply ) );
        if ( preg_match( '/: (.+) FOUND$/', $reply, $m ) ) {
            return array( 'status'=>'infected', 'transport'=>$transport, 'signature'=>sanitize_text_field( $m[1] ), 'raw'=>sanitize_text_field( $reply ) );
        }
        if ( str_ends_with( $reply, ' OK' ) ) return array( 'status'=>'clean', 'transport'=>$transport, 'raw'=>sanitize_text_field( $reply ) );
        if ( preg_match( '/: (.+) ERROR$/', $reply, $m ) ) {
            return array( 'status'=>'unavailable', 'transport'=>$transport, 'raw'=>sanitize_text_field( $reply ), 'error'=>sanitize_text_field( $m[1] ) );
        }
        return array( 'status'=>'unknown', 'transport'=>$transport, 'raw'=>sanitize_text_field( $reply ), 'error'=>'unexpected_reply' );
    }
}
