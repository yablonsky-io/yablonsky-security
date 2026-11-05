<?php
/**
 * Bounded, read-only reader for YSec's own compiled GNU gettext catalogs.
 *
 * WordPress remains responsible for selecting the admin locale and resolving
 * translations normally. This fallback is used only if that resolution returns
 * the original English msgid (for example, after a third-party i18n override).
 * It never touches another text domain or global locale, and makes no network
 * or database calls.
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class YSEC_Bundled_MO {
    private array $entries = array();
    private string $plural_expression = '';
    private int $plural_count = 2;
    private $plural_rules = null;

    public function import_from_file( string $filename ): bool {
        // The 36 bundled catalogs are below 300 KB. Fail closed on anything
        // unusually large, empty or not a regular readable file.
        if ( ! is_file( $filename ) || ! is_readable( $filename ) ) {
            return false;
        }
        $size = filesize( $filename );
        if ( false === $size || $size < 28 || $size > 2 * 1024 * 1024 ) {
            return false;
        }
        $data = file_get_contents( $filename );
        if ( ! is_string( $data ) || strlen( $data ) !== $size ) {
            return false;
        }
        $magic = unpack( 'V', substr( $data, 0, 4 ) );
        if ( ! is_array( $magic ) ) {
            return false;
        }
        if ( 0x950412de === $magic[1] ) {
            $endian = 'V';
        } elseif ( 0xde120495 === $magic[1] ) {
            $endian = 'N';
        } else {
            return false;
        }
        $revision = self::read_uint( $data, 4, $endian );
        $count = self::read_uint( $data, 8, $endian );
        $ids = self::read_uint( $data, 12, $endian );
        $texts = self::read_uint( $data, 16, $endian );
        if ( 0 !== $revision || null === $count || $count < 1 || $count > 10000 ||
            null === $ids || null === $texts || $ids > $size - 8 * $count ||
            $texts > $size - 8 * $count ) {
            return false;
        }
        $catalog = array();
        for ( $i = 0; $i < $count; ++$i ) {
            $orig_len = self::read_uint( $data, $ids + $i * 8, $endian );
            $orig_at = self::read_uint( $data, $ids + $i * 8 + 4, $endian );
            $trans_len = self::read_uint( $data, $texts + $i * 8, $endian );
            $trans_at = self::read_uint( $data, $texts + $i * 8 + 4, $endian );
            if ( null === $orig_len || null === $orig_at || null === $trans_len ||
                null === $trans_at || $orig_at > $size || $trans_at > $size ||
                $orig_len > $size - $orig_at || $trans_len > $size - $trans_at ) {
                return false;
            }
            $id = substr( $data, $orig_at, $orig_len );
            $text = substr( $data, $trans_at, $trans_len );
            if ( '' !== $id && '' !== $text ) {
                $catalog[ $id ] = $text;
            } elseif ( '' === $id ) {
                if ( preg_match( '/^Plural-Forms:\s*[^\r\n]*?nplurals\s*=\s*(\d+)\s*;\s*plural\s*=\s*([^;\r\n]+)/mi', $text, $matches ) ) {
                    $this->plural_count = max( 1, min( 8, (int) $matches[1] ) );
                    $this->plural_expression = trim( $matches[2] );
                }
            }
        }
        if ( empty( $catalog ) ) {
            return false;
        }
        $this->entries = $catalog;
        return true;
    }

    private static function read_uint( string $data, int $pos, string $endian ): ?int {
        if ( $pos < 0 || $pos + 4 > strlen( $data ) ) {
            return null;
        }
        $item = unpack( $endian, substr( $data, $pos, 4 ) );
        return isset( $item[1] ) ? (int) $item[1] : null;
    }

    public function translate( string $original, ?string $context = null ): string {
        $key = null === $context ? $original : $context . "\x04" . $original;
        return isset( $this->entries[ $key ] ) ? $this->entries[ $key ] : $original;
    }

    public function translate_plural( string $singular, string $plural, $number, ?string $context = null ): string {
        $key = $singular . "\0" . $plural;
        if ( null !== $context ) {
            $key = $context . "\x04" . $key;
        }
        if ( ! isset( $this->entries[ $key ] ) ) {
            return 1 === (int) $number ? $singular : $plural;
        }
        $variants = explode( "\0", $this->entries[ $key ] );
        $index = 1 === (int) $number ? 0 : 1;
        if ( '' !== $this->plural_expression && class_exists( 'Plural_Forms' ) ) {
            try {
                if ( null === $this->plural_rules ) {
                    $this->plural_rules = new Plural_Forms( $this->plural_expression );
                }
                $index = (int) $this->plural_rules->get( (int) $number );
            } catch ( Throwable $error ) {
                $index = 1 === (int) $number ? 0 : 1;
            }
        }
        $index = max( 0, min( $this->plural_count - 1, $index ) );
        return $variants[ $index ] ?? end( $variants );
    }
}
