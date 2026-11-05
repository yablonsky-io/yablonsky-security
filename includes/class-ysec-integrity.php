<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Integrity  {
    public static function boot(): void  {
        add_action('ysec_daily_maintenance',array(__CLASS__,'scheduled'));
        add_action('upgrader_process_complete',array(__CLASS__,'maintenance_baseline'),20,2);
    }
    private static function files(): array  {
        $roots=array(WP_PLUGIN_DIR,get_theme_root(),ABSPATH.'wp-admin',ABSPATH.'wp-includes');
        $out=[];
        foreach($roots as $root) {
            if(!is_dir($root))continue;
            $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS));
            foreach($it as $f) {
                if(!$f->isFile()||$f->getSize()>3*1024*1024)continue;
                $ext=strtolower($f->getExtension());
                if(!in_array($ext,array('php','js','css','json'),true))continue;
                $p=$f->getPathname();
                $rel=str_starts_with($p,ABSPATH)?substr($p,strlen(ABSPATH)):$p;
                $out[$rel]=$p;
                if(count($out)>=20000)break 2;
            }
        }
        ksort($out);
        return $out;
    }

    public static function ignored_paths(): array {
        $raw = get_option( 'ysec_integrity_ignores', array() );
        return is_array( $raw ) ? array_values( array_filter( array_map( 'strval', $raw ) ) ) : array();
    }
    public static function sanitize_ignores( string $raw ): array {
        $out = array();
        foreach ( preg_split( '/[\r\n]+/', $raw ) ?: array() as $line ) {
            $line = trim( wp_normalize_path( $line ) );
            if ( '' === $line ) continue;
            $line = ltrim( $line, '/' );
            if ( str_contains( $line, '..' ) || preg_match( '/[\x00-\x1F]/', $line ) ) continue;
            if ( ! preg_match( '#^[A-Za-z0-9_./*\-]+$#', $line ) ) continue;
            if ( str_contains( substr( $line, 0, -1 ), '*' ) ) continue;
            if ( '*' !== substr( $line, -1 ) && str_contains( $line, '*' ) ) continue;
            $out[] = substr( $line, 0, 512 );
            if ( count( $out ) >= 200 ) break;
        }
        return array_values( array_unique( $out ) );
    }
    public static function set_ignores( string $raw ): array {
        $items = self::sanitize_ignores( $raw );
        update_option( 'ysec_integrity_ignores', $items, false );
        YSEC_Events::log( 'integrity_ignore_policy_saved', array( 'severity'=>'info', 'family'=>'integrity', 'details'=>array( 'rules'=>count( $items ) ) ) );
        return $items;
    }
    private static function is_ignored( string $path ): bool {
        $path = ltrim( wp_normalize_path( $path ), '/' );
        foreach ( self::ignored_paths() as $rule ) {
            if ( str_ends_with( $rule, '*' ) ) {
                $prefix = substr( $rule, 0, -1 );
                if ( '' !== $prefix && str_starts_with( $path, $prefix ) ) return true;
            } elseif ( hash_equals( $rule, $path ) ) return true;
        }
        return false;
    }

    public static function baseline(): array  {
        $map=[];
        foreach(self::files() as $rel=>$abs) {
            $h=@hash_file('sha256',$abs);
            if($h)$map[$rel]=$h;
        }
        update_option('ysec_integrity_baseline',array('version'=>gmdate('YmdHis'),'created_at'=>current_time('mysql',true),'files'=>$map),false);
        delete_transient('ysec_maintenance_context');
        YSEC_Events::log('integrity_baseline',array('severity'=>'info','family'=>'integrity','details'=>array('files'=>count($map))));
        return array('files'=>count($map),'created_at'=>current_time('mysql',true));
    }
    public static function scan(): array  {
        if ( get_transient('ysec_maintenance_context') ) return array('maintenance'=>true,'changes'=>array());
        $base=get_option('ysec_integrity_baseline',array());
        if(empty($base['files'])||!is_array($base['files']))return array('needs_baseline'=>true,'changes'=>array(),'scanned_at'=>current_time('mysql',true));
        $current=[];
        foreach(self::files() as $rel=>$abs) {
            $h=@hash_file('sha256',$abs);
            if($h)$current[$rel]=$h;
        }
        $changes=[];
        foreach($base['files'] as $p=>$h) {
            if(self::is_ignored((string)$p))continue;
            if(!isset($current[$p]))$changes[]=array('path'=>$p,'state'=>'missing');
            elseif(!hash_equals($h,$current[$p]))$changes[]=array('path'=>$p,'state'=>'modified');
        }
        foreach($current as $p=>$h) {
            if(self::is_ignored((string)$p))continue;
            if(!isset($base['files'][$p]))$changes[]=array('path'=>$p,'state'=>'added');
        }
        global $wpdb;
        $t=YSEC_DB::table('integrity');
        $now=current_time('mysql',true);
        foreach(array_slice($changes,0,2000) as $c) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Dedicated integrity table stores current scan state; this is a write operation.
            $wpdb->replace($t,array('path'=>$c['path'],'baseline_hash'=>$base['files'][$c['path']]??'','observed_hash'=>$current[$c['path']]??'','state'=>$c['state'],'baseline_version'=>$base['version']??'','first_seen'=>$now,'last_seen'=>$now),array('%s','%s','%s','%s','%s','%s','%s'));
        }
        if($changes)YSEC_Events::log('integrity_drift',array('severity'=>'high','family'=>'integrity','state'=>'suspicious','details'=>array('changes'=>count($changes),'sample'=>array_slice($changes,0,20))));
        return array('needs_baseline'=>false,'checked'=>count($current),'changes'=>$changes,'scanned_at'=>$now,'baseline_version'=>(string)($base['version']??''),'baseline_created_at'=>(string)($base['created_at']??''),'baseline_files'=>count($base['files']));
    }
    public static function scheduled(): void  {
        $r=self::scan();
        if(!empty($r['needs_baseline']))self::baseline();
    }
    public static function maintenance_baseline($upgrader,$options): void  {
        try {
            set_transient('ysec_maintenance_context',1,10*MINUTE_IN_SECONDS);
            wp_schedule_single_event(time()+60,'ysec_integrity_rebaseline');
        } catch ( Throwable $e ) {
            // Integrity re-baselining is deferred work; updater success takes priority.
        }
    }
}
