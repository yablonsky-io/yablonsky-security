<?php
if ( ! defined( 'ABSPATH' ) )  {
    exit;
}
final class YSEC_Classifier  {
    public const VERSION='1.0.0';
    public static function policy_class( string $path ): string  {
        $path=trim($path);
        if(''===$path)return 'technical';
        if(preg_match('#^https?://#i',$path)) {
            $parts=wp_parse_url($path);
            if(!is_array($parts))return 'technical';
            $path=(string)($parts['path']??'/');
        }
        $path=rawurldecode($path);
        if(false!==strpos($path,"\0"))return 'technical';
        $path='/'.ltrim(preg_replace('#/+#','/',$path)?:'','/');
        if(preg_match('#(?:^|/)\.\.(?:/|$)#',$path))return 'technical';
        $path=strtolower($path);
        if(0===strpos($path,'/wp-content/uploads/')&&preg_match('#\.(?:avif|gif|ico|jpe?g|mp3|mp4|ogg|pdf|png|svg|wav|webm|webp)$#',$path))return 'content';
        $probe=array(
        '#(?:^|/)\.(?!well-known(?:/|$))[^/]+#','#(?:^|/)[^/]*\.env(?:[._-][^/]*)?(?:/|$)#','#(?:^|/)(?:wp-config(?:-sample)?\.php(?:\.[^/]*)?|config\.php\.bak|phpinfo(?:\.php)?(?:\.[^/]*)?)(?:/|$)#','#(?:^|/)[^/]+\.(?:bak|backup|key|old|p12|pem|pfx|save|sql)(?:\.[^/]*)?$#','#^/(?:dockerfile|docker-compose(?:\.[^/]+)?\.ya?ml)(?:/|$)#','#(?:^|/)(?:composer(?:\.json|\.lock)?|package(?:-lock)?\.json|pnpm-lock\.ya?ml|yarn\.lock)(?:/|$)#','#^/(?:config(?:\.(?:json|ya?ml))|config/secrets\.ya?ml|application(?:\.[^/]+)?\.(?:properties|ya?ml)|appsettings(?:\.[^/]+)?\.json|server\.key)(?:/|$)#','#^/(?:conf|config)/(?:.+\.(?:ini|json|properties|xml|ya?ml)|secrets(?:/|$))#','#^/(?:swagger(?:\.json|/)|openapi(?:\.(?:json|ya?ml)|/)|api-docs(?:/|$)|v\d+/api-docs(?:/|$))#','#^/(?:actuator|_ignition|_profiler|debug|phpinfo|telescope)(?:/|$)#','#^/(?:cgi-bin|developmentserver)(?:/|$)#','#^/api/v\d+/projects/?$#','#^/autodiscover/autodiscover\.json$#','#^/\+cscot\+/#','#^/(?:firewall|randkeyword|warm|worm)\.php\d*/?$#','#^/\.well-known/[^/]*\.php\d*/?$#','#^/patriotic/wp-includes/#','#^/plugins/jquery\.filer/uploads/?$#','#^/themes/pridmag/?$#','#^/(?:admin/uploads|alfa_data|aspera/faspex|webui)(?:/|$)#','#^/(?:config|\.aws|\.docker|\.git)/(?:core-block|global-styles|google_gtagjs|lodash-|moment-|vegan-|wc-|woocommerce-|wp-|width=).+$#','#^/(?:core-block|global-styles|google_gtagjs|lodash-|moment-|vegan-|wc-|woocommerce-|wp-).*(?:inline-css|js-(?:after|before|extra))$#','#^/width=device-width,#','#^/(?:mcp|sse)(?:/|$)#','#^/v2/_catalog/?$#','#^/owa(?:/|$)#','#^/rest/api(?:/|$)#','#^/alfacgiapi(?:/|$)#','#^/telerik\.web\.ui\.webresource\.axd$#','#^/solr(?:/|$)#','#^/(?:console|weblogic|jenkins|jmx-console)(?:/|$)#','#^/sitecore(?:/|$)#','#^/(?:hnap1|evox/about|remote/info)(?:/|$)#','#^/nmaplowercheck\d+$#','#^/(?:xleet|dr0v|_environment)(?:/|$)#','#^/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.html$#','#(?:^|/)(?:secret|secrets)\.(?:txt|py|js|json|ya?ml)$#','#(?:^|/)(?:aws[-_]?config|awssettings|aws_config)\.(?:csv|js|json|py|ya?ml)$#','#\*#');
        foreach($probe as $rx)if(preg_match($rx,$path))return 'probe';
        $technical=array('#^/(?:wp-admin|wp-includes|wp-json)(?:/|$)#','#^/(?:wp-activate\.php|wp-comments-post\.php|wp-cron\.php|wp-load\.php|wp-login\.php|wp-mail\.php|wp-settings\.php|wp-signup\.php|wp-trackback\.php|xmlrpc\.php)(?:/|$)#','#^/wp-content/(?:cache|languages|mu-plugins(?:-old)?|plugins|themes|upgrade)(?:/|$)#','#^/wp-content/uploads(?:/|$)#','#^/\.well-known(?:/|$)#','#^/(?:ads|robots)\.txt$#','#(?:^|/)[^/]*sitemap[^/]*\.xml(?:/|$)#','#^/(?:api|graphql|ipfs)(?:/|$)#','#(?:^|/)[^/]+\.(?:ini|json|xml|ya?ml)$#','#\.(?:js|css|py|php\d*|phar|aspx?|axd|jsp|do|cgi|pl|sh|ps1|cc)(?:~)?$#','#^/(?:admin|assets|backup|dashboard|id|index|login|modules|plugins|upload|uploads|users/sign_in|web|webinterface|wordpress|wp|www)(?:/|$)#','#^/(?:conf|config|deploy|node_modules|server|storage|vendor)(?:/|$)#');
        foreach($technical as $rx)if(preg_match($rx,$path))return 'technical';
        return 'content';
    }
    public static function classify( string $path, string $method='GET' ): array  {
        if(in_array(strtoupper($method),array('TRACE','TRACK','CONNECT'),true))return array('class'=>'probe','family'=>'method_abuse','confidence'=>'high','severity'=>'high');
        $p=strtolower(rawurldecode($path));
        $strong=array(
        'credentials_secrets'=>'#(?:^|/)(?:\.env(?:[./_-]|$)|\.git(?:/|$)|\.svn(?:/|$)|wp-config(?:\.php|[-._/]|$)|credentials(?:[./_-]|$)|secrets?(?:[./_-]|$)|server\.key(?:/|$))#i',
        'database_admin'=>'#(?:^|/)(?:phpmyadmin|pma|adminer|mysqladmin|dbadmin)(?:/|$|\.php)#i',
        'backup_dump'=>'#(?:^|/)(?:backup|backups|dump|database|db)[^/]*\.(?:zip|tar|gz|sql|7z|bak|old)(?:$|[/?])#i',
        'webshell_probe'=>'#(?:^|/)(?:wso|c99|r57|alfa|b374k|webshell|shell|cmd|up)(?:[^/]*\.php\d*|/|$)#i',
        'traversal_lfi'=>'#(?:\.\.[/\\\\]|/etc/(?:passwd|shadow)|/proc/self/environ|windows[/\\\\]win\.ini)#i',
        'framework_probe'=>'#(?:^|/)(?:actuator|swagger|openapi|weblogic|jenkins|solr|sitecore|owa|telerik|jmx-console)(?:/|$|\.)#i',
        );
        foreach($strong as $f=>$rx) {
            if(preg_match($rx,$p))return array('class'=>'probe','family'=>$f,'confidence'=>'high','severity'=>in_array($f,array('credentials_secrets','webshell_probe','traversal_lfi'),true)?'high':'medium');
        }
        $class=self::policy_class($path);
        if('technical'===$class)return array('class'=>'technical','family'=>'wordpress_or_technical_surface','confidence'=>'high','severity'=>'info');
        if('content'===$class)return array('class'=>'content','family'=>'content_or_unknown','confidence'=>'medium','severity'=>'info');
        return array('class'=>'probe','family'=>'reconnaissance','confidence'=>'high','severity'=>'medium');
    }
    private static function canonicalize_payload( string $value ): string  {
        $value=substr($value,0,65536);
        for($i=0;$i<3;$i++) {
            $decoded=rawurldecode($value);
            if($decoded===$value)break;
            $value=$decoded;
        }
        $value=html_entity_decode($value,ENT_QUOTES|ENT_HTML5,'UTF-8');
        $value=str_replace(array("\0","\r"),array('',"\n"),$value);
        return $value;
    }
    public static function request_threats( bool $include_payload = true ): array  {
        $uri=isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $path=YSEC_Utils::normalize_path($uri);
        $method=isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';
        $signals=[];
        $c=self::classify($path,$method);
        if('probe'===$c['class'])$signals[]=$c;
        if(!$include_payload)return $signals;
        $raw_query=isset($_SERVER['QUERY_STRING']) ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING'])) : '';
        $body='';
        if(in_array(strtoupper($method),array('POST','PUT','PATCH','DELETE'),true)) {
            $len=isset($_SERVER['CONTENT_LENGTH']) ? absint(wp_unslash($_SERVER['CONTENT_LENGTH'])) : 0;
            if($len>0&&$len<=262144)$body=(string)file_get_contents('php://input',false,null,0,262144);
        }
        $hay=self::canonicalize_payload($path.'?'.substr($raw_query,0,8192).' '.substr($body,0,32768));
        $rules=array(
        'path_traversal'=>'#(?:\.\.[/\\\\]|/etc/(?:passwd|shadow)|/proc/self/environ|boot\.ini|windows[/\\\\]win\.ini)#i',
        'sql_injection'=>'#(?:\bunion(?:/\*.*?\*/|\s)+(?:all(?:/\*.*?\*/|\s)+)?select\b|\b(?:sleep|benchmark|pg_sleep)\s*\(|\binformation_schema\b|\bload_file\s*\(|\binto\s+outfile\b|\b(?:updatexml|extractvalue)\s*\(|\bxp_cmdshell\b|(?:\'|\")\s*(?:or|and)\s+[\'\"0-9a-z_]+\s*=\s*[\'\"0-9a-z_]+)#is',
        'xss'=>'#(?:<\s*script\b|<\s*svg\b[^>]*\bonload\s*=|<\s*iframe\b[^>]*\bsrcdoc\s*=|javascript\s*:|data\s*:\s*text/html|\bon(?:error|load|click|mouseover|focus)\s*=)#is',
        'rfi_lfi'=>'#(?:php://(?:filter|input)|data://|expect://|zip://|phar://|/etc/(?:passwd|shadow)|/proc/self/environ)#i',
        'jndi'=>'#\$\{\s*jndi\s*:(?:ldap|rmi|dns|http)#i',
        'xxe'=>'#<!doctype[^>]*\[[\s\S]{0,4096}<!entity[^>]+system\s+[\'\"](?:file|https?|ftp):#i',
        'command_injection'=>'#(?:[;&|]\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|powershell|cmd)(?:\s|$)|\$\([^)]{1,256}\)|`(?:id|whoami|uname|cat\s)[^`]*`)#i',
        'php_object_injection'=>'#(?:^|[^a-z0-9])O:\d+:\"[A-Za-z_\\\\][^\"]*\":\d+:\{#',
        'metadata_ssrf'=>'#(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/latest/meta-data)#i',
        );
        foreach($rules as $family=>$rx)if(preg_match($rx,$hay))$signals[]=array('class'=>'probe','family'=>$family,'confidence'=>'high','severity'=>'critical');
        return $signals;
    }
}
