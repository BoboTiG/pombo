<?php
    /****************
     * Pombo 0.0.11 *
     ****************/

    error_reporting(0);
    usleep(200000);

    if ( !function_exists('hash_hmac') ) {
        //Calculate HMAC-SHA1 according to RFC2104
        // http://www.ietf.org/rfc/rfc2104.txt
        function hash_hmac($hashfunc, $data, $key) {
            $blocksize = 64;
            if ( strlen($key) > $blocksize )
                $key = pack('H*', $hashfunc($key));
            $key  = str_pad($key, $blocksize, chr(0x00));
            $ipad = str_repeat(chr(0x36), $blocksize);
            $opad = str_repeat(chr(0x5c), $blocksize);
            $hmac = pack('H*', $hashfunc(($key ^ $opad).pack('H*', $hashfunc(($key ^ $ipad).$data))));
            return bin2hex($hmac);
        }
    }

    /* Stolen! */
    if ( !empty($_GET) ) {
        if ( isset($_GET['check']) && $_GET['check'] == $CHECKFILE ) {
            if ( is_file($CHECKFILE) )
                die('Computer already stolen!');
            if ( ($fh = fopen($CHECKFILE, 'w')) === false )
                die('Could not create file.');
            fclose($fh);
            die('File created, pombo will see it and check every 5 minutes.');
        }
        if ( isset($_GET['myip']) )
            die( !empty($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR']);
        die('Nothing to do ...');
    }
    /* Routine */
    else {
        if ( empty($_POST) )
            die('Nothing to do ...');
        if ( isset($_POST['verify']) )
            if ( $_POST['verify'] != hash_hmac('sha1', $_POST['filedata'].'***'.$_POST['filename'], $PASSWORD) )
                die('Wrong password!');
            else
                die(is_file($CHECKFILE));
        if ( $_POST['token'] != hash_hmac('sha1', $_POST['filedata'].'***'.$_POST['filename'], $PASSWORD) )
            die('Wrong password!');
        if ( pathinfo($_POST['filename'], 4) != 'gpg' && pathinfo($_POST['filename'], 4) != 'zip' )
            die('Not a gpg file.');
        if ( !preg_match('/^[\w\.\-]*$/', $_POST['filename']) )
            die('Invalid characters in filename.');
        if ( ($fh = fopen($_POST['filename'], 'xb')) === false )
            die('Could not create file.');
        if ( fwrite($fh, base64_decode($_POST['filedata'])) === false )
            die('Could not write file.');
        fclose($fh);
    }
    echo 'File stored.';
?>
