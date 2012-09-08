<?php
	/****************
	 * Pombo 0.0.10 *
	 ****************/
	 
	error_reporting(0);
	usleep(200000);
	$PASSWORD  = 'mysecret';
	$CHECKFILE = '.stolen';
	
	if ( substr(phpversion(), 0, 1) == 4 ) {
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
	if ( ! empty($_GET) ) {
		if ( isset($_GET['check']) && $_GET['check'] == $CHECKFILE ) {
			usleep(200000);
			if ( file_exists($CHECKFILE) )
				die('Computer already stolen!');
			$fh = fopen($CHECKFILE, 'xb');
			if ( ! $fh )
				die('Could not create file.');
			if ( ! fwrite($fh, 'Chenapan !') )
				die('Could not write file.');
			fclose($fh);
			die('File created, pombo will see it and check every 5 minutes.');
		}
		if ( isset($_GET['myip']) )
			die($_SERVER['REMOTE_ADDR']);
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
				die(file_exists($CHECKFILE));
		if ( $_POST['token'] != hash_hmac('sha1', $_POST['filedata'].'***'.$_POST['filename'], $PASSWORD) )
			die('Wrong password!');
		if ( pathinfo($_POST['filename'], PATHINFO_EXTENSION) != 'gpg' )
			die('Not a gpg file.');
		if ( ! preg_match('/^[a-zA-Z0-9\.\-\_]*$/', $_POST['filename']) )
			die('Invalid characters in filename.');
		$fh = fopen($_POST['filename'], 'xb');
		if ( ! $fh )
			die('Could not create file.');
		if ( ! fwrite($fh, base64_decode($_POST['filedata'])) )
			die('Could not write file.');
		fclose($fh);
	}
	echo 'File stored.';
?>
