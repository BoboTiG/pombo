<?php
    error_reporting(0);
    usleep(200000);

    /* For multi hosts, you can define these 2 variables in
     * the index.php and call pombo.php.
     *
     * Tree:
     *     /pombo.php
     *     /bob
     *       |--- index.php
     *     /alice
     *       |--- index.php
     *
     * Contents of index.php:
     *
     * <?php
     *     $PASSWORD  = '<The same value as in pombo.conf.>';
     *     $CHECKFILE = '<The same value as in pombo.conf.>';
     *     require '../pombo.php';
     * ?>
     */
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

    class Pombo 
    {
        private $password;
        private $checkfile;

        public function __construct($password, $checkfile) 
        {
            $this->password = $password;
            $this->checkfile = $checkfile;
        }

        public function isStolen() 
        {
            return is_file($this->checkfile);
        }

        public function markAsStolen() 
        {
            if (!$this->isStolen()) {
                $fh = fopen($this->checkfile, 'w');
                if ($fh === false) {
                    return false;
                }
                fclose($fh);
                return true;
            }
            return true;
        }

        public function getClientIP() 
        {
            return !empty($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
        }
    }
    $pombo = new Pombo($PASSWORD, $CHECKFILE);

    /* Stolen! */
    if ( !empty($_GET) ) {
        if ( isset($_GET['check']) && $_GET['check'] == $CHECKFILE ) {
            if ( $pombo->isStolen() ) {
                die('Computer already stolen!');
            }
            if ( !$pombo->markAsStolen() ) {
                die('Could not create file.');
            }
            die('File created, Pombo will see it and check every 5 minutes.');
        }
        if ( isset($_GET['myip']) ) {
            die($pombo->getClientIP());
        }
        die('Nothing to do ...');
    }
    /* Routine */
    elseif ( !empty($_POST) ) {
        // if ( empty($_POST) )
        //     die('Nothing to do ...');
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
        echo 'File stored.';
    }



/**
 * Archive Cleaner Script (v3)
 *
 * Cleans archived zip files in the script's directory based on retention rules.
 * Outputs HTML-compatible line breaks.
 *
 * Filename format: {device}_{YYYYMMDD}_{HHMMSS}.zip
 * Example: NOTASC271_20250331_093208.zip
 *
 * Retention Rules (per device):
 * - Keep all files from the current day.
 * - Keep the last file for each day in the past week (excluding today).
 * - Keep the last file for each week in the past month (excluding the last week).
 * - Keep the last file for each month in the past year (excluding the last month).
 */

function cecho($msg) {
    // echo($msg);
}

// --- Configuration ---
// Set to false to actually delete files, true to only list what would be deleted.
define('DRY_RUN', false);
// Define the target directory (current directory where the script resides)
define('TARGET_DIR', __DIR__);
// Define the filename pattern using regex - UPDATED for YYYYMMDD_HHMMSS
// - Group 1: Device name ([a-zA-Z0-9_-]+)
// - Group 2: Date (YYYYMMDD) (\d{8}) << CORRECTED
// - Group 3: Time (HHMMSS) (\d{6})
define('FILENAME_REGEX', '/^([a-zA-Z0-9_-]+)_(\d{8})_(\d{6})\.zip$/'); // << CORRECTED Regex
// Define the line break string
define('NL', "<br/>\n");

// --- Initialization ---
// Use the timezone appropriate for the file timestamps / server location
// Set based on location context provided
date_default_timezone_set('Europe/Prague');
$now = new DateTimeImmutable(); // Use immutable for safety
$allFilesData = [];
$filesToDelete = [];
$filesToKeep = []; // For verification/logging if needed

cecho("Archive Cleaner Started: " . $now->format('Y-m-d H:i:s T') . NL); // Added Timezone abbreviation
cecho("Mode: " . (DRY_RUN ? "DRY RUN (No files will be deleted)" : "LIVE (Files will be deleted!)") . NL);
cecho("Target Directory: " . TARGET_DIR . NL);

// --- Step 1: Find and Parse All Zip Files ---
$directoryIterator = new DirectoryIterator(TARGET_DIR);

foreach ($directoryIterator as $fileInfo) {
    if ($fileInfo->isFile() && $fileInfo->getExtension() === 'zip') {
        $filename = $fileInfo->getFilename();
        if (preg_match(FILENAME_REGEX, $filename, $matches)) {
            $deviceName = $matches[1];
            $dateStr = $matches[2]; // YYYYMMDD << CORRECTED interpretation
            $timeStr = $matches[3]; // HHMMSS
            $dateTimeStr = $dateStr . $timeStr; // Combined: YYYYMMDDHHMMSS

            try {
                // UPDATED format string 'YmdHis' for YYYYMMDDHHMMSS << CORRECTED
                $fileDateTime = DateTimeImmutable::createFromFormat('YmdHis', $dateTimeStr);
                if ($fileDateTime === false) {
                    throw new Exception("Could not parse date/time using format 'YmdHis': $dateTimeStr");
                }

                // Store file info grouped by device name
                if (!isset($allFilesData[$deviceName])) {
                    $allFilesData[$deviceName] = [];
                }
                $allFilesData[$deviceName][] = [
                    'path' => $fileInfo->getPathname(),
                    'filename' => $filename,
                    'datetime' => $fileDateTime,
                    'timestamp' => $fileDateTime->getTimestamp(),
                ];
            } catch (Exception $e) {
                cecho("Skipping file (parse error): $filename - " . $e->getMessage() . NL);
            }
        } else {
                cecho("Skipping file (format mismatch): $filename" . NL);
        }
    }
}

// --- Step 2: Process Files Per Device ---
if (empty($allFilesData)) {
    cecho("No matching zip files found." . NL);
    exit;
}

// Calculate cutoff dates (using DateTime objects for reliable comparisons)
$todayStart = $now->setTime(0, 0, 0);
// Start of the week for "past week" rule calculation
$startOfPastWeek = $now->modify('monday this week')->setTime(0, 0, 0);
// If today *is* Monday, "past week" should start from *last* Monday
if ($now->format('N') == 1) { // 'N' gives ISO-8601 day number (1=Monday, 7=Sunday)
        $startOfPastWeek = $startOfPastWeek->modify('-7 days');
}
// Use $startOfPastWeek directly for the lower bound of daily retention
$oneWeekAgo = $startOfPastWeek; // Keep daily files from this time up to todayStart
$oneMonthAgo = $now->modify('-1 month')->setTime(0,0,0);
$oneYearAgo = $now->modify('-1 year')->setTime(0,0,0);


cecho("Cutoff - Today Start: " . $todayStart->format('Y-m-d H:i:s') . NL);
// Clarify rule boundaries:
cecho("Cutoff - Keep Daily From: " . $oneWeekAgo->format('Y-m-d H:i:s') . " (Up to Today)" . NL);
cecho("Cutoff - Keep Weekly From: " . $oneMonthAgo->format('Y-m-d H:i:s') . " (Up to Start of Past Week: " . $oneWeekAgo->format('Y-m-d H:i:s') . ")" . NL);
cecho("Cutoff - Keep Monthly From: " . $oneYearAgo->format('Y-m-d H:i:s') . " (Up to 1 Month Ago: " . $oneMonthAgo->format('Y-m-d H:i:s') . ")" . NL);


foreach ($allFilesData as $deviceName => $files) {
    cecho(NL . "--- Processing Device: $deviceName ---" . NL);

    // Sort files by datetime descending (newest first)
    usort($files, function ($a, $b) {
        return $b['timestamp'] <=> $a['timestamp']; // Newest first
    });

    $keptMarkers = [
        'daily' => [], // Key: YYYY-MM-DD
        'weekly' => [], // Key: YYYY-WW (ISO-8601 week number, 'o-W' format)
        'monthly' => [], // Key: YYYY-MM
    ];

    $deviceFilesToKeep = [];
    $deviceFilesToDelete = [];

    foreach ($files as $file) {
        $fileDateTime = $file['datetime'];
        $filePath = $file['path'];
        $fileIdentifier = $file['filename']; // Use filename for easier debugging

        // Assume deletion unless a rule keeps it
        $keepFile = false;

        // Rule 1: Keep all files from today
        if ($fileDateTime >= $todayStart) {
            // cecho("Keep (Today): $fileIdentifier" . NL); // Uncomment for verbose debugging
            $keepFile = true;
        }
        // Rule 2: Keep last file for each day in the past week (older than today, newer than or equal to start of past week)
        elseif ($fileDateTime < $todayStart && $fileDateTime >= $oneWeekAgo) {
                $dayKey = $fileDateTime->format('Y-m-d');
                if (!isset($keptMarkers['daily'][$dayKey])) {
                // cecho("Keep (Last 7 Days - Day: $dayKey): $fileIdentifier" . NL); // Uncomment for verbose debugging
                $keptMarkers['daily'][$dayKey] = true;
                $keepFile = true;
                }
        }
        // Rule 3: Keep last file for each week in the past month (older than start of past week, newer than or equal to 1 month ago)
        elseif ($fileDateTime < $oneWeekAgo && $fileDateTime >= $oneMonthAgo) {
                $weekKey = $fileDateTime->format('o-W'); // ISO-8601 year and week number
                if (!isset($keptMarkers['weekly'][$weekKey])) {
                // cecho("Keep (Last Month - Week: $weekKey): $fileIdentifier" . NL); // Uncomment for verbose debugging
                $keptMarkers['weekly'][$weekKey] = true;
                $keepFile = true;
                }
        }
        // Rule 4: Keep last file for each month in the past year (older than 1 month, newer than or equal to 1 year ago)
        elseif ($fileDateTime < $oneMonthAgo && $fileDateTime >= $oneYearAgo) {
            $monthKey = $fileDateTime->format('Y-m');
            if (!isset($keptMarkers['monthly'][$monthKey])) {
                // cecho("Keep (Last Year - Month: $monthKey): $fileIdentifier" . NL); // Uncomment for verbose debugging
                $keptMarkers['monthly'][$monthKey] = true;
                $keepFile = true;
            }
        }

        // Add to appropriate list
        if ($keepFile) {
                $deviceFilesToKeep[$fileIdentifier] = $filePath;
        } else {
                // Only add for deletion if it's older than 1 year OR not kept by any rule above
                if ($fileDateTime < $oneYearAgo || !isset($deviceFilesToKeep[$fileIdentifier])) {
                // cecho("Mark for Deletion: $fileIdentifier" . NL); // Uncomment for verbose debugging
                $deviceFilesToDelete[$fileIdentifier] = $filePath;
                }
        }
    } // End foreach file in device

    // Add to global lists
    $filesToKeep = array_merge($filesToKeep, $deviceFilesToKeep);
    $filesToDelete = array_merge($filesToDelete, $deviceFilesToDelete);

    cecho("Summary for $deviceName: " . count($files) . " total files found." . NL);
    cecho(" - Files to keep: " . count($deviceFilesToKeep) . NL);
    if (!empty($deviceFilesToKeep)) {
        cecho("   <ul>" . NL);
        foreach(array_keys($deviceFilesToKeep) as $fname) { cecho("     <li>$fname</li>" . NL); }
        cecho("   </ul>" . NL);
    }
    cecho(" - Files to delete: " . count($deviceFilesToDelete) . NL);
    if (!empty($deviceFilesToDelete)) {
        cecho("   <ul>" . NL);
        foreach(array_keys($deviceFilesToDelete) as $fname) { cecho("     <li>$fname</li>" . NL); }
        cecho("   </ul>" . NL);
    }


} // End foreach device

// --- Step 3: Perform Deletion (if not DRY_RUN) ---
cecho(NL . "--- Deletion Phase ---" . NL);
if (DRY_RUN) {
    cecho("DRY RUN enabled. No files will be deleted." . NL);
    if (empty($filesToDelete)) {
        cecho("No files marked for deletion." . NL);
    } else {
        cecho("Files that would be deleted: " . count($filesToDelete) . NL);
        // Optional: List files again if needed for clarity in dry run
        // cecho("   <ul>" . NL);
        // foreach(array_keys($filesToDelete) as $fname) { cecho("     <li>$fname</li>" . NL); }
        // cecho("   </ul>" . NL);
    }
} else {
    if (empty($filesToDelete)) {
        cecho("No files marked for deletion." . NL);
    } else {
        cecho("Deleting " . count($filesToDelete) . " files..." . NL);
        $deletedCount = 0;
        $errorCount = 0;
        foreach ($filesToDelete as $filename => $path) {
            cecho("Deleting: $filename ... ");
            if (file_exists($path)) {
                // Use @unlink to suppress potential warnings if deletion fails, handle manually
                if (@unlink($path)) {
                    cecho("Success." . NL);
                    $deletedCount++;
                } else {
                    $error = error_get_last();
                    cecho("FAILED! (Reason: " . ($error['message'] ?? 'Unknown permission or lock issue') . ")" . NL);
                    $errorCount++;
                }
            } else {
                    cecho("Skipped (File not found at path: $path)." . NL);
                    $errorCount++; // Count as error if it was expected to be there based on initial scan
            }
        }
        cecho("Deletion complete. $deletedCount files deleted, $errorCount errors." . NL);
    }
}

cecho(NL . "Archive Cleaner Finished." . NL);