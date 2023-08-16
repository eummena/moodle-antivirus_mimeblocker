<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * An "antivirus" for Moodle that will accurately check the mimetype and allow only specific types of file uploads.
 *
 * MIME Blocker antivirus integration.
 *
 * @package    antivirus_mimeblocker
 * @copyright  2019 Eummena, TK.
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @author     Tasos Koutoumanos <tk@eummena.org>
 */

namespace antivirus_mimeblocker;

defined('MOODLE_INTERNAL') || die();

/**
 * Class implementing Mime Blocker antivirus.
 *
 * @copyright  2018 Eummena, TK.
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scanner extends \core\antivirus\scanner {

    /**
     * @var string A semicolon separated string of allowed or denyed mimetypes.
     */
    public $configuredmimetypes;

    /**
     * Class constructor.
     *
     * @return void.
     */
    public function __construct() {
        parent::__construct();
        // Create array of allowed mimetypes based on config setting.
        $this->configuredmimetypes = explode(";", trim($this->get_config('mimetypes')));
    }

    /**
     * Are the necessary antivirus settings configured?
     *
     * @return bool True if all necessary config settings been entered.
     */
    public function is_configured() {
        if ($this->get_config('mimetypes') != '') {
            return (bool) $this->configuredmimetypes;
        }
        return false;
    }

    /**
     * Scan file.
     *
     * This method is normally called from antivirus manager (\core\antivirus\manager::scan_file).
     *
     * @param string $file Full path to the file.
     * @param string $filename Name of the file (could be different from physical file if temp file is used).
     * @return int Scanning result constant.
     */
    public function scan_file($file, $filename) {
        if (!is_readable($file)) {
            debugging("File is not readable ($file / $filename).");
            return self::SCAN_RESULT_FOUND;
        }

        // Set scanmode.
        $scanmodeconfig = self::get_config('scanmode');
        $scanmode = [];
        if ($scanmodeconfig == "allow") {
            $scanmode = [true, false];
        } else if ($scanmodeconfig == "deny") {
            $scanmode = [false, true]; // Switch scanmode.
        } else {
            return self::SCAN_RESULT_FOUND;
        }

        $detectedmimetype = null;
        // Check mimetype using php functions.
        if (function_exists('finfo_file')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $detectedmimetype = finfo_file($finfo, $file);
            finfo_close($finfo);
        } else if (function_exists('mime_content_type')) {
            // Deprecated, only when finfo isn't available.
            debugging("Note finfo_file() php function not available, falling back to depracated mime_content_type()");
            $detectedmimetype = mime_content_type($file);
        }

        // MoodleNet compatibility, Ignore course backup file.
        if ($detectedmimetype == 'inode/x-empty' && pathinfo($file, PATHINFO_EXTENSION) == 'log') {
            $detectedmimetype = 'text/plain';
        }

        if ($detectedmimetype == 'application/x-gzip' || $detectedmimetype == 'application/gzip') {
            $detectedmimetype = 'application/vnd.moodle.backup';
        }

        // Check if result is in the array of allowed mimetypes.
        $return = in_array($detectedmimetype, $this->configuredmimetypes);
        if ($return == $scanmode[0]) {
            return self::SCAN_RESULT_OK;
        } else if ($return == $scanmode[1]) {
            // MIME type not allowed! custom exception will be throw and not return back at \core\antivirus\manager::scan_file.
            unlink($file);
            require_once('mimeblocker_exception.php');
            if ($scanmodeconfig == "allow") {
                throw new mimeblocker_exception('virusfoundallow', '', ['types' => self::get_file_extensions()]);
            }
            if ($scanmodeconfig == "deny") {
                throw new mimeblocker_exception('virusfounddeny', '', ['types' => self::get_file_extensions()]);
            }
        }

        return $return;
    }

    /**
     *
     * To identify extension of the MIME type.
     *
     * @param string MIME type
     * @return array MIME type extention
     */
    public static function extension_filter($mime) {
        $types = \core_filetypes::get_types();
        $extensions = [];
        foreach ($types as $key => $type) {
            if ($type['type'] === $mime) {
                $extensions[] = $key;
            }
        }

        if (count($extensions)) {
            return $extensions;
        }
    }

    /**
     * To get comma separate extension on the basis of allowed or denxed MIME types configure by administrator.
     *
     * @return string types of allowed extensions based on allowed MIME types.
     */
    public function get_file_extensions() {

        $extensions = [];

        foreach ($this->configuredmimetypes as $mime) {
            array_push($extensions, ...self::extension_filter($mime));
        }

        return implode(", ", $extensions);
    }
}
