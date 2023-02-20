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
     * @var string A semicolon separated string of allowed mimetypes.
     */
    public $allowed_mimetypes;

    /**
     * Class constructor.
     *
     * @return void.
     */
    public function __construct() {
        parent::__construct();
        // create array of allowed mimetypes based on config setting
        $this->allowed_mimetypes = explode(";", trim($this->get_config('allowedmimetypes')));
    }

    /**
     * Are the necessary antivirus settings configured?
     *
     * @return bool True if all necessary config settings been entered.
     */
    public function is_configured() {
        if ($this->get_config('allowedmimetypes') != '') {
            return (bool) $this->allowed_mimetypes;
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

        $detected_mimetype = null;
        // Check mimetype using php functions.
        if (function_exists('finfo_file')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $detected_mimetype = finfo_file($finfo, $file);
            finfo_close($finfo);
        } else if (function_exists('mime_content_type')) {
            // Deprecated, only when finfo isn't available.
            debugging("Note finfo_file() php function not available, falling back to depracated mime_content_type()");
            $detected_mimetype = mime_content_type($file);
        }

        // MoodleNet compatibility, Ignore course backup file.
        if ($detected_mimetype == 'inode/x-empty' && pathinfo($file, PATHINFO_EXTENSION) == 'log') {
            $detected_mimetype = 'text/plain';
        }

        if ($detected_mimetype == 'application/x-gzip' || $detected_mimetype == 'application/gzip') {
            $detected_mimetype = 'application/vnd.moodle.backup';
        }

        // Check if result is in the array of allowed mimetypes.
        $return = in_array($detected_mimetype, $this->allowed_mimetypes);
        if ($return == 1) {
            return self::SCAN_RESULT_OK;
        } else if ($return == 0) {
            // MIME type not allowed! custom exception will be throw and not return back at \core\antivirus\manager::scan_file
            unlink($file);
            require_once('mimeblocker_exception.php');
            throw new mimeblocker_exception('virusfound', '', ['types' => self::get_allowed_file_extensions()]);
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
     * To get comma separate extension on the basis of allowed MIME types configure by administrator.
     *
     * @return string types of allowed extensions based on allowed MIME types.
     */
    public function get_allowed_file_extensions() {

        $extensions = [];

        foreach ($this->allowed_mimetypes as $mime) {
            array_push($extensions, ...self::extension_filter($mime));
        }

        return implode(", ", $extensions);
    }
}
    
