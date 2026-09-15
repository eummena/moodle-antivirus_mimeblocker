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
     * @var array Configured mimetypes to allow or deny.
     */
    protected $configuredmimetypes;

    /**
     * @var string The active scan mode ('allow' or 'deny'), set during scan_file().
     */
    private $scanmodeconfig = 'allow';

    /**
     * Class constructor.
     *
     * @return void.
     */
    public function __construct() {
        parent::__construct();
        // Create array of allowed mimetypes based on config setting.
        $this->configuredmimetypes = explode(";", trim((string) $this->get_config('mimetypes')));
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
        $scanmodeconfig = $this->get_config('scanmode');
        if ($scanmodeconfig !== "allow" && $scanmodeconfig !== "deny") {
            // Invalid scanmode config, fail safe and block all uploads.
            return self::SCAN_RESULT_FOUND;
        }

        $detectedmimetype = $this->detect_mimetype($file);

        if ($detectedmimetype === null) {
            debugging("Could not detect MIME type for file ($file). No detection function available.");
            return self::SCAN_RESULT_ERROR;
        }

        // MoodleNet compatibility, Ignore course backup file.
        if ($detectedmimetype == 'inode/x-empty' && pathinfo($file, PATHINFO_EXTENSION) == 'log') {
            $detectedmimetype = 'text/plain';
        }

        if ($detectedmimetype == 'application/x-gzip' || $detectedmimetype == 'application/gzip') {
            $detectedmimetype = 'application/vnd.moodle.backup';
        }

        // In deny mode, block if the type matches the list. In allow mode, block if it doesn't match.
        $ismatch = in_array($detectedmimetype, $this->configuredmimetypes);
        $isblocked = ($scanmodeconfig === 'deny') ? $ismatch : !$ismatch;

        if (!$isblocked) {
            return self::SCAN_RESULT_OK;
        }

        // MIME type not allowed — let the antivirus manager handle quarantine, cleanup and messaging.
        $this->scanmodeconfig = $scanmodeconfig;
        return self::SCAN_RESULT_FOUND;
    }

    /**
     * Return custom virus found message based on the active scan mode.
     *
     * Overrides the base method so the antivirus manager displays a message
     * that tells the user which file types are allowed or denied.
     *
     * @return array array of string, component and placeholders for the exception.
     */
    public function get_virus_found_message() {
        $stringkey = ($this->scanmodeconfig === 'deny') ? 'virusfounddeny' : 'virusfoundallow';
        return [
            'string' => $stringkey,
            'component' => 'antivirus_mimeblocker',
            'placeholders' => ['types' => $this->get_file_extensions()],
        ];
    }

    /**
     * Detect the MIME type of a file.
     *
     * @param string $file Full path to the file.
     * @return string|null The detected MIME type, or null if detection is not available.
     */
    protected function detect_mimetype($file) {
        if (function_exists('finfo_file')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mimetype = finfo_file($finfo, $file);
            finfo_close($finfo);
            return $mimetype ?: null;
        } else if (function_exists('mime_content_type')) {
            debugging("Note finfo_file() php function not available, falling back to deprecated mime_content_type()");
            $mimetype = mime_content_type($file);
            return $mimetype ?: null;
        }
        return null;
    }

    /**
     * To identify extension of the MIME type.
     *
     * @param string $mime MIME type.
     * @return array MIME type extensions.
     */
    public static function extension_filter($mime) {
        $types = \core_filetypes::get_types();
        $extensions = [];
        foreach ($types as $key => $type) {
            if ($type['type'] === $mime) {
                $extensions[] = $key;
            }
        }

        return $extensions;
    }

    /**
     * To get comma separated extensions on the basis of allowed or denied MIME types configured by administrator.
     *
     * @return string types of allowed extensions based on allowed MIME types.
     */
    public function get_file_extensions() {

        $extensions = [];

        foreach ($this->configuredmimetypes as $mime) {
            // Types unknown to Moodle's file type registry have no extensions; show the MIME type itself.
            array_push($extensions, ...(self::extension_filter($mime) ?: [$mime]));
        }

        return implode(", ", $extensions);
    }
}
