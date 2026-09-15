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
 * Admin setting for MIME verification.
 *
 * @package    antivirus_mimeblocker
 * @copyright  2019 Eummena
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @author     Azmat Ullah <azmat@eummena.org>
 */

defined('MOODLE_INTERNAL') || die();

class antivirus_mimeblocker_allowedmimetypes extends admin_setting_configtextarea {

    /**
     * @param string $name
     * @param string $visiblename
     * @param string $description
     * @param mixed $defaultsetting string or array
     * @param mixed $paramtype
     * @param string $cols The number of columns to make the editor
     * @param string $rows The number of rows to make the editor
     */
    public function __construct($name, $visiblename, $description, $defaultsetting, $paramtype = PARAM_RAW) {
        parent::__construct($name, $visiblename, $description, $defaultsetting, $paramtype);
    }

    /**
     * Validate the contents of the textarea as a ";"-separated list of syntactically valid MIME types.
     *
     * Types do not have to be known to Moodle's file type registry, since in deny mode
     * the types to block are typically ones Moodle does not register (e.g. executables).
     *
     * @param string $data MIME types string
     * @return mixed bool true for success or string:error on failure
     */
    public function validate($data) {
        if ($data) {
            $mimetypes = explode(";", trim($data));
            foreach ($mimetypes as $mimetype) {
                if (!self::is_valid_mimetype($mimetype)) {
                    return get_string('invalidtypes', 'antivirus_mimeblocker', $mimetype);
                }
            }
        }
        return true;
    }

    /**
     * Check if a string has the form of a MIME type (type/subtype, RFC 2045 token characters).
     *
     * Wildcards are rejected because the scanner matches configured types exactly.
     *
     * @param string $mime
     * @return bool
     */
    public static function is_valid_mimetype($mime) {
        return (bool) preg_match('~^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$~i', $mime);
    }
}
