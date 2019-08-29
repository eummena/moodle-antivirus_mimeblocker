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
     * Validate the contents of the textarea as JSON
     *
     * @param string $data allowed MIME types string
     * @return mixed bool true for success or string:error on failure
     */
    public function validate($data) {
        $types = \core_filetypes::get_types();
        if ($data) {
            $allowed_mimetypes = explode(";", trim($data));
            foreach ($allowed_mimetypes as $mimetype) {
                if (!self::extension_filter($types, $mimetype)) {
                    return get_string('invalidtypes', 'antivirus_mimeblocker');
                }
            }
        }
        return true;
    }

    /**
     * Check if MIME type is valid
     *
     * @param array $types
     * @param array $mime
     * @return mixed array of extensions if MIME type is valid or FALSE if it's invalid
     */
    public function extension_filter($types, $mime) {
        $extensions = [];
        foreach ($types as $key => $type) {
            if ($type['type'] === $mime) {
                $extensions[] = $key;
            }
        }
        if (count($extensions)) {
            return $extensions;
        }
        return false;
    }

}
