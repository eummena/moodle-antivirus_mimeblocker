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
 * MIME Blocker antivirus setting
 *
 * @package    antivirus_mimeblocker
 * @copyright  2019 Eummena, TK.
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @author     Tasos Koutoumanos <tk@eummena.org>
 */
defined('MOODLE_INTERNAL') || die();

if ($ADMIN->fulltree) {
    require_once(__DIR__ . '/classes/adminlib.php');
    require_once(__DIR__ . '/classes/scanner.php');

    // Scanmode.
    $settings->add(new admin_setting_configselect('antivirus_mimeblocker/scanmode',
    new lang_string('scanmode', 'antivirus_mimeblocker'),
    new lang_string('scanmodedesc', 'antivirus_mimeblocker'),
    '0',
    [
        'allow' => new lang_string('scanmodeallow', 'antivirus_mimeblocker'),
        'deny' => new lang_string('scanmodedeny', 'antivirus_mimeblocker')
    ]));

    // Mimetypes.
    $settings->add(new antivirus_mimeblocker_allowedmimetypes(
            'antivirus_mimeblocker/mimetypes', new lang_string('mimetypes', 'antivirus_mimeblocker'),
            new lang_string('mimetypesdesc', 'antivirus_mimeblocker'), ''));
}
