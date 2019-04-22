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
 * Strings for component 'antivirus_mimeblocker', language 'en'.
 *
 * @package    antivirus_mimeblocker
 * @copyright  2019 Eummena, TK.
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @author     Tasos Koutoumanos <tk@eummena.org>
 */
$string['pluginname'] = 'Mime Blocker antivirus';
$string['privacy:metadata'] = 'The Mime Blocker antivirus plugin does not store any personal data.';
$string['quarantinedir'] = 'Quarantine directory';
$string['unknownerror'] = 'There was an unknown error with Mime Blocker.';
$string['allowedmimetypes'] = 'Allowed mime types';
$string['allowedmimetypesdesc'] =
        'Provide a list of allowed mimetypes separated by ";". For example: "text/xml;image/png;application/pdf"';
$string['virusfound'] = ' You can only upload one of the following file types : {$a->types}.';
