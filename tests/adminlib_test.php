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

namespace antivirus_mimeblocker;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->libdir . '/adminlib.php');
require_once(__DIR__ . '/../classes/adminlib.php');

/**
 * Tests for the mimetypes admin setting validation.
 *
 * @package    antivirus_mimeblocker
 * @category   test
 * @copyright  2026 MBS
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(\antivirus_mimeblocker_allowedmimetypes::class)]
final class adminlib_test extends \advanced_testcase {
    /**
     * Helper: create the setting instance under test.
     *
     * @return \antivirus_mimeblocker_allowedmimetypes
     */
    private function create_setting(): \antivirus_mimeblocker_allowedmimetypes {
        return new \antivirus_mimeblocker_allowedmimetypes(
            'antivirus_mimeblocker/mimetypes',
            'Mimetypes',
            '',
            ''
        );
    }

    /**
     * Syntactically valid MIME types are accepted, whether or not Moodle's
     * file type registry knows them.
     *
     * @param string $data
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('valid_mimetypes_provider')]
    public function test_validate_accepts_valid_mimetypes(string $data): void {
        $this->assertTrue($this->create_setting()->validate($data));
    }

    /**
     * Data provider for test_validate_accepts_valid_mimetypes.
     *
     * @return array
     */
    public static function valid_mimetypes_provider(): array {
        return [
            'empty' => [''],
            'single known type' => ['application/pdf'],
            'multiple known types' => ['text/plain;image/png;application/pdf'],
            'unknown to moodle (exe)' => ['application/x-msdownload;application/x-dosexec'],
            'vendor tree with dots and plus' => ['application/vnd.microsoft.portable-executable;image/svg+xml'],
            'surrounding whitespace' => [" application/pdf;text/plain \n"],
        ];
    }

    /**
     * Malformed entries are rejected with an error message naming the offending entry.
     *
     * @param string $data
     * @param string $offending
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('invalid_mimetypes_provider')]
    public function test_validate_rejects_invalid_mimetypes(string $data, string $offending): void {
        $result = $this->create_setting()->validate($data);
        $this->assertIsString($result);
        $this->assertStringContainsString($offending, $result);
    }

    /**
     * Data provider for test_validate_rejects_invalid_mimetypes.
     *
     * @return array
     */
    public static function invalid_mimetypes_provider(): array {
        return [
            'extension instead of mimetype' => ['pdf', 'pdf'],
            'missing subtype' => ['application/', 'application/'],
            'missing type' => ['/pdf', '/pdf'],
            'space inside' => ['application/x foo', 'application/x foo'],
            'wrong separator' => ['application/pdf,text/plain', 'application/pdf,text/plain'],
            'trailing separator leaves empty entry' => ['application/pdf;', ''],
            'one bad entry in list' => ['application/pdf;bad;text/plain', 'bad'],
        ];
    }

    /**
     * Test the low-level syntax check directly.
     */
    public function test_is_valid_mimetype(): void {
        $this->assertTrue(\antivirus_mimeblocker_allowedmimetypes::is_valid_mimetype('application/octet-stream'));
        $this->assertTrue(\antivirus_mimeblocker_allowedmimetypes::is_valid_mimetype('Application/PDF'));
        $this->assertFalse(\antivirus_mimeblocker_allowedmimetypes::is_valid_mimetype('image/*'));
        $this->assertFalse(\antivirus_mimeblocker_allowedmimetypes::is_valid_mimetype(''));
        $this->assertFalse(\antivirus_mimeblocker_allowedmimetypes::is_valid_mimetype('application'));
        $this->assertFalse(\antivirus_mimeblocker_allowedmimetypes::is_valid_mimetype('a/b/c'));
    }
}
