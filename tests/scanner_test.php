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

/**
 * Tests for the MIME blocker scanner.
 *
 * @package    antivirus_mimeblocker
 * @copyright  2026 ISB Bayern
 * @author     Dr. Peter Mayer
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers     \antivirus_mimeblocker\scanner
 */
final class scanner_test extends \advanced_testcase {
    /**
     * A gzip stream is only accepted if a gzip MIME type is allowed, not via the Moodle backup type.
     */
    #[\PHPUnit\Framework\Attributes\Group('baseline')]
    public function test_gzip_is_not_treated_as_backup(): void {
        $this->resetAfterTest();
        $file = make_request_directory() . '/payload.gz';

        // Violation: only the Moodle backup type is allowed, so a gzip stream is rejected.
        file_put_contents($file, gzencode('payload'));
        set_config('allowedmimetypes', 'application/vnd.moodle.backup', 'antivirus_mimeblocker');
        try {
            (new scanner())->scan_file($file, 'coursework.gz');
            $this->fail('Expected mimeblocker_exception.');
        } catch (\moodle_exception $e) {
            $this->assertEquals('virusfound', $e->errorcode);
        }

        // Verification: an explicitly allowed gzip type is still accepted.
        file_put_contents($file, gzencode('payload'));
        set_config('allowedmimetypes', 'application/gzip;application/x-gzip', 'antivirus_mimeblocker');
        $this->assertEquals(scanner::SCAN_RESULT_OK, (new scanner())->scan_file($file, 'coursework.gz'));
    }
}
