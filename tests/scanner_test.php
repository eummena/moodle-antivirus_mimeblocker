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
 * Tests for mimeblocker antivirus scanner class.
 *
 * @package    antivirus_mimeblocker
 * @category   test
 * @copyright  2026 MBS
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(\antivirus_mimeblocker\scanner::class)]
final class scanner_test extends \advanced_testcase {
    /** @var string Temporary file used in testing. */
    protected $tempfile;

    protected function setUp(): void {
        parent::setUp();
        $this->resetAfterTest();

        // Create tempfile.
        $tempfolder = make_request_directory(false);
        $this->tempfile = $tempfolder . '/' . rand();
        touch($this->tempfile);
    }

    protected function tearDown(): void {
        @unlink($this->tempfile);
        parent::tearDown();
    }

    /**
     * Helper: create a scanner mock with detect_mimetype and get_config stubbed.
     *
     * We mock detect_mimetype() because finfo_file() is always available in the
     * test environment and will always return a real MIME type. Mocking lets us
     * simulate undetectable files (null) and control the exact MIME type without
     * needing real files of each type on disk.
     *
     * @param string|null $mimetype The MIME type that detect_mimetype should return.
     * @param string $scanmode 'allow' or 'deny'.
     * @param string $mimetypes Semicolon-separated configured MIME types.
     * @return scanner
     */
    private function create_scanner_mock(?string $mimetype, string $scanmode, string $mimetypes): scanner {
        $antivirus = $this->getMockBuilder('\antivirus_mimeblocker\scanner')
            ->onlyMethods(['detect_mimetype', 'get_config'])
            ->getMock();

        $antivirus->method('detect_mimetype')->willReturn($mimetype);
        $configmap = [
            ['scanmode', $scanmode],
            ['mimetypes', $mimetypes],
        ];
        $antivirus->method('get_config')->willReturnMap($configmap);

        // Reinitialise the configured mimetypes from the mocked config via reflection,
        // since the property is protected.
        $reflection = new \ReflectionProperty($antivirus, 'configuredmimetypes');
        $reflection->setValue($antivirus, explode(';', trim($mimetypes)));

        return $antivirus;
    }

    /**
     * Helper: create a scanner with real MIME detection and only get_config stubbed.
     *
     * Unlike create_scanner_mock(), detect_mimetype() is NOT mocked, so finfo
     * inspects the actual file content. Used to verify content-based detection
     * end to end (e.g. a .txt file containing a shebang is not text/plain).
     *
     * @param string $scanmode 'allow' or 'deny'.
     * @param string $mimetypes Semicolon-separated configured MIME types.
     * @return scanner
     */
    private function create_scanner_real_detection(string $scanmode, string $mimetypes): scanner {
        $antivirus = $this->getMockBuilder('\antivirus_mimeblocker\scanner')
            ->onlyMethods(['get_config'])
            ->getMock();

        $configmap = [
            ['scanmode', $scanmode],
            ['mimetypes', $mimetypes],
        ];
        $antivirus->method('get_config')->willReturnMap($configmap);

        $reflection = new \ReflectionProperty($antivirus, 'configuredmimetypes');
        $reflection->setValue($antivirus, explode(';', trim($mimetypes)));

        return $antivirus;
    }

    /**
     * When MIME detection returns null (no detection function available),
     * the scanner should return SCAN_RESULT_ERROR regardless of scan mode.
     *
     * This means the admin's "Action on scan failure" setting decides
     * whether the upload is ultimately accepted or rejected — not the plugin.
     */
    public function test_scan_file_undetectable_mimetype_returns_error(): void {
        // In allow mode, undetectable MIME → ERROR.
        $scanner = $this->create_scanner_mock(null, 'allow', 'text/plain;image/png');
        $result = $scanner->scan_file($this->tempfile, 'testfile.txt');
        $this->assertEquals(scanner::SCAN_RESULT_ERROR, $result);
        $this->assertDebuggingCalled();

        // In deny mode, undetectable MIME → ERROR (NOT silently passing).
        $scanner = $this->create_scanner_mock(null, 'deny', 'application/x-msdownload');
        $result = $scanner->scan_file($this->tempfile, 'testfile.exe');
        $this->assertEquals(scanner::SCAN_RESULT_ERROR, $result);
        $this->assertDebuggingCalled();
    }

    /**
     * Allow mode: a file with an allowed MIME type should pass.
     */
    public function test_scan_file_allow_mode_allowed_type(): void {
        $scanner = $this->create_scanner_mock('text/plain', 'allow', 'text/plain;image/png');
        $result = $scanner->scan_file($this->tempfile, 'readme.txt');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $result);
    }

    /**
     * Allow mode: a file with a non-allowed MIME type should be blocked.
     */
    public function test_scan_file_allow_mode_blocked_type(): void {
        $scanner = $this->create_scanner_mock('application/x-msdownload', 'allow', 'text/plain;image/png');
        $result = $scanner->scan_file($this->tempfile, 'malware.exe');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * Deny mode: a file with a denied MIME type should be blocked.
     */
    public function test_scan_file_deny_mode_blocked_type(): void {
        $scanner = $this->create_scanner_mock('application/x-msdownload', 'deny', 'application/x-msdownload');
        $result = $scanner->scan_file($this->tempfile, 'malware.exe');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * Deny mode: a file with a non-denied MIME type should pass.
     */
    public function test_scan_file_deny_mode_allowed_type(): void {
        $scanner = $this->create_scanner_mock('text/plain', 'deny', 'application/x-msdownload');
        $result = $scanner->scan_file($this->tempfile, 'readme.txt');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $result);
    }

    /**
     * Unreadable file should return SCAN_RESULT_FOUND.
     */
    public function test_scan_file_not_readable(): void {
        $scanner = $this->create_scanner_mock('text/plain', 'allow', 'text/plain');
        $nonexistent = $this->tempfile . '_nonexistent';

        $result = $scanner->scan_file($nonexistent, 'missing.txt');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
        $this->assertDebuggingCalled();
    }

    /**
     * Invalid scanmode config should return SCAN_RESULT_FOUND.
     */
    public function test_scan_file_invalid_scanmode(): void {
        $scanner = $this->create_scanner_mock('text/plain', 'invalid', 'text/plain');

        $result = $scanner->scan_file($this->tempfile, 'readme.txt');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * When a blocked file is rejected, the temp file should still exist afterward
     * so the antivirus manager can quarantine it, and get_virus_found_message()
     * should return the structure the manager needs to display the error.
     */
    public function test_scan_file_blocked_does_not_delete_file(): void {
        $scanner = $this->create_scanner_mock('application/x-msdownload', 'allow', 'text/plain;image/png');
        $result = $scanner->scan_file($this->tempfile, 'malware.exe');

        // The manager expects SCAN_RESULT_FOUND to trigger quarantine + cleanup.
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);

        // The file must still exist so the manager can quarantine it before deleting.
        $this->assertFileExists($this->tempfile, 'Scanner should not delete the file — the antivirus manager handles cleanup');

        // The manager calls get_virus_found_message() to build the user-facing exception.
        $message = $scanner->get_virus_found_message();
        $this->assertArrayHasKey('string', $message);
        $this->assertArrayHasKey('component', $message);
        $this->assertArrayHasKey('placeholders', $message);
        $this->assertEquals('antivirus_mimeblocker', $message['component']);
        $this->assertEquals('virusfoundallow', $message['string']);
        $this->assertArrayHasKey('types', $message['placeholders']);
    }

    /**
     * Real detection: genuine plain text content in a .txt file passes in allow mode.
     *
     * This is the manual "Test 1" scenario: allow mode with
     * text/plain;image/png;application/pdf and a plain text upload.
     */
    public function test_scan_file_real_detection_plain_text(): void {
        $scanner = $this->create_scanner_real_detection('allow', 'text/plain;image/png;application/pdf');
        file_put_contents($this->tempfile, "Hallo Welt\nls -la\ncd /tmp\n");

        $result = $scanner->scan_file($this->tempfile, 'befehle.txt');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $result);
    }

    /**
     * Real detection: a .txt file starting with a shebang is detected as
     * text/x-shellscript by content, not text/plain, and therefore blocked
     * in allow mode. Detection is content-based, the extension is irrelevant.
     */
    public function test_scan_file_real_detection_shebang_in_txt_blocked(): void {
        $scanner = $this->create_scanner_real_detection('allow', 'text/plain;image/png;application/pdf');
        file_put_contents($this->tempfile, "#!/bin/bash\necho hallo\n");

        $result = $scanner->scan_file($this->tempfile, 'befehle.txt');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * Real detection: an empty file is detected as application/x-empty
     * and blocked in allow mode unless that type is configured.
     */
    public function test_scan_file_real_detection_empty_file_blocked(): void {
        $scanner = $this->create_scanner_real_detection('allow', 'text/plain;image/png;application/pdf');
        // Tempfile is created empty by setUp().

        $result = $scanner->scan_file($this->tempfile, 'leer.txt');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * Real detection: binary content (PNG magic bytes) is detected as image/png,
     * passing in allow mode and blocked in deny mode.
     */
    public function test_scan_file_real_detection_png(): void {
        // Minimal valid PNG header (signature + IHDR chunk).
        $png = "\x89PNG\r\n\x1a\n" . pack('N', 13) . 'IHDR'
            . pack('N', 1) . pack('N', 1) . "\x08\x02\x00\x00\x00" . pack('N', 0x907753de);
        file_put_contents($this->tempfile, $png);

        $scanner = $this->create_scanner_real_detection('allow', 'text/plain;image/png;application/pdf');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->tempfile, 'bild.png'));

        $scanner = $this->create_scanner_real_detection('deny', 'image/png');
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($this->tempfile, 'bild.png'));
    }

    /**
     * MoodleNet compatibility: an empty file detected as inode/x-empty with a
     * .log extension is treated as text/plain.
     */
    public function test_scan_file_empty_log_file_treated_as_text_plain(): void {
        $logfile = $this->tempfile . '.log';
        touch($logfile);

        $scanner = $this->create_scanner_mock('inode/x-empty', 'allow', 'text/plain');
        $result = $scanner->scan_file($logfile, 'backup.log');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $result);

        unlink($logfile);
    }

    /**
     * Gzip compatibility: gzip MIME types are treated as Moodle backup files.
     */
    public function test_scan_file_gzip_treated_as_moodle_backup(): void {
        $scanner = $this->create_scanner_mock('application/x-gzip', 'allow', 'application/vnd.moodle.backup');
        $result = $scanner->scan_file($this->tempfile, 'backup.mbz');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $result);

        $scanner = $this->create_scanner_mock('application/gzip', 'allow', 'application/vnd.moodle.backup');
        $result = $scanner->scan_file($this->tempfile, 'backup.mbz');
        $this->assertEquals(scanner::SCAN_RESULT_OK, $result);
    }

    /**
     * The user-facing message lists extensions for types Moodle knows, and falls
     * back to the MIME type string for types not in Moodle's file type registry
     * (e.g. executables configured in deny mode).
     */
    public function test_get_file_extensions_falls_back_to_mimetype(): void {
        $scanner = $this->create_scanner_mock(
            'application/x-dosexec',
            'deny',
            'application/pdf;application/x-dosexec;application/x-msdownload'
        );

        $this->assertEquals(
            'pdf, application/x-dosexec, application/x-msdownload',
            $scanner->get_file_extensions()
        );

        // The blocked-upload message must not end up with an empty type list.
        $this->assertEquals(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($this->tempfile, 'setup.exe'));
        $message = $scanner->get_virus_found_message();
        $this->assertEquals('virusfounddeny', $message['string']);
        $this->assertStringContainsString('application/x-dosexec', $message['placeholders']['types']);
    }
}
