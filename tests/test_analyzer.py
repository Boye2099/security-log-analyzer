import tempfile
import unittest

from analyzer import analyze_log


class TestLogAnalyzer(unittest.TestCase):

    def test_detects_repeated_failures(self):

        log_data = (
            "timestamp,username,event,source_ip\n"
            "2026-08-10T09:00:00Z,bob,failed_login,192.0.2.20\n"
            "2026-08-10T09:01:00Z,bob,failed_login,192.0.2.20\n"
            "2026-08-10T09:02:00Z,bob,failed_login,192.0.2.20\n"
        )

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False
        ) as file:

            file.write(log_data)
            file_path = file.name

        report = analyze_log(
            file_path,
            threshold=3
        )

        self.assertEqual(
            report["failed_logins"],
            3
        )

        self.assertEqual(
            len(report["flagged_sources"]),
            1
        )


if __name__ == "__main__":
    unittest.main()
