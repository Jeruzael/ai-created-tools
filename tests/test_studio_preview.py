"""Ensure the human UI preview cannot accidentally collect machine diagnostics."""

import unittest

from studio_preview import FIXTURE_ROOT, dashboard, fixture_record, preview_environment


class StudioPreviewTests(unittest.TestCase):
    def test_fixture_uses_existing_saved_record_contract_and_synthetic_paths(self):
        record = fixture_record()
        self.assertIs(dashboard.validate_scan_record_payload(record), record)
        self.assertEqual(record['root'], FIXTURE_ROOT)
        self.assertEqual(len(record['result']['top_folders']), 280)
        self.assertTrue(all(row['path'].startswith(FIXTURE_ROOT) for row in record['result']['biggest_files']))

    def test_preview_isolated_history_and_native_collectors_are_disabled(self):
        with preview_environment() as app:
            self.assertEqual(len(app.history()), 4)
            self.assertEqual(dashboard.get_process_snapshot(), [])
            for action in (lambda: app.start_security_check({}), app.installer_cache_review,
                           lambda: app.installer_backup_review_manifest({}), lambda: dashboard.get_process_detail(1)):
                with self.assertRaisesRegex(ValueError, 'preview'):
                    action()

    def test_preview_scan_preserves_booleans_cancel_and_shutdown_guards(self):
        with preview_environment() as app:
            result = app.start_scan({'root': FIXTURE_ROOT, 'acknowledgeSafety': True, 'includeReparse': False})
            self.assertIs(result['settings']['include_reparse'], False)
            self.assertTrue(result['active'])
            with self.assertRaises(RuntimeError):
                app.request_shutdown()
            self.assertEqual(app.cancel_scan()['status'], 'cancelled')
            self.assertEqual(app.request_shutdown()['status'], 'shutting_down')

    def test_preview_rejects_real_paths_invalid_booleans_and_missing_acknowledgement(self):
        with preview_environment(empty=True) as app:
            cases = ({'root': 'C:\\Users', 'acknowledgeSafety': True},
                     {'root': FIXTURE_ROOT, 'acknowledgeSafety': True, 'includeReparse': 'false'},
                     {'root': FIXTURE_ROOT, 'acknowledgeSafety': True, 'includeReparse': 0},
                     {'root': FIXTURE_ROOT, 'acknowledgeSafety': False})
            for data in cases:
                with self.subTest(data=data), self.assertRaises(ValueError):
                    app.start_scan(data)
                self.assertFalse(app.scan_status()['active'])
                self.assertIsNone(app._operation)

    def test_preview_completion_publishes_compatible_isolated_history(self):
        with preview_environment(empty=True) as app:
            app.start_scan({'root': FIXTURE_ROOT, 'acknowledgeSafety': True})
            for _ in range(6):
                result = app.scan_status()
            self.assertFalse(result['active'])
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(len(app.history()), 1)
            self.assertIsNone(app._operation)


if __name__ == '__main__':
    unittest.main()
