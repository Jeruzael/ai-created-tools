import contextlib
import io
import unittest
from unittest import mock

import verify_project


class StrictVerificationRunnerTests(unittest.TestCase):
    def run_fixture(self, case):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(case)
        with mock.patch.object(unittest.defaultTestLoader, "discover", return_value=suite), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return verify_project.run_tests()

    def test_unexpected_skip_cannot_be_successful_verification(self):
        class Skipped(unittest.TestCase):
            @unittest.skip("fixture unavailable")
            def test_fixture(self):
                self.fail("must be skipped")
        self.assertFalse(self.run_fixture(Skipped))

    def test_expected_failure_cannot_hide_a_release_failure(self):
        class ExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def test_fixture(self):
                self.assertEqual(1, 2)
        self.assertFalse(self.run_fixture(ExpectedFailure))

    def test_unexpected_success_is_not_accepted(self):
        class UnexpectedSuccess(unittest.TestCase):
            @unittest.expectedFailure
            def test_fixture(self):
                self.assertEqual(1, 1)
        self.assertFalse(self.run_fixture(UnexpectedSuccess))

    def test_clean_suite_is_accepted(self):
        class Passing(unittest.TestCase):
            def test_fixture(self):
                self.assertEqual(1, 1)
        self.assertTrue(self.run_fixture(Passing))

    def test_empty_discovery_is_not_a_passing_release_check(self):
        class NoTests(unittest.TestCase):
            pass
        self.assertFalse(self.run_fixture(NoTests))


if __name__ == "__main__":
    unittest.main()
