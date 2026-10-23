
import unittest

from qber_detector import assess_qber


class TestQBERDetector(unittest.TestCase):

    def test_zero_error(self):
        result = assess_qber(0.0)
        self.assertEqual(result.status, "BELOW_THRESHOLD")
        self.assertFalse(result.alert)

    def test_below_threshold(self):
        result = assess_qber(0.05)
        self.assertFalse(result.alert)

    def test_exact_threshold(self):
        result = assess_qber(0.11)
        self.assertFalse(result.alert)

    def test_above_threshold(self):
        result = assess_qber(0.25)
        self.assertEqual(result.status, "HIGH_ERROR_RATE")
        self.assertTrue(result.alert)

    def test_rejects_invalid_qber(self):
        for value in (-0.1, 1.1, float("nan"), float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    assess_qber(value)

    def test_rejects_invalid_threshold(self):
        for value in (0.0, 1.0, -0.1, 1.1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    assess_qber(0.1, value)


if __name__ == "__main__":
    unittest.main()
