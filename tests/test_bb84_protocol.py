
import unittest
from bb84_protocol import run_bb84


class TestBB84(unittest.TestCase):

    def test_no_eve(self):
        result = run_bb84(128, False, 10)
        self.assertGreater(result["sifted_bits"], 0)
        self.assertEqual(result["errors"], 0)
        self.assertTrue(result["key_matches"])

    def test_eve_experiment(self):
        result = run_bb84(512, True, 42)
        self.assertGreater(result["sifted_bits"], 0)
        self.assertGreaterEqual(result["qber"], 0.0)
        self.assertLessEqual(result["qber"], 1.0)

    def test_reproducible(self):
        a = run_bb84(64, True, 123)
        b = run_bb84(64, True, 123)
        self.assertEqual(a["errors"], b["errors"])
        self.assertEqual(a["qber"], b["qber"])

    def test_invalid_bit_count(self):
        with self.assertRaises(ValueError):
            run_bb84(0)

    def test_invalid_attack_flag(self):
        with self.assertRaises(ValueError):
            run_bb84(eavesdropper="yes")


if __name__ == "__main__":
    unittest.main()
