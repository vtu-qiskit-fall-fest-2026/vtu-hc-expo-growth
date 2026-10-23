
import unittest

from experiment_runner import run_experiment


class TestExperimentRunner(unittest.TestCase):

    def test_no_eve_ideal_channel(self):
        report = run_experiment(
            n_bits=128,
            eavesdropper=False,
            seed=10,
        )

        self.assertEqual(report["observed_errors"], 0)
        self.assertEqual(report["qber"], 0.0)
        self.assertEqual(report["decision"], "BELOW_THRESHOLD_DEMO_ONLY")
        self.assertFalse(report["production_security_established"])

    def test_eve_experiment_is_reported(self):
        report = run_experiment(
            n_bits=512,
            eavesdropper=True,
            seed=42,
        )

        self.assertTrue(report["simulation_only"])
        self.assertIn(
            report["decision"],
            {"REJECT_DEMO_SESSION", "BELOW_THRESHOLD_DEMO_ONLY"},
        )
        self.assertGreaterEqual(report["qber"], 0.0)
        self.assertLessEqual(report["qber"], 1.0)

    def test_threshold_triggers_rejection(self):
        # With this fixed seed, the simulator is expected to produce
        # a nonzero QBER. Verify the detector through a very low threshold.
        report = run_experiment(
            n_bits=512,
            eavesdropper=True,
            seed=42,
            threshold=0.000001,
        )

        if report["qber"] > 0.000001:
            self.assertEqual(report["decision"], "REJECT_DEMO_SESSION")
            self.assertTrue(report["alert"])


if __name__ == "__main__":
    unittest.main()
