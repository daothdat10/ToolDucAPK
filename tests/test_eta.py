import unittest

from ducapk import runner
from ducapk.eta import ProgressEta, format_duration


class EtaTests(unittest.TestCase):
    def test_rate_and_remaining_from_recent_window(self):
        eta = ProgressEta()
        for second in range(0, 61, 10):
            eta.update(second * 10, 10_000, float(second))  # 10 functions/s
        self.assertAlmostEqual(eta.rate(), 10.0)
        self.assertAlmostEqual(eta.remaining_seconds(), (10_000 - 600) / 10)

    def test_needs_some_time_before_estimating(self):
        eta = ProgressEta()
        eta.update(10, 100, 0.0)
        eta.update(20, 100, 5.0)
        self.assertIsNone(eta.remaining_seconds())

    def test_out_of_order_counters_do_not_reset(self):
        eta = ProgressEta()
        for second, current in ((0, 0), (10, 100), (20, 202), (21, 201), (30, 300)):
            eta.update(current, 1000, float(second))
        self.assertEqual(eta.elapsed_seconds(30.0), 30.0)
        self.assertAlmostEqual(eta.rate(), 10.0)

    def test_new_pass_resets_estimate(self):
        eta = ProgressEta()
        eta.update(500, 1000, 0.0)
        eta.update(900, 1000, 40.0)
        eta.update(10, 35, 41.0)  # retry pass with a different total
        self.assertIsNone(eta.rate())

    def test_old_samples_leave_the_window(self):
        eta = ProgressEta()
        for second in range(0, 600, 5):          # slow first 10 minutes: 1 function/s
            eta.update(second, 100_000, float(second))
        for second in range(600, 1201, 5):       # then 10 functions/s
            eta.update(600 + (second - 600) * 10, 100_000, float(second))
        self.assertAlmostEqual(eta.rate(), 10.0, delta=0.5)

    def test_format_duration(self):
        self.assertEqual(format_duration(45), "45 giây")
        self.assertEqual(format_duration(125), "2 phút 05 giây")
        self.assertEqual(format_duration(3900), "1 giờ 05 phút")

    def test_runner_logs_eta_each_thousand(self):
        messages = []
        runner._reset_eta()
        clock = iter(float(i) for i in range(0, 1000, 20))
        original = runner.time.monotonic
        runner.time.monotonic = lambda: next(clock)
        try:
            for current in (500, 999, 1001, 1500, 1999, 2003):
                runner._report_eta(f"INFO DUCAPK_PROGRESS {current}/5000 ok=1", messages.append)
        finally:
            runner.time.monotonic = original
        self.assertEqual(len(messages), 2)
        self.assertTrue(all(message.startswith("ETA: ") for message in messages))
        self.assertIn("2,003/5,000", messages[-1])


if __name__ == "__main__":
    unittest.main()
