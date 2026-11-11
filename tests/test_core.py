import unittest

from log_closure_capture_detector import (
    DEFAULT_CONFIG,
    Detector,
    DetectorConfig,
    Finding,
    inspect_message,
)


class ConfigTests(unittest.TestCase):
    def test_defaults_are_sane(self):
        cfg = DetectorConfig()
        self.assertEqual(cfg.max_repr_chars, 512)
        self.assertEqual(cfg.max_nesting_depth, 32)
        self.assertIn("<function ", cfg.closure_markers)

    def test_negative_max_repr_chars_rejected(self):
        with self.assertRaises(ValueError):
            DetectorConfig(max_repr_chars=-1)

    def test_zero_max_nesting_depth_rejected(self):
        with self.assertRaises(ValueError):
            DetectorConfig(max_nesting_depth=0)

    def test_default_config_is_a_detector_config(self):
        self.assertIsInstance(DEFAULT_CONFIG, DetectorConfig)


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.det = Detector()

    def test_plain_message_has_no_findings(self):
        self.assertEqual(self.det.inspect("user logged in"), [])

    def test_function_repr_is_flagged(self):
        msg = "handler=<function handle at 0x7f00>"
        findings = self.det.inspect(msg)
        kinds = [f.kind for f in findings]
        self.assertIn("closure", kinds)
        closure = [f for f in findings if f.kind == "closure"][0]
        self.assertEqual(closure.offset, msg.index("<function "))

    def test_bound_method_repr_is_flagged(self):
        findings = self.det.inspect("cb=<bound method Foo.bar of <Foo>>")
        self.assertTrue(any(f.kind == "closure" for f in findings))

    def test_lambda_literal_is_flagged(self):
        findings = self.det.inspect("callback=lambda x: x")
        self.assertTrue(any(f.kind == "closure" for f in findings))

    def test_multiple_closure_markers_each_reported(self):
        msg = "a=<function a> b=<function b>"
        closures = [f for f in self.det.inspect(msg) if f.kind == "closure"]
        self.assertEqual(len(closures), 2)

    def test_is_suspicious_matches_inspect(self):
        self.assertTrue(self.det.is_suspicious("x=<function f>"))
        self.assertFalse(self.det.is_suspicious("just a message"))


class MutableReprTests(unittest.TestCase):
    def setUp(self):
        self.det = Detector()

    def test_dict_repr_marker_flagged(self):
        findings = self.det.inspect("payload=<dict object at 0x1>")
        self.assertTrue(any(f.kind == "mutable_repr" for f in findings))

    def test_list_repr_marker_flagged(self):
        findings = self.det.inspect("items=<list object at 0x2>")
        self.assertTrue(any(f.kind == "mutable_repr" for f in findings))

    def test_small_literal_container_not_flagged(self):
        # A short balanced literal is below the length threshold, so no finding.
        self.assertEqual(self.det.inspect("value={1}"), [])

    def test_large_literal_container_flagged(self):
        inner = ",".join(str(i) for i in range(20))
        msg = "value={" + inner + "}"
        findings = self.det.inspect(msg)
        self.assertTrue(any(f.kind == "mutable_repr" for f in findings))

    def test_unbalanced_bracket_not_flagged_as_container(self):
        # An unmatched opening bracket is prose, not a container repr.
        self.assertEqual(self.det.inspect("value={1"), [])

    def test_nesting_depth_limit_reports_finding(self):
        cfg = DetectorConfig(max_nesting_depth=3)
        det = Detector(cfg)
        msg = "x=" + "[" * 10 + "]" * 10
        findings = det.inspect(msg)
        self.assertTrue(any(f.kind == "mutable_repr" for f in findings))


class LargePayloadTests(unittest.TestCase):
    def test_short_message_not_flagged_for_size(self):
        det = Detector()
        findings = det.inspect("short")
        self.assertFalse(any(f.kind == "large_payload" for f in findings))

    def test_long_message_flagged_for_size(self):
        cfg = DetectorConfig(max_repr_chars=10)
        det = Detector(cfg)
        findings = det.inspect("x" * 11)
        large = [f for f in findings if f.kind == "large_payload"]
        self.assertEqual(len(large), 1)
        self.assertEqual(large[0].offset, -1)

    def test_exactly_at_limit_not_flagged(self):
        cfg = DetectorConfig(max_repr_chars=10)
        det = Detector(cfg)
        findings = det.inspect("x" * 10)
        self.assertFalse(any(f.kind == "large_payload" for f in findings))


class CoercionTests(unittest.TestCase):
    def test_non_string_input_is_coerced(self):
        det = Detector()
        findings = det.inspect(12345)
        self.assertEqual(findings, [])

    def test_non_string_with_marker_is_flagged(self):
        det = Detector()
        findings = det.inspect("<function f>")
        self.assertTrue(any(f.kind == "closure" for f in findings))


class ModuleLevelTests(unittest.TestCase):
    def test_inspect_message_returns_findings(self):
        findings = inspect_message("x=<function f>")
        self.assertTrue(any(f.kind == "closure" for f in findings))

    def test_inspect_message_accepts_config(self):
        cfg = DetectorConfig(max_repr_chars=3)
        findings = inspect_message("abcd", cfg)
        self.assertTrue(any(f.kind == "large_payload" for f in findings))

    def test_finding_is_frozen(self):
        f = Finding(kind="closure", detail="d", offset=0)
        with self.assertRaises(Exception):
            f.kind = "other"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
