import unittest
from idps.engine import inspect_input, init_patterns

class TestEngine(unittest.TestCase):
    def setUp(self):
        self.patterns = init_patterns()

    def test_safe(self):
        v = inspect_input("alice", self.patterns)
        self.assertFalse(v["malicious"])

    def test_union(self):
        v = inspect_input("UNION SELECT * FROM users", self.patterns)
        self.assertTrue(v["malicious"])

    def test_or_true(self):
        v = inspect_input("' OR 1=1 --", self.patterns)
        self.assertTrue(v["malicious"])

if __name__ == '__main__':
    unittest.main()
