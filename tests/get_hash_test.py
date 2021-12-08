import unittest
from passman import get_hash


class MasterPassswordHashTest(unittest.TestCase):
    def test_hash_1(self):
        self.assertEqual(get_hash("Password"), "e7cf3ef4f17c3999a94f2c6f612e8a888e5b1026878e4e19398b23bd38ec221a")

    def test_hash_2(self):
        self.assertEqual(get_hash("MyMasterPassword"), "27c9e4cb64684a9af621ed71e33a9a3860ab38c6b251a69d03809d40ab312838")


if __name__ == '__main__':
    unittest.main()