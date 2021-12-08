import re
import unittest
from passman import pass_gen

def secure_check(password):
    length_check = len(password) > 8
    digits_check = re.search(r"\d", password) is not None
    lowercase_check = re.search(r"[a-z]", password) is not None
    uppercase_check = re.search(r"[A-Z]", password) is not None
    symbol_check = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is not None

    result = (length_check and digits_check and lowercase_check and uppercase_check and symbol_check)

    return result


class PassGenTest(unittest.TestCase):
    def test_pass_gen_1(self):
        self.assertEqual(secure_check(pass_gen(10)), True)
    
    def test_pass_gen_2(self):
        self.assertEqual(secure_check(pass_gen(20)), True)


if __name__ == '__main__':
    unittest.main()