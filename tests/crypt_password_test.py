import unittest
from passman import encrypt_password, decrypt_password


class CryptPasswordTest(unittest.TestCase):
    def test_encrypted_password_length(self):
        self.assertEqual(len(encrypt_password(b"salt", "Password", "MyMasterPassword")), 32)
    
    def test_encryption_1(self):
        self.assertEqual(decrypt_password(b"salt", encrypt_password(b"salt", "Password", "MyMasterPassword"), "MyMasterPassword").decode("utf-8"), "Password")

    def test_encryption_2(self):
        self.assertEqual(decrypt_password(b"newsalt", encrypt_password(b"newsalt", "NewPassword", "MyMasterPassword"), "MyMasterPassword").decode("utf-8"), "NewPassword")
        

if __name__ == '__main__':
    unittest.main()