import unittest
from passman import health_check


class HealthCheckTest(unittest.TestCase):
    def test_reused_passwords(self):
        self.assertEqual(health_check( ["password", "MyPassword", "P@ssw0rd", "MyPassword", "hD<4[pvnai"],
                                        {"google.com" : "password",
                                        "youtube.com" : "MyPassword",
                                        "instagram.com" : "P@ssw0rd",
                                        "stackoverflow.com" : "MyPassword",
                                        "github.com" : "hD<4[pvnai"})[0],
                                        ["youtube.com", "stackoverflow.com"])
    def test_weak_passwords(self):
        self.assertEqual(health_check( ["password", "MyPassword", "P@ssw0rd", "MyPassword", "hD<4[pvnai"], 
                                        {"google.com" : "password",
                                        "youtube.com" : "MyPassword",
                                        "instagram.com" : "P@ssw0rd",
                                        "stackoverflow.com" : "MyPassword",
                                        "github.com" : "hD<4[pvnai"})[1], 
                                        ["google.com", "youtube.com", "instagram.com", "stackoverflow.com"])


if __name__ == '__main__':
    unittest.main()