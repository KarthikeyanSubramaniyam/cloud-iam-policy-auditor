import unittest
from scanner import audit

class ScannerTests(unittest.TestCase):
    def test_security_cases(self):
        self.assertEqual(len(audit({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}})), 2)
        self.assertEqual(audit({"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}), [])
        self.assertEqual(audit({"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/*"}]}), [])

if __name__ == "__main__":
    unittest.main()

