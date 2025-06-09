import unittest
from ip_lookup_enhanced import IPLookupTool

class TestIPLookupTool(unittest.TestCase):
    def setUp(self):
        self.tool = IPLookupTool()

    def test_ip_validation(self):
        self.assertTrue(self.tool.validate_ip_address("8.8.8.8"))
        self.assertTrue(self.tool.validate_ip_address("192.168.1.1"))
        self.assertTrue(self.tool.validate_ip_address("255.255.255.255"))
        self.assertFalse(self.tool.validate_ip_address("256.1.1.1"))
        self.assertFalse(self.tool.validate_ip_address("not.an.ip"))
        self.assertFalse(self.tool.validate_ip_address(""))

    def test_api_call(self):
        data = self.tool.get_ip_info("8.8.8.8")
        self.assertIsInstance(data, dict)
        if data is not None and "error" in data:
            self.fail(f"API call failed: {data['error']}")
        if data is not None:
            self.assertEqual(data.get("ip"), "8.8.8.8")
        else:
            self.fail("API call returned None")

if __name__ == "__main__":
    unittest.main()
