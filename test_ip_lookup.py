import unittest
from ip_lookup_enhanced import IPLookupTool
import os
import tempfile
from unittest.mock import patch, Mock

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

    def test_redis_health(self):
        health = self.tool.redis_health()
        self.assertIn(health['status'], ['up', 'down', 'error'])

    def test_api_failure(self):
        with patch('requests.get', side_effect=Exception("Timeout")):
            data = self.tool.get_ip_info('8.8.8.8')
            self.assertIsNone(data)

    def test_invalid_api_key(self):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {'error': 'Invalid API key'}
        with patch('requests.get', return_value=mock_response):
            tool = IPLookupTool(api_token='INVALID_KEY')
            data = tool.get_ip_info('8.8.8.8')
            self.assertTrue(data is None or ('error' in data and 'Invalid API key' in str(data['error'])))

    def test_batch_mode(self):
        ips = ['8.8.8.8', '1.1.1.1', '256.256.256.256']
        results = self.tool.lookup_multiple_ips(ips)
        self.assertIn('8.8.8.8', results)
        self.assertIn('1.1.1.1', results)
        self.assertIsNone(results.get('256.256.256.256'))

    def test_json_parsing_error(self):
        # Simulate bad JSON in cache
        key = 'ipinfo:9.9.9.9'
        if self.tool.redis_available:
            self.tool.redis_client.set(key, '{bad json')
            data = self.tool._get_from_cache('9.9.9.9')
            self.assertIsNone(data)

    def test_missing_json_file(self):
        # Simulate missing file for batch mode
        with self.assertRaises(FileNotFoundError):
            self.tool.lookup_multiple_ips(open('nonexistent_file.txt').readlines())

if __name__ == "__main__":
    unittest.main()
