#!/usr/bin/env python3
"""
Simple test script for the IP lookup tool
"""

from ip_lookup import IPLookupTool

def test_ip_validation():
    """Test IP address validation"""
    tool = IPLookupTool()

    # Valid IPv4 addresses
    assert tool.validate_ip_address("8.8.8.8") == True
    assert tool.validate_ip_address("192.168.1.1") == True
    assert tool.validate_ip_address("255.255.255.255") == True

    # Invalid addresses
    assert tool.validate_ip_address("256.1.1.1") == False
    assert tool.validate_ip_address("not.an.ip") == False
    assert tool.validate_ip_address("") == False

    print("✅ IP validation tests passed!")

def test_api_call():
    """Test API call with a known good IP"""
    tool = IPLookupTool()

    # Test with Google DNS
    data = tool.get_ip_info("8.8.8.8")

    if data:
        print("✅ API call successful!")
        print(f"📍 IP: {data.get('ip')}")
        print(f"🏢 Org: {data.get('org')}")
        print(f"🌍 Country: {data.get('country')}")
    else:
        print("❌ API call failed")

if __name__ == "__main__":
    print("🧪 Running IP Lookup Tool Tests...")
    print("-" * 40)

    test_ip_validation()
    test_api_call()

    print("-" * 40)
    print("✅ All tests completed!")