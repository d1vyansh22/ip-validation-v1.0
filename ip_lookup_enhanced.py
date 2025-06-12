#!/usr/bin/env python3
"""
IP Address Information Lookup Tool
==================================

A comprehensive tool for retrieving IP address information using the IPInfo API.
Supports both free (unauthenticated) and authenticated requests.

Author: IP Lookup Tool
Version: 1.0.0
"""

import concurrent.futures
import requests
import json
import sys
import re
import time
import argparse
import redis
from dotenv import load_dotenv
from typing import cast, Optional, Dict, Any

import os
load_dotenv()  # Load .env file
API_KEY = os.getenv('IPINFO_API_KEY') # Get API key from environment variable
API_TIMEOUT = int(os.getenv('API_TIMEOUT', 10))  # Default to 10 if not set
MAX_RETRIES = int(os.getenv('MAX_RETRIES', 3))   # Default to 3 if not set

# Redis configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')  # Default to localhost if not set
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))  # Default to 6379 if not set   
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)  # Optional Redis password
CACHE_TTL = int(os.getenv('CACHE_TTL', 86400))  # Default to 24 hours if not set
MAX_CONCURRENT_REQUESTS = int(os.getenv('MAX_CONCURRENT_REQUESTS', 10))  # Default to 10 if not set

class IPLookupTool:
    """Main class for IP address lookup functionality with Redis caching and retry logic"""

    def __init__(self, api_token: Optional[str] = None, timeout: Optional[int] = None):
        """
        Initialize the IP lookup tool

        Args:
            api_token: Optional IPInfo API token for authenticated requests
            timeout: Request timeout in seconds
        """
        self.api_token = api_token or API_KEY  # Use API key from environment variable or provided argument
        self.timeout = timeout if timeout is not None else API_TIMEOUT
        self.base_url = "https://ipinfo.io"

        #Redis configuration
        self.redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            decode_responses=True,    # Critical for type safety
            socket_timeout=3,         # Fail fast on network issues
            socket_connect_timeout=3, # Quick failure if Redis down
            protocol=3                # Explicit protocol version
        )
        self.cache_ttl =  CACHE_TTL # 24 hours default
        self.max_workers = MAX_CONCURRENT_REQUESTS

    def validate_ip_address(self, ip: str) -> bool:
        """
        Validate IP address format (IPv4 and IPv6)

        Args:
            ip: IP address string to validate

        Returns:
            bool: True if valid IP address, False otherwise
        """
        # IPv4 pattern
        ipv4_pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'

        # IPv6 pattern (simplified but covers most cases)
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^([0-9a-fA-F]{1,4}:){0,6}::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'

        return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

    def _get_from_cache(self, ip: str) -> Optional[Dict]:
        """Retrieve cached IP data"""
        try:
            # Explicit type annotation for Redis response
            cached: Optional[str] = cast(Optional[str], self.redis_client.get(ip))
            return json.loads(cached) if cached else None
        except (redis.RedisError,json.JSONDecodeError):
            return None

    def _store_in_cache(self, ip: str, data: Dict) -> None:
        """Store IP data in cache"""
        try:
            self.redis_client.setex(
                name=ip,
                time=self.cache_ttl,
                value=json.dumps(data)
            )
        except redis.RedisError:
            pass

    def get_ip_info(self, ip_address: str, max_retries: Optional[int] = None) -> Optional[Dict[Any, Any]]:
        """
        Retrieve IP information from IPInfo API with cache support and retry logic

        Args:
            ip_address: IP address to lookup
            max_retries: Maximum number of retry attempts

        Returns:
            dict: IP information or None if failed
        """
        max_retries = max_retries if max_retries is not None else MAX_RETRIES
        
        # Check cache first
        if cached := self._get_from_cache(ip_address):
            return cached
        
        # API call logic with retries
        for attempt in range(max_retries):
            try:
                # Construct URL
                url = f"{self.base_url}/{ip_address}/json"

                # Prepare headers
                headers = {}
                if self.api_token:
                    headers['Authorization'] = f'Bearer {self.api_token}'

                # Make API request
                response = requests.get(url, headers=headers, timeout=self.timeout)

                # Check response status
                if response.status_code == 200:
                    data = response.json()
                    self._store_in_cache(ip_address, data)
                    return data
                elif response.status_code == 429:
                    print(f"⚠️  Rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        print(f"⏳ Waiting {wait_time} seconds before retry...")
                        time.sleep(wait_time)
                elif response.status_code == 404:
                    print(f"❌ IP address not found: {ip_address}")
                    return None
                else:
                    print(f"❌ HTTP Error {response.status_code}: {response.text}")
                    return None

            except requests.exceptions.Timeout:
                print(f"⏰ Timeout on attempt {attempt + 1}/{max_retries}")
            except requests.exceptions.ConnectionError:
                print(f"🌐 Connection error on attempt {attempt + 1}/{max_retries}")
            except requests.exceptions.RequestException as e:
                print(f"📡 Request error: {e}")
                return None
            except json.JSONDecodeError as e:
                print(f"📋 JSON decode error: {e}")
                return None

            # Wait before retry (exponential backoff)
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(f"⏳ Retrying in {wait_time} seconds...")
                time.sleep(wait_time)

        print(f"❌ Failed to retrieve information after {max_retries} attempts")
        return None

    def format_output(self, data: Dict[Any, Any], show_raw: bool = False) -> str:
        """
        Format IP information for terminal display

        Args:
            data: IP information dictionary
            show_raw: Whether to include raw JSON output

        Returns:
            str: Formatted output string
        """
        if not data:
            return "❌ No data available"

        output = "\n" + "=" * 60
        output += "\n" + " " * 15 + "🌐 IP ADDRESS INFORMATION"
        output += "\n" + "=" * 60 + "\n"

        # Basic information
        output += f"📍 IP Address:      {data.get('ip', 'N/A')}\n"
        output += f"🏠 Hostname:        {data.get('hostname', 'N/A')}\n"

        # Location information
        output += f"🌍 Country:         {data.get('country', 'N/A')}"
        if 'country_name' in data:
            output += f" ({data['country_name']})"
        output += "\n"

        output += f"🗺️  Region:          {data.get('region', 'N/A')}\n"
        output += f"🏙️  City:            {data.get('city', 'N/A')}\n"
        output += f"📮 Postal Code:     {data.get('postal', 'N/A')}\n"

        # Coordinates
        if 'loc' in data and data['loc']:
            try:
                coords = data['loc'].split(',')
                if len(coords) == 2:
                    output += f"📍 Latitude:        {coords[0]}\n"
                    output += f"📍 Longitude:       {coords[1]}\n"
            except (ValueError, IndexError):
                output += f"📍 Coordinates:     {data['loc']}\n"

        # Network information
        output += f"🏢 Organization:    {data.get('org', 'N/A')}\n"
        output += f"🕐 Timezone:        {data.get('timezone', 'N/A')}\n"

        # Additional network details
        if 'asn' in data:
            output += f"🔢 ASN:             {data['asn']}\n"
        if 'as_name' in data:
            output += f"🏷️  AS Name:         {data['as_name']}\n"
        if 'as_domain' in data:
            output += f"🌐 AS Domain:       {data['as_domain']}\n"

        # Privacy and security information
        if 'privacy' in data:
            privacy = data['privacy']
            if any(privacy.values()):
                output += "\n" + "🔒 Privacy/Security Information:" + "\n"
                if privacy.get('vpn'):
                    output += "   • VPN detected\n"
                if privacy.get('proxy'):
                    output += "   • Proxy detected\n"
                if privacy.get('tor'):
                    output += "   • Tor network detected\n"
                if privacy.get('relay'):
                    output += "   • Relay detected\n"
                if privacy.get('hosting'):
                    output += "   • Hosting service detected\n"

        output += "\n" + "=" * 60 + "\n"

        # Raw JSON output if requested
        if show_raw:
            output += "\n📋 Raw JSON Response:\n"
            output += "-" * 40 + "\n"
            output += json.dumps(data, indent=2)
            output += "\n" + "-" * 40 + "\n"

        return output

    def lookup_multiple_ips(self, ip_list: list) -> Dict[str, Any]:
        """
        Lookup multiple IP addresses with caching amd concurrent requests

        Args:
            ip_list: List of IP addresses to lookup

        Returns:
            dict: Results for each IP address
        """
        results = {}
        total = len(ip_list)
        futures = {}

        print(f"🔍 Looking up {total} IP address(es)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # First pass: Check cache and submit API calls for misses
            for ip in ip_list:
                if not self.validate_ip_address(ip):
                    continue
                
                if cached := self._get_from_cache(ip):
                    results[ip] = cached
                else:
                    futures[ip] = executor.submit(self.get_ip_info, ip)

            # Second pass: Process in original order with preserved prints
            for i, ip in enumerate(ip_list, 1):
                print(f"\n📍 Processing {i}/{total}: {ip}")

                if not self.validate_ip_address(ip):
                    print(f"❌ Invalid IP format: {ip}")
                    results[ip] = None
                    continue

                if ip in futures:
                    results[ip] = futures[ip].result()
                    # Rate limit only actual API calls
                    if i < total and not self._get_from_cache(ip):
                        time.sleep(0.2)  # Reduced delay for concurrent calls
        return results

    def interactive_mode(self):
        """Run the tool in interactive mode"""
        print("\n🌐 IP Address Information Lookup Tool")
        print("=====================================")
        print("Enter IP addresses to get detailed information.")
        print("Commands: 'quit', 'exit', 'q' to exit")

        if self.api_token:
            print("✅ Using authenticated API (unlimited requests)")
        else:
            print("⚠️  Using free API (limited to 1000 requests/day per IP)")

        while True:
            try:
                ip_input = input("\n🔍 Enter IP address: ").strip()

                if ip_input.lower() in ['quit', 'exit', 'q', '']:
                    print("\n👋 Goodbye!")
                    break

                # Handle multiple IPs separated by commas or spaces
                ip_list = [ip.strip() for ip in re.split(r'[,\s]+', ip_input.strip()) if ip.strip()]
                
                if len(ip_list) == 1:
                    ip = ip_list[0]
                    if not self.validate_ip_address(ip):
                        print("❌ Invalid IP address format")
                        continue

                    print(f"⏳ Looking up: {ip}")
                    data = self.get_ip_info(ip)

                    if data:
                        print(self.format_output(data))

                        # Ask for raw JSON
                        show_raw = input("\n📋 Show raw JSON? (y/n): ").strip().lower()
                        if show_raw == 'y':
                            print(json.dumps(data, indent=2))
                    else:
                        print("❌ Failed to retrieve information")

                elif len(ip_list) > 1:
                    # Multiple IP lookup
                    results = self.lookup_multiple_ips(ip_list)

                    print("\n" + "=" * 60)
                    print("📊 MULTIPLE IP LOOKUP RESULTS")
                    print("=" * 60)

                    for ip, data in results.items():
                        if data:
                            print(self.format_output(data))
                        else:
                            print(f"\n❌ Failed to get information for: {ip}\n")

            except KeyboardInterrupt:
                print("\n\n👋 Interrupted by user. Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Unexpected error: {e}")


def main():
    """Updated Main function with command line argument support and cache state"""
    parser = argparse.ArgumentParser(
        description="IP Address Information Lookup Tool with Redis caching",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ip_lookup.py                   # Interactive mode
  python ip_lookup.py 8.8.8.8           # Single IP lookup
  python ip_lookup.py --json 8.8.8.8    # JSON output
  python ip_lookup.py --token YOUR_TOKEN # With authentication
        """
    )

    parser.add_argument('ip', nargs='?', help='IP address to lookup')
    parser.add_argument('--token', '-t', help='IPInfo API token for authentication')
    parser.add_argument('--json', '-j', action='store_true', help='Output raw JSON')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10s)')

    args = parser.parse_args()

    # Initialize the tool
    tool = IPLookupTool(api_token=args.token, timeout=args.timeout)

    if args.ip:
        # Single IP mode
        if not tool.validate_ip_address(args.ip):
            print("❌ Invalid IP address format")
            sys.exit(1)

        print(f"🔍 Looking up: {args.ip}")
        data = tool.get_ip_info(args.ip)

        if data:
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                print(tool.format_output(data))
        else:
            print("❌ Failed to retrieve information")
            sys.exit(1)
    else:
        # Interactive mode
        tool.interactive_mode()


if __name__ == "__main__":
    main()