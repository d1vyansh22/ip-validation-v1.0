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
import logging

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

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

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
        self.api_metrics = {'calls': 0, 'failures': 0, 'total_time': 0.0}
        self.redis_metrics = {'hits': 0, 'misses': 0, 'failures': 0}

        try:
            self.redis_client.ping()
            self.redis_available = True
        except redis.RedisError as e:
            logging.error(f"Redis unavailable: {e}")
            self.redis_available = False

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

    def redis_health(self):
        """Return Redis health and info."""
        if not self.redis_available:
            return {'status': 'down'}
        try:
            info = self.redis_client.info()
            return {'status': 'up', 'info': info}
        except redis.RedisError as e:
            return {'status': 'error', 'error': str(e)}

    def api_metrics_info(self):
        """Return API call efficiency metrics."""
        calls = self.api_metrics['calls']
        avg_time = self.api_metrics['total_time'] / calls if calls else 0
        return {
            'calls': calls,
            'failures': self.api_metrics['failures'],
            'avg_time': avg_time
        }

    def _get_from_cache(self, ip: str) -> Optional[Dict]:
        key = f"ipinfo:{ip}"
        try:
            cached: Optional[str] = cast(Optional[str], self.redis_client.get(key))
            if cached:
                self.redis_metrics['hits'] += 1
            else:
                self.redis_metrics['misses'] += 1
            return json.loads(cached) if cached else None
        except (redis.RedisError, json.JSONDecodeError) as e:
            self.redis_metrics['failures'] += 1
            logging.warning(f"Redis cache error: {e}")
            return None

    def _store_in_cache(self, ip: str, data: Dict) -> None:
        key = f"ipinfo:{ip}"
        try:
            self.redis_client.setex(
                name=key,
                time=self.cache_ttl,
                value=json.dumps(data)
            )
        except redis.RedisError as e:
            self.redis_metrics['failures'] += 1
            logging.warning(f"Redis store error: {e}")

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
                start = time.time()
                response = requests.get(url, headers=headers, timeout=self.timeout)
                elapsed = time.time() - start
                self.api_metrics['calls'] += 1
                self.api_metrics['total_time'] += elapsed

                # Check response status
                if response.status_code == 200:
                    data = response.json()
                    self._store_in_cache(ip_address, data)
                    return data
                elif response.status_code == 429:
                    logging.warning(f"⚠️  Rate limit exceeded. Attempt {attempt + 1}/{max_retries}")
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logging.info(f"⏳ Waiting {wait_time} seconds before retry...")
                        time.sleep(wait_time)
                elif response.status_code == 404:
                    logging.error(f"❌ IP address not found: {ip_address}")
                    return None
                else:
                    logging.error(f"❌ HTTP Error {response.status_code}: {response.text}")
                    return None

            except requests.exceptions.Timeout:
                logging.error(f"⏰ Timeout on attempt {attempt + 1}/{max_retries}")
            except requests.exceptions.ConnectionError:
                logging.error(f"🌐 Connection error on attempt {attempt + 1}/{max_retries}")
            except requests.exceptions.RequestException as e:
                logging.error(f"📡 Request error: {e}")
                return None
            except json.JSONDecodeError as e:
                logging.error(f"📋 JSON decode error: {e}")
                return None

            # Wait before retry (exponential backoff)
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logging.info(f"⏳ Retrying in {wait_time} seconds...")
                time.sleep(wait_time)

        logging.error(f"❌ Failed to retrieve information after {max_retries} attempts")
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

        logging.info(f"🔍 Looking up {total} IP address(es)...")
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
                logging.info(f"\n📍 Processing {i}/{total}: {ip}")

                if not self.validate_ip_address(ip):
                    logging.error(f"❌ Invalid IP format: {ip}")
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
        logging.info("\n🌐 IP Address Information Lookup Tool")
        logging.info("=====================================")
        logging.info("Enter IP addresses to get detailed information.")
        logging.info("Commands: 'quit', 'exit', 'q' to exit")

        if self.api_token:
            logging.info("✅ Using authenticated API (unlimited requests)")
        else:
            logging.info("⚠️  Using free API (limited to 1000 requests/day per IP)")

        while True:
            try:
                ip_input = input("\n🔍 Enter IP address: ").strip()

                if ip_input.lower() in ['quit', 'exit', 'q', '']:
                    logging.info("\n👋 Goodbye!")
                    break

                # Handle multiple IPs separated by commas or spaces
                ip_list = [ip.strip() for ip in re.split(r'[,\s]+', ip_input.strip()) if ip.strip()]
                
                if len(ip_list) == 1:
                    ip = ip_list[0]
                    if not self.validate_ip_address(ip):
                        logging.error("❌ Invalid IP address format")
                        continue

                    logging.info(f"⏳ Looking up: {ip}")
                    data = self.get_ip_info(ip)

                    if data:
                        logging.info(self.format_output(data))

                        # Ask for raw JSON
                        show_raw = input("\n📋 Show raw JSON? (y/n): ").strip().lower()
                        if show_raw == 'y':
                            logging.info(json.dumps(data, indent=2))
                    else:
                        logging.error("❌ Failed to retrieve information")

                elif len(ip_list) > 1:
                    # Multiple IP lookup
                    results = self.lookup_multiple_ips(ip_list)

                    logging.info("\n" + "=" * 60)
                    logging.info("📊 MULTIPLE IP LOOKUP RESULTS")
                    logging.info("=" * 60)

                    for ip, data in results.items():
                        if data:
                            logging.info(self.format_output(data))
                        else:
                            logging.error(f"\n❌ Failed to get information for: {ip}\n")

            except KeyboardInterrupt:
                logging.info("\n\n👋 Interrupted by user. Goodbye!")
                break
            except Exception as e:
                logging.error(f"\n❌ Unexpected error: {e}")

    def monitor(self):
        print("\n--- Monitoring Info ---")
        print("Redis:", self.redis_health())
        print("API:", self.api_metrics_info())
        print("Redis Metrics:", self.redis_metrics)


def main():
    """Updated Main function with command line argument support and cache state"""
    parser = argparse.ArgumentParser(
        description="IP Address Information Lookup Tool with Redis caching",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ip_lookup_enhanced.py                   # Interactive mode
  python ip_lookup_enhanced.py 8.8.8.8           # Single IP lookup
  python ip_lookup_enhanced.py --json 8.8.8.8    # JSON output
  python ip_lookup_enhanced.py --token YOUR_TOKEN # With authentication
  python ip_lookup_enhanced.py --monitor           # Show monitoring info and exit
  python ip_lookup_enhanced.py --batch ips.txt     # Batch mode with file
  python ip_lookup_enhanced.py --healthcheck       # Check Redis and API health and exit
"""
    )

    parser.add_argument('ip', nargs='?', help='IP address to lookup')
    parser.add_argument('--token', '-t', help='IPInfo API token for authentication')
    parser.add_argument('--json', '-j', action='store_true', help='Output raw JSON')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10s)')
    parser.add_argument('--monitor', action='store_true', help='Show monitoring info and exit')
    parser.add_argument('--batch', type=str, help='Comma-separated list of IPs or path to file with IPs')
    parser.add_argument('--healthcheck', action='store_true', help='Check Redis and API health and exit')

    args = parser.parse_args()

    # Initialize the tool
    tool = IPLookupTool(api_token=args.token, timeout=args.timeout)

    # Handle monitor, healthcheck, and batch flags first
    if args.monitor:
        tool.monitor()
        sys.exit(0)
    if args.healthcheck:
        print("Redis Health:", tool.redis_health())
        print("API Metrics:", tool.api_metrics_info())
        sys.exit(0)
    if args.batch:
        if os.path.isfile(args.batch):
            with open(args.batch) as f:
                ip_list = [line.strip() for line in f if line.strip()]
        else:
            ip_list = [ip.strip() for ip in args.batch.split(',') if ip.strip()]
        results = tool.lookup_multiple_ips(ip_list)
        for ip, data in results.items():
            print(f"\n{ip}:")
            if data:
                print(tool.format_output(data))
            else:
                print("❌ Failed to retrieve information")
        sys.exit(0)

    if args.ip:
        # Check if multiple IPs are provided in the 'ip' argument
        ip_list = [ip.strip() for ip in re.split(r'[\s,]+', args.ip) if ip.strip()]
        if len(ip_list) > 1:
            # Batch mode for multiple IPs
            results = tool.lookup_multiple_ips(ip_list)
            for ip, data in results.items():
                print(f"\n{ip}:")
                if data:
                    print(tool.format_output(data))
                else:
                    print("❌ Failed to retrieve information")
            sys.exit(0)
        else:
            # Single IP mode
            ip = ip_list[0]
            if not tool.validate_ip_address(ip):
                logging.error("❌ Invalid IP address format")
                sys.exit(1)
            logging.info(f"🔍 Looking up: {ip}")
            data = tool.get_ip_info(ip)
            if data:
                if args.json:
                    logging.info(json.dumps(data, indent=2))
                else:
                    logging.info(tool.format_output(data))
            else:
                logging.error("❌ Failed to retrieve information")
                sys.exit(1)
    else:
        # Interactive mode
        tool.interactive_mode()


if __name__ == "__main__":
    main()