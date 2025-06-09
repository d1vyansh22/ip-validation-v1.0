import requests
import json
import sys

def get_ip_info_direct(ip_address):
    """
    Get IP information using direct API call to IPInfo (no authentication required)
    Limited to 1000 requests per day for the same IP address
    """
    try:
        # Make API call to IPInfo's free endpoint
        url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(url, timeout=10)

        # Check if request was successful
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: HTTP {response.status_code} - {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return None

def get_ip_info_with_library(ip_address, access_token=None):
    """
    Get IP information using the official IPInfo library (requires installation)
    Provides unlimited requests with free account
    """
    try:
        import ipinfo

        # Initialize handler with or without token
        if access_token:
            handler = ipinfo.getHandler(access_token)
        else:
            handler = ipinfo.getHandler()

        # Get IP details
        details = handler.getDetails(ip_address)
        return details.details

    except ImportError:
        print("IPInfo library not installed. Install with: pip install ipinfo")
        return None
    except Exception as e:
        print(f"Error with IPInfo library: {e}")
        return None

def format_ip_info(data):
    """
    Format the IP information for display in terminal
    """
    if not data:
        return "No data available"

    formatted_output = "\n" + "="*50
    formatted_output += "\n           IP ADDRESS INFORMATION"
    formatted_output += "\n" + "="*50 + "\n"

    # Basic information
    formatted_output += f"IP Address:     {data.get('ip', 'N/A')}\n"
    formatted_output += f"Hostname:       {data.get('hostname', 'N/A')}\n"
    formatted_output += f"Country:        {data.get('country', 'N/A')} ({data.get('country_name', 'N/A')})\n"
    formatted_output += f"Region:         {data.get('region', 'N/A')}\n"
    formatted_output += f"City:           {data.get('city', 'N/A')}\n"
    formatted_output += f"Postal Code:    {data.get('postal', 'N/A')}\n"

    # Location coordinates
    if 'loc' in data:
        coords = data['loc'].split(',')
        if len(coords) == 2:
            formatted_output += f"Latitude:       {coords[0]}\n"
            formatted_output += f"Longitude:      {coords[1]}\n"

    # Network information
    formatted_output += f"Organization:   {data.get('org', 'N/A')}\n"
    formatted_output += f"Timezone:       {data.get('timezone', 'N/A')}\n"

    # Additional info if available
    if 'asn' in data:
        formatted_output += f"ASN:            {data.get('asn', 'N/A')}\n"
    if 'as_name' in data:
        formatted_output += f"AS Name:        {data.get('as_name', 'N/A')}\n"
    if 'as_domain' in data:
        formatted_output += f"AS Domain:      {data.get('as_domain', 'N/A')}\n"

    formatted_output += "\n" + "="*50 + "\n"

    return formatted_output

def validate_ip_address(ip):
    """
    Basic IP address validation
    """
    import re

    # IPv4 pattern
    ipv4_pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'

    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'

    if re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip):
        return True
    return False

def main():
    """
    Main function to run the IP lookup tool
    """
    print("\n🌐 IP Address Information Lookup Tool")
    print("=====================================")

    while True:
        # Get IP address from user
        ip_address = input("\nEnter an IP address (or 'quit' to exit): ").strip()

        if ip_address.lower() in ['quit', 'exit', 'q']:
            print("Goodbye! 👋")
            break

        if not ip_address:
            print("❌ Please enter a valid IP address.")
            continue

        # Validate IP address format
        if not validate_ip_address(ip_address):
            print("❌ Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")
            continue

        print(f"\n🔍 Looking up information for: {ip_address}")
        print("⏳ Please wait...")

        # Try direct API approach first (no authentication required)
        data = get_ip_info_direct(ip_address)

        if data:
            print("✅ Information retrieved successfully!")
            print(format_ip_info(data))

            # Ask if user wants to see raw JSON
            show_raw = input("Show raw JSON data? (y/n): ").strip().lower()
            if show_raw == 'y':
                print("\n📋 Raw JSON Response:")
                print("-" * 30)
                print(json.dumps(data, indent=2))
                print("-" * 30)
        else:
            print("❌ Failed to retrieve IP information. Please try again.")

        # Ask if user wants to lookup another IP
        another = input("\nLookup another IP address? (y/n): ").strip().lower()
        if another != 'y':
            print("Goodbye! 👋")
            break

if __name__ == "__main__":
    main()