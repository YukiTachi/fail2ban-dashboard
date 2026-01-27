#!/usr/bin/env python3
"""
GeoIP Service - Get country information for IP addresses
Uses ip-api.com free API
"""
import requests
from functools import lru_cache


class GeoIPService:
    """Service class to get geographic information for IP addresses"""

    def __init__(self):
        self.api_url = 'http://ip-api.com/json/'
        self.cache = {}

    @lru_cache(maxsize=1000)
    def get_country(self, ip):
        """Get country information for an IP address"""
        try:
            # Skip private/local IPs
            if self._is_private_ip(ip):
                return {
                    'country': 'Private',
                    'country_code': 'XX',
                    'city': 'Local Network',
                    'isp': 'Local'
                }

            response = requests.get(
                f'{self.api_url}{ip}',
                params={'fields': 'status,country,countryCode,city,isp'},
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'XX'),
                        'city': data.get('city', ''),
                        'isp': data.get('isp', '')
                    }

            return {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': '',
                'isp': ''
            }

        except requests.exceptions.Timeout:
            return {
                'country': 'Timeout',
                'country_code': 'XX',
                'city': '',
                'isp': ''
            }
        except Exception:
            return {
                'country': 'Error',
                'country_code': 'XX',
                'city': '',
                'isp': ''
            }

    def _is_private_ip(self, ip):
        """Check if IP is a private/local address"""
        try:
            parts = [int(p) for p in ip.split('.')]

            # 10.0.0.0/8
            if parts[0] == 10:
                return True

            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True

            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True

            # 127.0.0.0/8 (loopback)
            if parts[0] == 127:
                return True

            return False
        except Exception:
            return False

    def get_country_batch(self, ips):
        """Get country information for multiple IPs"""
        results = {}
        for ip in ips:
            results[ip] = self.get_country(ip)
        return results
