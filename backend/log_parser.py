#!/usr/bin/env python3
"""
Log Parser - Parse various log files for malicious activity
Supports: sshd, postfix-sasl, nginx, apache
"""
import subprocess
import re
from datetime import datetime
from collections import defaultdict


class LogParser:
    """Parser for various log files to extract malicious IP activity"""

    # Log file paths by jail type
    LOG_PATHS = {
        'sshd': ['/var/log/auth.log', '/var/log/secure'],
        'postfix-sasl': ['/var/log/mail.log', '/var/log/maillog'],
        'postfix': ['/var/log/mail.log', '/var/log/maillog'],
        'dovecot': ['/var/log/mail.log', '/var/log/dovecot.log'],
        'nginx-http-auth': ['/var/log/nginx/error.log'],
        'nginx-botsearch': ['/var/log/nginx/access.log'],
        'apache-auth': ['/var/log/apache2/error.log', '/var/log/httpd/error_log'],
    }

    # Regex patterns for different log types
    PATTERNS = {
        'sshd': [
            r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
            r'Failed password for invalid user .* from (\d+\.\d+\.\d+\.\d+)',
            r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)',
            r'Connection closed by authenticating user .* (\d+\.\d+\.\d+\.\d+)',
            r'Disconnected from authenticating user .* (\d+\.\d+\.\d+\.\d+)',
        ],
        'postfix-sasl': [
            r'warning: .*\[(\d+\.\d+\.\d+\.\d+)\]: SASL .* authentication failed',
            r'SASL LOGIN authentication failed: .* \[(\d+\.\d+\.\d+\.\d+)\]',
        ],
        'postfix': [
            r'NOQUEUE: reject: .* from .*\[(\d+\.\d+\.\d+\.\d+)\]',
            r'warning: .*\[(\d+\.\d+\.\d+\.\d+)\]',
        ],
        'dovecot': [
            r'auth failed, (\d+\.\d+\.\d+\.\d+)',
            r'Aborted login .* rip=(\d+\.\d+\.\d+\.\d+)',
        ],
        'nginx-http-auth': [
            r'no user/password was provided .* client: (\d+\.\d+\.\d+\.\d+)',
            r'user .* was not found .* client: (\d+\.\d+\.\d+\.\d+)',
            r'password mismatch .* client: (\d+\.\d+\.\d+\.\d+)',
        ],
        'nginx-botsearch': [
            r'(\d+\.\d+\.\d+\.\d+) .* "(GET|POST) .*(\.php|wp-|admin|\.env|\.git)',
        ],
        'apache-auth': [
            r'\[client (\d+\.\d+\.\d+\.\d+)\] .* authentication failure',
            r'AH01617: user .* authentication failure .* (\d+\.\d+\.\d+\.\d+)',
        ],
    }

    def __init__(self):
        self.cache = {}

    def _find_log_file(self, jail_name):
        """Find the appropriate log file for a jail"""
        # Map jail name to log type
        log_type = None
        for key in self.LOG_PATHS:
            if key in jail_name.lower():
                log_type = key
                break

        if not log_type:
            log_type = 'sshd'  # Default to sshd

        # Find existing log file
        for path in self.LOG_PATHS.get(log_type, []):
            try:
                result = subprocess.run(
                    ['sudo', 'test', '-f', path],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return path, log_type
            except Exception:
                continue

        return None, log_type

    def _get_patterns(self, jail_name):
        """Get regex patterns for a jail type"""
        for key in self.PATTERNS:
            if key in jail_name.lower():
                return self.PATTERNS[key]
        return self.PATTERNS.get('sshd', [])

    def parse_logs(self, jail_name, limit=100):
        """Parse logs and extract malicious IP activity"""
        log_file, log_type = self._find_log_file(jail_name)

        if not log_file:
            return []

        patterns = self._get_patterns(jail_name)
        if not patterns:
            return []

        try:
            # Read last N lines of log file
            result = subprocess.run(
                ['sudo', 'tail', '-n', '10000', log_file],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return []

            ip_data = defaultdict(lambda: {'count': 0, 'last_seen': None, 'lines': []})

            for line in result.stdout.split('\n'):
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        ip = match.group(1)
                        ip_data[ip]['count'] += 1
                        ip_data[ip]['last_seen'] = self._extract_timestamp(line)
                        if len(ip_data[ip]['lines']) < 3:  # Keep only last 3 log lines
                            ip_data[ip]['lines'].append(line[:200])  # Truncate long lines
                        break

            # Convert to list and sort by count
            logs = []
            for ip, data in ip_data.items():
                logs.append({
                    'ip': ip,
                    'count': data['count'],
                    'last_seen': data['last_seen'],
                    'sample_logs': data['lines']
                })

            logs.sort(key=lambda x: x['count'], reverse=True)
            return logs[:limit]

        except subprocess.TimeoutExpired:
            return []
        except Exception as e:
            return []

    def _extract_timestamp(self, line):
        """Extract timestamp from log line"""
        # Common timestamp patterns
        patterns = [
            r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)',  # syslog format: "Jan 25 10:30:45"
            r'^(\d{4}-\d{2}-\d{2}T\d+:\d+:\d+)',  # ISO format
            r'^(\d{4}/\d{2}/\d{2} \d+:\d+:\d+)',  # nginx format
            r'^\[(\d{2}/\w{3}/\d{4}:\d+:\d+:\d+)',  # apache format
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)

        return None

    def get_attack_summary(self, jail_name):
        """Get summary of attacks for a jail"""
        logs = self.parse_logs(jail_name)

        if not logs:
            return {
                'total_ips': 0,
                'total_attempts': 0,
                'top_attackers': []
            }

        total_attempts = sum(log['count'] for log in logs)

        return {
            'total_ips': len(logs),
            'total_attempts': total_attempts,
            'top_attackers': logs[:10]
        }
