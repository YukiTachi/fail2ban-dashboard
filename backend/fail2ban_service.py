#!/usr/bin/env python3
"""
Fail2ban Service - Interface with fail2ban-client
"""
import subprocess
import re
from collections import defaultdict


class Fail2banService:
    """Service class to interact with fail2ban-client"""

    def __init__(self):
        self.sudo_cmd = ['sudo', 'fail2ban-client']

    def _run_command(self, args):
        """Run fail2ban-client command with sudo"""
        try:
            cmd = self.sudo_cmd + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip(), result.returncode == 0
        except subprocess.TimeoutExpired:
            return '', False
        except Exception as e:
            return str(e), False

    def get_all_jails(self):
        """Get list of all jail names"""
        output, success = self._run_command(['status'])
        if not success:
            return []

        # Parse output: "Jail list:   jail1, jail2, jail3"
        match = re.search(r'Jail list:\s*(.+)', output)
        if match:
            jails_str = match.group(1)
            jails = [j.strip() for j in jails_str.split(',') if j.strip()]
            return jails
        return []

    def get_jail_status(self, jail_name):
        """Get status for a specific jail"""
        output, success = self._run_command(['status', jail_name])
        if not success:
            return None

        status = {
            'name': jail_name,
            'currently_failed': 0,
            'total_failed': 0,
            'currently_banned': 0,
            'total_banned': 0
        }

        # Parse the output
        lines = output.split('\n')
        for line in lines:
            line = line.strip()

            if 'Currently failed:' in line:
                match = re.search(r'Currently failed:\s*(\d+)', line)
                if match:
                    status['currently_failed'] = int(match.group(1))

            elif 'Total failed:' in line:
                match = re.search(r'Total failed:\s*(\d+)', line)
                if match:
                    status['total_failed'] = int(match.group(1))

            elif 'Currently banned:' in line:
                match = re.search(r'Currently banned:\s*(\d+)', line)
                if match:
                    status['currently_banned'] = int(match.group(1))

            elif 'Total banned:' in line:
                match = re.search(r'Total banned:\s*(\d+)', line)
                if match:
                    status['total_banned'] = int(match.group(1))

        return status

    def get_banned_ips(self, jail_name):
        """Get list of currently banned IPs with reject counts"""
        output, success = self._run_command(['status', jail_name])
        if not success:
            return []

        banned_ips = []

        # Find banned IP list in output
        match = re.search(r'Banned IP list:\s*(.+?)(?:\n|$)', output)
        if match:
            ips_str = match.group(1).strip()
            if ips_str:
                ips = [ip.strip() for ip in ips_str.split() if ip.strip()]

                # Get reject counts from iptables
                reject_counts = self._get_reject_counts(jail_name)

                for ip in ips:
                    banned_ips.append({
                        'ip': ip,
                        'reject_count': reject_counts.get(ip, 0)
                    })

        # Sort by reject count (descending)
        banned_ips.sort(key=lambda x: x['reject_count'], reverse=True)
        return banned_ips

    def _get_reject_counts(self, jail_name):
        """Get reject counts from iptables-save for banned IPs"""
        counts = defaultdict(int)

        try:
            # Use iptables-save -c for reading (read-only, more secure)
            result = subprocess.run(
                ['sudo', 'iptables-save', '-c'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                chain_name = f'f2b-{jail_name}'
                for line in result.stdout.split('\n'):
                    # Match lines like: [708:36816] -A f2b-postfix-sasl -s 77.83.39.180/32 -j REJECT
                    if chain_name in line and 'REJECT' in line:
                        match = re.search(
                            r'\[(\d+):\d+\]\s+-A\s+' + re.escape(chain_name) + r'\s+-s\s+(\d+\.\d+\.\d+\.\d+)/32',
                            line
                        )
                        if match:
                            count = int(match.group(1))
                            ip = match.group(2)
                            counts[ip] = count
        except Exception:
            pass

        return dict(counts)

    def get_failed_ips(self, jail_name):
        """Get list of IPs currently being counted for failures"""
        # Use fail2ban-client to get failed IPs
        # Note: This requires fail2ban 0.10+ with the 'get' command
        output, success = self._run_command(['get', jail_name, 'failregex'])

        # Alternative: parse the fail2ban log
        failed_ips = []

        try:
            result = subprocess.run(
                ['sudo', 'fail2ban-client', 'status', jail_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Get filter info
                filter_output, _ = self._run_command(['get', jail_name, 'findtime'])
                findtime = 600  # default

                try:
                    findtime = int(filter_output) if filter_output.isdigit() else 600
                except ValueError:
                    pass

                # Parse fail2ban log for recent failures
                log_result = subprocess.run(
                    ['sudo', 'grep', f'\\[{jail_name}\\]', '/var/log/fail2ban.log'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if log_result.returncode == 0:
                    ip_failures = defaultdict(int)
                    for line in log_result.stdout.split('\n'):
                        if 'Found' in line:
                            match = re.search(r'Found\s+(\d+\.\d+\.\d+\.\d+)', line)
                            if match:
                                ip_failures[match.group(1)] += 1

                    for ip, count in ip_failures.items():
                        failed_ips.append({
                            'ip': ip,
                            'fail_count': count
                        })

                    failed_ips.sort(key=lambda x: x['fail_count'], reverse=True)

        except Exception:
            pass

        return failed_ips[:50]  # Return top 50

    def get_reject_histogram(self, jail_name):
        """Get histogram data for reject counts"""
        banned_ips = self.get_banned_ips(jail_name)

        if not banned_ips:
            return {'labels': [], 'data': []}

        # Create histogram buckets
        counts = [ip['reject_count'] for ip in banned_ips]

        if not counts:
            return {'labels': [], 'data': []}

        max_count = max(counts) if counts else 0

        # Create appropriate bucket ranges
        if max_count <= 10:
            bucket_size = 1
        elif max_count <= 100:
            bucket_size = 10
        elif max_count <= 1000:
            bucket_size = 100
        else:
            bucket_size = 1000

        buckets = defaultdict(int)
        for count in counts:
            bucket = (count // bucket_size) * bucket_size
            buckets[bucket] += 1

        # Sort buckets
        sorted_buckets = sorted(buckets.items())

        labels = []
        data = []
        for bucket, count in sorted_buckets:
            if bucket_size == 1:
                labels.append(str(bucket))
            else:
                labels.append(f'{bucket}-{bucket + bucket_size - 1}')
            data.append(count)

        return {'labels': labels, 'data': data}

    def ban_ip(self, jail_name, ip):
        """Ban an IP address in a jail"""
        _, success = self._run_command(['set', jail_name, 'banip', ip])
        return success

    def unban_ip(self, jail_name, ip):
        """Unban an IP address from a jail"""
        _, success = self._run_command(['set', jail_name, 'unbanip', ip])
        return success
