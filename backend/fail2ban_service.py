#!/usr/bin/env python3
"""
Fail2ban Service - Interface with fail2ban-client
"""
import ipaddress
import logging
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# 例: 2026-09-05 08:30:09,123 fail2ban.filter [1234]: INFO [sshd] Found 1.2.3.4 - 2026-09-05 08:30:08
_FOUND_RE = re.compile(r'\] Found (\S+)(?: - (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))?')
# 例: 2026-09-05 08:30:09,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 1.2.3.4
_BAN_RE = re.compile(r'\] Ban (\S+)')


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

        ips = self._parse_banned_ip_list(output)
        if ips:
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

    def _parse_banned_ip_list(self, status_output):
        """fail2ban-client status の出力から BAN 中の IP を、fail2ban が返した順のまま取り出す"""
        match = re.search(r'Banned IP list:\s*(.*?)(?:\n|$)', status_output)
        if not match:
            return []
        return match.group(1).split()

    def _get_findtime(self, jail_name):
        """findtime を秒で返す。fail2ban は '1.5h' のような設定を float で返すので float 経由で解析する"""
        output, success = self._run_command(['get', jail_name, 'findtime'])
        try:
            if success and output:
                return int(float(output))
        except ValueError:
            pass
        logger.warning('Could not read findtime for jail %s (got %r); assuming 600s', jail_name, output)
        return 600

    def get_failed_ips(self, jail_name, banned_ips=None):
        """Get list of IPs currently being counted for failures

        fail2ban 本体と同じ基準に揃える:
        - 直近 findtime 秒以内の Found だけを数える（それより古い失敗は fail2ban も忘れている）
        - すでに BAN 中の IP は除外する
        - BAN 時点で失敗カウントはリセットされるので、その IP の最後の Ban より前の Found は数えない

        banned_ips: 呼び出し側がすでに status を取得済みなら、その BAN 中 IP 集合を渡すと status の再実行を省ける。
        注意: ログの時刻とこのプロセスの時刻を直接比較するため、fail2ban と同じタイムゾーンで動かすこと。
        """
        if banned_ips is None:
            status_output, success = self._run_command(['status', jail_name])
            if not success:
                return []
            banned_ips = set(self._parse_banned_ip_list(status_output))

        findtime = self._get_findtime(jail_name)
        cutoff = datetime.now() - timedelta(seconds=findtime)
        cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

        try:
            # Found 行と Ban 行だけを固定文字列で取り出す（Jail 名を正規表現として解釈させない）
            log_result = subprocess.run(
                ['sudo', 'grep', '-F', '-e', f'[{jail_name}] Found ', '-e', f'[{jail_name}] Ban ',
                 '/var/log/fail2ban.log'],
                capture_output=True,
                text=True,
                timeout=30
            )
        except Exception as e:
            logger.warning('Could not read fail2ban.log for jail %s: %s', jail_name, e)
            return []

        # grep は「該当行なし」で 1 を返すが、sudo 自体の失敗も 1 になる。stderr の有無で区別する
        if log_result.returncode == 1 and not log_result.stderr.strip():
            return []
        if log_result.returncode != 0:
            logger.warning('grep on fail2ban.log failed for jail %s (exit %s): %s',
                           jail_name, log_result.returncode, log_result.stderr.strip())
            return []

        founds = []            # (event_time, ip)
        last_ban = {}          # ip -> 最後に BAN された時刻
        for line in log_result.stdout.split('\n'):
            # 行頭の書き込み時刻（固定幅 19 文字）を文字列比較で先に絞る。
            # 書き込み時刻 >= イベント時刻 なので、書き込み時刻が cutoff より前ならイベントも必ず前
            if len(line) < 19 or line[:19] < cutoff_str:
                continue

            m = _FOUND_RE.search(line)
            if m:
                ip = self._valid_ip(m.group(1))
                if ip is None:
                    continue
                # Found 行末尾のイベント時刻を優先する（再スキャン時は書き込み時刻とずれる）
                event_str = m.group(2) or line[:19]
                if event_str < cutoff_str:
                    continue
                founds.append((event_str, ip))
                continue

            m = _BAN_RE.search(line)
            if m:
                ip = self._valid_ip(m.group(1))
                if ip is not None:
                    last_ban[ip] = max(last_ban.get(ip, ''), line[:19])

        ip_failures = defaultdict(int)
        for event_str, ip in founds:
            if ip in banned_ips:
                continue
            if ip in last_ban and event_str <= last_ban[ip]:
                continue
            ip_failures[ip] += 1

        failed_ips = [{'ip': ip, 'fail_count': count} for ip, count in ip_failures.items()]
        failed_ips.sort(key=lambda x: x['fail_count'], reverse=True)
        return failed_ips[:50]  # Return top 50

    @staticmethod
    def _valid_ip(token):
        """IP として解釈できれば正規化した文字列を、できなければ None を返す（画面や banip に渡す前の検証）"""
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            return None

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
