#!/usr/bin/env python3
"""
GeoIP Service - Get country information for IP addresses
Uses ip-api.com free API (batch endpoint: 100 IPs per request, 15 requests/minute)

結果は SQLite に永続化する。再起動してもキャッシュが残るため、
同じ IP を ip-api.com へ再問い合わせしない。
"""
import contextlib
import ipaddress
import logging
import os
import sqlite3
import time

import requests

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'data', 'geoip_cache.db'
)
_DEFAULT_TTL_DAYS = 30
_BATCH_URL = 'http://ip-api.com/batch'
_BATCH_SIZE = 100
_FIELDS = 'status,message,country,countryCode,city,isp,query'


def _info(country, country_code='XX', city='', isp=''):
    return {'country': country, 'country_code': country_code, 'city': city, 'isp': isp}


PRIVATE = _info('Private', 'XX', 'Local Network', 'Local')
UNKNOWN = _info('Unknown')
TIMEOUT = _info('Timeout')
ERROR = _info('Error')


class GeoIPService:
    """Service class to get geographic information for IP addresses"""

    def __init__(self, cache_path=None, ttl_days=None, negative_ttl_seconds=600, request_timeout=5):
        self.cache_path = cache_path or os.environ.get('GEOIP_CACHE_PATH') or _DEFAULT_CACHE_PATH
        self.ttl_seconds = self._parse_ttl_days(ttl_days) * 86400
        # 失敗（Timeout / Error / API が fail を返した IP）はこの秒数だけ再試行しない
        self.negative_ttl_seconds = negative_ttl_seconds
        self.request_timeout = request_timeout
        self._db_available = self._init_db()

    @staticmethod
    def _parse_ttl_days(value):
        if value is None:
            value = os.environ.get('GEOIP_CACHE_TTL_DAYS', '')
        try:
            days = int(value)
            if days <= 0:
                raise ValueError('must be positive')
            return days
        except (TypeError, ValueError):
            if value not in (None, ''):
                logger.warning('Invalid GEOIP_CACHE_TTL_DAYS=%r, using %d', value, _DEFAULT_TTL_DAYS)
            return _DEFAULT_TTL_DAYS

    # ------------------------------------------------------------------
    # SQLite
    # ------------------------------------------------------------------
    def _connect(self):
        # 呼び出しごとに接続を開いて閉じる。SQLite では十分軽く、スレッド間で接続を共有しなくて済む
        return contextlib.closing(sqlite3.connect(self.cache_path, timeout=5))

    def _init_db(self):
        """キャッシュ DB を初期化し、実際に書けることを確認する。失敗してもアプリは動かす（API 直接問い合わせのみになる）"""
        try:
            directory = os.path.dirname(self.cache_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with self._connect() as conn:
                with conn:
                    conn.execute('''
                        CREATE TABLE IF NOT EXISTS geoip_cache (
                            ip           TEXT PRIMARY KEY,
                            ok           INTEGER NOT NULL,
                            country      TEXT NOT NULL,
                            country_code TEXT NOT NULL,
                            city         TEXT NOT NULL DEFAULT '',
                            isp          TEXT NOT NULL DEFAULT '',
                            fetched_at   INTEGER NOT NULL
                        )
                    ''')
                    # 書き込み可否の確認（既存ファイルへの CREATE TABLE IF NOT EXISTS は何もしないため）
                    conn.execute("INSERT OR REPLACE INTO geoip_cache VALUES ('__probe__', 0, '', '', '', '', 0)")
                    conn.execute("DELETE FROM geoip_cache WHERE ip = '__probe__'")
                    # 古い行を掃除する。成功行は TTL の 2 倍まで残す（再取得失敗時の予備として使う）
                    now = int(time.time())
                    conn.execute(
                        'DELETE FROM geoip_cache WHERE (ok = 1 AND fetched_at < ?) OR (ok = 0 AND fetched_at < ?)',
                        (now - 2 * self.ttl_seconds, now - self.negative_ttl_seconds)
                    )
            return True
        except (OSError, sqlite3.Error) as e:
            logger.warning('GeoIP cache DB unavailable (%s): %s. Lookups will not be cached.', self.cache_path, e)
            return False

    def _db_get_many(self, ips):
        """{ip: (ok, info, age_seconds)} を返す。DB が使えなければ空 dict"""
        if not self._db_available or not ips:
            return {}
        try:
            placeholders = ','.join('?' * len(ips))
            with self._connect() as conn:
                rows = conn.execute(
                    f'SELECT ip, ok, country, country_code, city, isp, fetched_at '
                    f'FROM geoip_cache WHERE ip IN ({placeholders})',
                    tuple(ips)
                ).fetchall()
            now = time.time()
            return {
                ip: (bool(ok), _info(country, code, city, isp), now - fetched_at)
                for ip, ok, country, code, city, isp, fetched_at in rows
            }
        except sqlite3.Error as e:
            logger.warning('GeoIP cache read failed: %s', e)
            return {}

    def _db_put_many(self, entries):
        """entries: [(ip, ok, info)]。1 トランザクションでまとめて書く"""
        if not self._db_available or not entries:
            return
        now = int(time.time())
        try:
            with self._connect() as conn:
                with conn:
                    conn.executemany(
                        'INSERT OR REPLACE INTO geoip_cache VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [(ip, int(ok), i['country'], i['country_code'], i['city'], i['isp'], now)
                         for ip, ok, i in entries]
                    )
        except sqlite3.Error as e:
            logger.warning('GeoIP cache write failed: %s', e)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_country(self, ip):
        """Get country information for a single IP address"""
        return self.get_country_batch([ip]).get(ip, ERROR)

    def get_country_batch(self, ips):
        """Get country information for multiple IPs. Never raises."""
        try:
            return self._lookup(list(dict.fromkeys(ips)))
        except Exception as e:
            logger.warning('GeoIP lookup failed unexpectedly: %s', e)
            return {ip: dict(ERROR) for ip in ips}

    def _lookup(self, ips):
        results = {}
        to_fetch = []
        stale = {}

        public_ips = []
        for ip in ips:
            if self._is_private_ip(ip):
                results[ip] = dict(PRIVATE)
            else:
                public_ips.append(ip)

        cached = self._db_get_many(public_ips)
        for ip in public_ips:
            hit = cached.get(ip)
            if hit is None:
                to_fetch.append(ip)
                continue
            ok, info, age = hit
            if ok and age <= self.ttl_seconds:
                results[ip] = info
            elif not ok and age <= self.negative_ttl_seconds:
                results[ip] = info          # 直近で失敗した IP。しばらく再試行しない
            else:
                to_fetch.append(ip)
                if ok:
                    stale[ip] = info        # 期限切れだが、再取得に失敗したら予備として返す

        if to_fetch:
            fetched = {}
            for start in range(0, len(to_fetch), _BATCH_SIZE):
                fetched.update(self._fetch_batch(to_fetch[start:start + _BATCH_SIZE]))

            to_store = []
            for ip in to_fetch:
                ok, info = fetched.get(ip, (False, dict(ERROR)))
                to_store.append((ip, ok, info))
                results[ip] = info if ok else stale.get(ip, info)
            self._db_put_many(to_store)

        return results

    def _fetch_batch(self, ips):
        """ip-api.com の batch エンドポイントに問い合わせる。{ip: (ok, info)} を返す"""
        try:
            response = requests.post(
                _BATCH_URL,
                params={'fields': _FIELDS},
                json=ips,
                timeout=self.request_timeout
            )
            if response.status_code != 200:
                logger.warning('GeoIP batch lookup returned HTTP %s for %d IPs', response.status_code, len(ips))
                return {ip: (False, dict(UNKNOWN)) for ip in ips}

            out = {}
            for item in response.json():
                ip = item.get('query')
                if ip is None:
                    continue
                if item.get('status') == 'success':
                    out[ip] = (True, _info(
                        item.get('country', 'Unknown'),
                        item.get('countryCode', 'XX'),
                        item.get('city', ''),
                        item.get('isp', '')
                    ))
                else:
                    logger.debug('GeoIP lookup for %s failed: %s', ip, item.get('message'))
                    out[ip] = (False, dict(UNKNOWN))
            # 応答に含まれなかった IP は失敗扱い
            for ip in ips:
                out.setdefault(ip, (False, dict(UNKNOWN)))
            return out

        except requests.exceptions.Timeout:
            logger.warning('GeoIP batch lookup timed out for %d IPs', len(ips))
            return {ip: (False, dict(TIMEOUT)) for ip in ips}
        except Exception as e:
            logger.warning('GeoIP batch lookup failed for %d IPs: %s', len(ips), e)
            return {ip: (False, dict(ERROR)) for ip in ips}

    @staticmethod
    def _is_private_ip(ip):
        """プライベート / 予約アドレス（IPv4・IPv6 両対応）。解析できない文字列も API に送らない"""
        try:
            return not ipaddress.ip_address(ip).is_global
        except ValueError:
            return True
