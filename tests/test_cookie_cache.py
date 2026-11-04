"""Cache isolation, permissions, and expiry without real user state."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'codebase'))
from core import cookies


class CookieCacheTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cache = Path(self.directory.name)
        self.patch = patch.object(cookies, '_get_user_cache_dir', return_value=self.cache)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_previously_colliding_profiles_are_isolated(self):
        self.assertTrue(cookies.store_cookies('work vpn', {'webvpn': 'first'}))
        self.assertTrue(cookies.store_cookies('work_vpn', {'webvpn': 'second'}))
        self.assertEqual(cookies.get_cached_cookies('work vpn')[0]['webvpn'], 'first')
        self.assertEqual(cookies.get_cached_cookies('work_vpn')[0]['webvpn'], 'second')
        cookies.clear_cookies('work vpn')
        self.assertIsNone(cookies.get_cached_cookies('work vpn'))
        self.assertIsNotNone(cookies.get_cached_cookies('work_vpn'))

    def test_cache_replacement_stays_private(self):
        for value in ['initial', 'replacement']:
            self.assertTrue(cookies.store_cookies('work', {'webvpn': value}))
            self.assertEqual(cookies._get_cookie_file('work').stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.cache.glob('.session-*')))

    def test_expired_future_and_malformed_tokens_are_ignored(self):
        path = cookies._get_cookie_file('work')
        with patch.object(cookies.time, 'time', return_value=100000):
            for timestamp in [0, 100001]:
                path.write_text(json.dumps({'timestamp': timestamp, 'cookies': {'webvpn': 'x'}}))
                self.assertIsNone(cookies.get_cached_cookies('work'))
            path.write_text('{broken')
            self.assertIsNone(cookies.get_cached_cookies('work'))
            path.write_text(json.dumps({'timestamp': 100000, 'cookies': 'bad'}))
            self.assertIsNone(cookies.get_cached_cookies('work'))


if __name__ == '__main__':
    unittest.main()
