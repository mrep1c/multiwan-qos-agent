import unittest

from multiwan_qos_agent.sync import _endpoint_urls


class EndpointUrlTests(unittest.TestCase):
    def test_bare_router_defaults_to_https_only(self):
        self.assertEqual(
            _endpoint_urls("192.0.2.1"),
            ["https://192.0.2.1/cgi-bin/multiwan-qos-agent"],
        )

    def test_explicit_http_is_preserved(self):
        self.assertEqual(
            _endpoint_urls("http://192.0.2.1"),
            ["http://192.0.2.1/cgi-bin/multiwan-qos-agent"],
        )

    def test_full_cgi_url_is_preserved(self):
        self.assertEqual(
            _endpoint_urls("https://router.example/cgi-bin/multiwan-qos-agent"),
            ["https://router.example/cgi-bin/multiwan-qos-agent"],
        )

    def test_trailing_slash_is_normalized(self):
        self.assertEqual(
            _endpoint_urls("https://router.example/"),
            ["https://router.example/cgi-bin/multiwan-qos-agent"],
        )


if __name__ == "__main__":
    unittest.main()
