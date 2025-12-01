import unittest
from datetime import datetime

# Import your function here if it's in another file
# from your_module import normalize_timestamp

def normalize_timestamp(raw_timestamp: str) -> str:
    """
    Convert a single raw timestamp string to ISO 8601 format with Zulu time.
    """
    dt = datetime.strptime(raw_timestamp, "%d/%m/%Y, %H:%M:%S")
    return dt.isoformat() + "Z"

class TestNormalizeTimestamp(unittest.TestCase):
    
    def test_standard_timestamp(self):
        raw = "29/11/2025, 23:45:12"
        expected = "2025-11-29T23:45:12Z"
        self.assertEqual(normalize_timestamp(raw), expected)

    def test_single_digit_day_month(self):
        raw = "5/2/2025, 01:02:03"
        expected = "2025-02-05T01:02:03Z"
        self.assertEqual(normalize_timestamp(raw), expected)

    def test_invalid_format(self):
        raw = "2025-11-29 23:45:12"
        with self.assertRaises(ValueError):
            normalize_timestamp(raw)

    def test_empty_string(self):
        raw = ""
        with self.assertRaises(ValueError):
            normalize_timestamp(raw)

if __name__ == "__main__":
    unittest.main()

# Bring your function here for testing
def event_type(raw_payload):
    if raw_payload.startswith("b'\\x16"):
        return "tls_handshake"
    elif raw_payload.startswith("GET") or raw_payload.startswith("'GET"):
        return "http_request"
    elif raw_payload.startswith("b'\\x00\\x00") or raw_payload.startswith("SMBr"):
        return "smb_probe"
    elif raw_payload.strip() in ["''", '"\'\'"']:
        return "empty_payload"
    else:
        return "text_probe"


class TestEventType(unittest.TestCase):

    def test_tls_handshake(self):
        payload = "b'\\x16\\x03\\x01\\x00{'"
        self.assertEqual(event_type(payload), "tls_handshake")

    def test_http_request(self):
        payload = "'GET / HTTP/1.1\\r\\nHost: 3.8.136.101:16026\\r\\n\\r\\n'"
        self.assertEqual(event_type(payload), "http_request")

    def test_smb_probe(self):
        payload = "b'\\x00\\x00\\x00T\\xffSMBr.....'"
        self.assertEqual(event_type(payload), "smb_probe")

    def test_empty_payload(self):
        payload = "''"
        self.assertEqual(event_type(payload), "empty_payload")

    def test_text_probe(self):
        payload = "'myversion|3.6 Public\\r\\n'"
        self.assertEqual(event_type(payload), "text_probe")


if __name__ == "__main__":
    unittest.main()
