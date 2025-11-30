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
