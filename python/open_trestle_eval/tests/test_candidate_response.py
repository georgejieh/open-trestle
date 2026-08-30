import json
import math
import sys
import unittest
from typing import cast

from open_trestle_eval import (
    CandidateResponseDecodeError,
    CandidateResponseErrorCode,
    decode_candidate_response,
)

MAX_RESPONSE_BYTES = 256 * 1024


class CandidateResponseDecoderTest(unittest.TestCase):
    def assert_decode_error(
        self, code: CandidateResponseErrorCode, encoded: bytes
    ) -> CandidateResponseDecodeError:
        with self.assertRaises(CandidateResponseDecodeError) as caught:
            decode_candidate_response(encoded)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn("SENTINEL", str(caught.exception))
        return caught.exception

    def test_decodes_candidate_batch(self) -> None:
        encoded = b'{"schema_version":1,"candidates":[]}'
        self.assertEqual(
            decode_candidate_response(encoded),
            {"schema_version": 1, "candidates": []},
        )

    def test_accepts_each_json_value_type_before_schema_validation(self) -> None:
        cases = (
            (b"null", None),
            (b"true", True),
            (b"42", 42),
            (b"1.5", 1.5),
            (b'"text"', "text"),
            (b"[]", []),
            (b"{}", {}),
        )
        for encoded, expected in cases:
            with self.subTest(encoded=encoded):
                self.assertEqual(decode_candidate_response(encoded), expected)

    def test_accepts_exact_byte_limit(self) -> None:
        encoded = b'"' + b"a" * (MAX_RESPONSE_BYTES - 2) + b'"'
        self.assertEqual(len(decode_candidate_response(encoded)), len(encoded) - 2)

    def test_rejects_oversized_input_before_decoding(self) -> None:
        encoded = b'"' + b"a" * (MAX_RESPONSE_BYTES - 2) + b'" '
        self.assertEqual(len(encoded), MAX_RESPONSE_BYTES + 1)
        self.assert_decode_error(CandidateResponseErrorCode.TOO_LARGE, encoded)

    def test_rejects_non_bytes_input(self) -> None:
        for value in ("{}", bytearray(b"{}"), memoryview(b"{}")):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(TypeError):
                    decode_candidate_response(cast(bytes, value))

    def test_rejects_invalid_utf8(self) -> None:
        for encoded in (b"\xff", b'"\xed\xa0\x80"'):
            with self.subTest(encoded=encoded):
                self.assert_decode_error(
                    CandidateResponseErrorCode.INVALID_UTF8, encoded
                )

    def test_rejects_duplicate_decoded_keys(self) -> None:
        for encoded in (
            b'{"a":1,"a":2}',
            b'{"outer":{"a":1,"a":2}}',
            b'{"a":1,"\\u0061":2}',
        ):
            with self.subTest(encoded=encoded):
                self.assert_decode_error(
                    CandidateResponseErrorCode.DUPLICATE_KEY, encoded
                )

    def test_allows_same_key_in_separate_objects_and_distinct_unicode(self) -> None:
        self.assertEqual(
            decode_candidate_response(b'[{"a":1},{"a":2}]'),
            [{"a": 1}, {"a": 2}],
        )
        decoded = decode_candidate_response(
            '{"é":1,"é":2}'.encode("utf-8")
        )
        self.assertEqual(len(decoded), 2)

    def test_rejects_nonfinite_numbers(self) -> None:
        for encoded in (
            b"NaN",
            b"Infinity",
            b"-Infinity",
            b"[NaN]",
            b"1e10000",
            b"-1e10000",
        ):
            with self.subTest(encoded=encoded):
                self.assert_decode_error(
                    CandidateResponseErrorCode.NON_FINITE_NUMBER, encoded
                )

    def test_accepts_finite_float_boundaries(self) -> None:
        for encoded in (b"1e308", b"-0.0", b"1e-10000"):
            with self.subTest(encoded=encoded):
                value = decode_candidate_response(encoded)
                self.assertTrue(math.isfinite(value))

    def test_rejects_malformed_or_multiple_values(self) -> None:
        for encoded in (
            b"",
            b"   ",
            b"{} {}",
            b"{} trailing",
            b"```json\n{}\n```",
            b"{/*comment*/}",
            b"{'a':1}",
            b'{"a":1,}',
            b'"line\ncontrol"',
            b"\xef\xbb\xbf{}",
        ):
            with self.subTest(encoded=encoded):
                self.assert_decode_error(
                    CandidateResponseErrorCode.INVALID_JSON, encoded
                )

    def test_allows_trailing_json_whitespace(self) -> None:
        self.assertEqual(decode_candidate_response(b"{} \r\n\t"), {})

    def test_enforces_array_object_and_mixed_depth(self) -> None:
        at_limit = (
            b"[" * 8 + b"0" + b"]" * 8,
            b'{"a":' * 8 + b"0" + b"}" * 8,
            b'[{"a":' * 4 + b"0" + b"}]" * 4,
        )
        over_limit = (
            b"[" * 9 + b"0" + b"]" * 9,
            b'{"a":' * 9 + b"0" + b"}" * 9,
        )
        for encoded in at_limit:
            with self.subTest(encoded=encoded):
                decode_candidate_response(encoded)
        for encoded in over_limit:
            with self.subTest(encoded=encoded):
                self.assert_decode_error(
                    CandidateResponseErrorCode.CONTAINER_DEPTH_EXCEEDED,
                    encoded,
                )

    def test_depth_preflight_ignores_brackets_inside_strings(self) -> None:
        encoded = json.dumps("[{" * 100 + "]}" * 100).encode("utf-8")
        self.assertIsInstance(decode_candidate_response(encoded), str)

    def test_rejects_unpaired_unicode_surrogates(self) -> None:
        for encoded in (
            b'"\\ud800"',
            b'"\\udfff"',
            b'["\\ud800"]',
            b'{"\\ud800":1}',
        ):
            with self.subTest(encoded=encoded):
                self.assert_decode_error(
                    CandidateResponseErrorCode.UNPAIRED_SURROGATE,
                    encoded,
                )

    def test_accepts_valid_unicode_pairs_and_utf8(self) -> None:
        self.assertEqual(decode_candidate_response(b'"\\ud83d\\ude00"'), "😀")
        self.assertEqual(decode_candidate_response('"😀"'.encode("utf-8")), "😀")

    def test_normalizes_guarded_large_integer_failure(self) -> None:
        digit_limit = sys.get_int_max_str_digits()
        if digit_limit == 0:
            self.skipTest("interpreter integer digit guard is disabled")
        encoded = b"1" * (digit_limit + 1)
        self.assert_decode_error(CandidateResponseErrorCode.INVALID_JSON, encoded)

    def test_error_does_not_echo_or_chain_input(self) -> None:
        error = self.assert_decode_error(
            CandidateResponseErrorCode.INVALID_JSON,
            b'{"secret":"SENTINEL",}',
        )
        self.assertIsNone(error.__cause__)


if __name__ == "__main__":
    unittest.main()
