"""
Tests for Mistral client rate-limit backoff logic.
"""

from backend.mcps.common.mistral_client import (
    _is_rate_limit_error,
    _get_retry_after,
    _compute_backoff,
    _BACKOFF_BASE_SECONDS,
    _BACKOFF_MAX_SECONDS,
)


# --- Mock exceptions ---


class MockRateLimitError(Exception):
    def __init__(self, status_code=429, headers=None):
        super().__init__("Rate limit exceeded")
        self.status_code = status_code
        self.headers = headers or {}


class MockServerError(Exception):
    def __init__(self):
        super().__init__("Internal server error")
        self.status_code = 500


class MockGenericError(Exception):
    pass


class MockErrorWithRetryAfter(Exception):
    def __init__(self, retry_after="2"):
        super().__init__("429 Too Many Requests")
        self.status_code = 429
        self.headers = {"Retry-After": retry_after}


class MockErrorWithResponseHeaders(Exception):
    """SDK error where headers are on a nested response object."""

    def __init__(self, retry_after="3"):
        super().__init__("rate limit hit")
        self.status_code = 429

        class _Response:
            headers = {"Retry-After": retry_after}

        self.response = _Response()


# --- Tests ---


class TestIsRateLimitError:
    def test_status_code_429(self):
        assert _is_rate_limit_error(MockRateLimitError(429)) is True

    def test_status_code_500(self):
        assert _is_rate_limit_error(MockServerError()) is False

    def test_generic_error(self):
        assert _is_rate_limit_error(MockGenericError()) is False

    def test_message_based_detection(self):
        err = Exception("429 Too Many Requests - rate limit exceeded")
        assert _is_rate_limit_error(err) is True

    def test_message_without_rate(self):
        err = Exception("429 something else")
        assert _is_rate_limit_error(err) is False

    def test_status_attribute(self):
        """Some SDKs use 'status' instead of 'status_code'."""

        class E(Exception):
            status = 429

        assert _is_rate_limit_error(E()) is True


class TestGetRetryAfter:
    def test_direct_headers(self):
        exc = MockErrorWithRetryAfter("5")
        assert _get_retry_after(exc) == 5.0

    def test_response_headers(self):
        exc = MockErrorWithResponseHeaders("3")
        assert _get_retry_after(exc) == 3.0

    def test_no_headers(self):
        exc = MockGenericError()
        assert _get_retry_after(exc) is None

    def test_capped_at_max(self):
        exc = MockErrorWithRetryAfter("999")
        result = _get_retry_after(exc)
        assert result == _BACKOFF_MAX_SECONDS

    def test_invalid_value(self):
        exc = MockErrorWithRetryAfter("not-a-number")
        assert _get_retry_after(exc) is None

    def test_lowercase_header(self):
        exc = MockRateLimitError(429, headers={"retry-after": "4"})
        assert _get_retry_after(exc) == 4.0


class TestComputeBackoff:
    def test_rate_limit_exponential(self):
        exc = MockRateLimitError(429)
        assert _compute_backoff(0, exc) == _BACKOFF_BASE_SECONDS * 1  # 1s
        assert _compute_backoff(1, exc) == _BACKOFF_BASE_SECONDS * 2  # 2s
        assert _compute_backoff(2, exc) == _BACKOFF_BASE_SECONDS * 4  # 4s

    def test_rate_limit_capped(self):
        exc = MockRateLimitError(429)
        # attempt=10 → 2^10 = 1024, should be capped
        assert _compute_backoff(10, exc) == _BACKOFF_MAX_SECONDS

    def test_rate_limit_respects_retry_after(self):
        exc = MockErrorWithRetryAfter("7")
        assert _compute_backoff(0, exc) == 7.0

    def test_non_rate_limit_linear(self):
        exc = MockServerError()
        assert _compute_backoff(0, exc) == 0.5
        assert _compute_backoff(1, exc) == 1.0
        assert _compute_backoff(2, exc) == 1.5

    def test_generic_error_linear(self):
        exc = MockGenericError()
        assert _compute_backoff(0, exc) == 0.5
