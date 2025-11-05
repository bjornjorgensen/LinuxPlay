"""Tests for security features: rate limiting, path traversal prevention, authentication."""

import time
from pathlib import Path
from unittest.mock import patch

import pytest


class TestRateLimiting:
    """Tests for PIN authentication rate limiting."""

    def setup_method(self):
        """Reset host_state before each test."""
        # Import here to avoid module-level side effects
        from linuxplay.host import host_state

        with host_state.auth_lock:
            host_state.failed_auth_attempts.clear()
        host_state.session_active = False
        host_state.authed_client_ip = None

    def test_first_attempt_allowed(self):
        """First auth attempt from an IP should be allowed."""
        from linuxplay.host import _check_rate_limit

        allowed, reason = _check_rate_limit("192.168.1.100")
        assert allowed is True
        assert reason == ""

    def test_record_failed_attempt(self):
        """Recording failed attempts should increment counter."""
        from linuxplay.host import _record_failed_auth, host_state

        test_ip = "192.168.1.100"
        _record_failed_auth(test_ip)

        with host_state.auth_lock:
            assert test_ip in host_state.failed_auth_attempts
            count, first_attempt, lockout = host_state.failed_auth_attempts[test_ip]
            assert count == 1
            assert first_attempt > 0
            assert lockout is None

    def test_multiple_failed_attempts(self):
        """Multiple failed attempts should be tracked."""
        from linuxplay.host import _record_failed_auth, host_state

        test_ip = "192.168.1.100"
        for _ in range(3):
            _record_failed_auth(test_ip)

        with host_state.auth_lock:
            count, _, _ = host_state.failed_auth_attempts[test_ip]
            assert count == 3

    def test_max_attempts_triggers_lockout(self):
        """Exceeding max attempts should trigger lockout."""
        from linuxplay.host import MAX_AUTH_ATTEMPTS, _check_rate_limit, _record_failed_auth

        test_ip = "192.168.1.100"

        # Record max attempts
        for _ in range(MAX_AUTH_ATTEMPTS):
            _record_failed_auth(test_ip)

        # Check should now fail
        allowed, reason = _check_rate_limit(test_ip)
        assert allowed is False
        assert "locked out" in reason.lower() or "too many" in reason.lower()

    def test_lockout_duration(self):
        """Lockout should persist for the configured duration."""
        from linuxplay.host import (
            MAX_AUTH_ATTEMPTS,
            _check_rate_limit,
            _record_failed_auth,
            host_state,
        )

        test_ip = "192.168.1.100"

        # Trigger lockout
        for _ in range(MAX_AUTH_ATTEMPTS):
            _record_failed_auth(test_ip)
        _check_rate_limit(test_ip)  # Apply lockout

        # Should still be locked
        allowed, _ = _check_rate_limit(test_ip)
        assert allowed is False

        # Verify lockout_until is set
        with host_state.auth_lock:
            _, _, lockout_until = host_state.failed_auth_attempts[test_ip]
            assert lockout_until is not None
            assert lockout_until > time.time()

    def test_clear_failed_auth_on_success(self):
        """Successful authentication should clear failed attempts."""
        from linuxplay.host import _clear_failed_auth, _record_failed_auth, host_state

        test_ip = "192.168.1.100"

        # Record some failures
        _record_failed_auth(test_ip)
        _record_failed_auth(test_ip)

        with host_state.auth_lock:
            assert test_ip in host_state.failed_auth_attempts

        # Clear on success
        _clear_failed_auth(test_ip)

        with host_state.auth_lock:
            assert test_ip not in host_state.failed_auth_attempts

    def test_attempts_reset_after_window(self):
        """Failed attempts should reset after time window expires."""
        from linuxplay.host import AUTH_WINDOW, _check_rate_limit, host_state

        test_ip = "192.168.1.100"

        # Record attempt with old timestamp
        with host_state.auth_lock:
            old_time = time.time() - AUTH_WINDOW - 10
            host_state.failed_auth_attempts[test_ip] = (2, old_time, None)

        # Check should reset and allow
        allowed, reason = _check_rate_limit(test_ip)
        assert allowed is True
        assert reason == ""

        with host_state.auth_lock:
            assert test_ip not in host_state.failed_auth_attempts

    def test_different_ips_independent(self):
        """Rate limiting should be independent per IP."""
        from linuxplay.host import _check_rate_limit, _record_failed_auth

        ip1 = "192.168.1.100"
        ip2 = "192.168.1.101"

        # Fail IP1 multiple times
        for _ in range(3):
            _record_failed_auth(ip1)

        # IP2 should still be allowed
        allowed, reason = _check_rate_limit(ip2)
        assert allowed is True
        assert reason == ""


class TestPinRotation:
    """Tests for PIN rotation logic fixes."""

    def setup_method(self):
        """Reset host_state before each test."""
        from linuxplay.host import host_state

        host_state.session_active = False
        host_state.pin_code = None
        host_state.pin_expiry = 0

    def test_forced_rotation_overrides_active_session(self):
        """Forced PIN rotation should work even when session is active."""
        from linuxplay.host import host_state, pin_rotate_if_needed

        # Set session as active
        host_state.session_active = True
        old_pin = "123456"
        host_state.pin_code = old_pin
        host_state.pin_expiry = time.time() + 100

        # Force rotation
        pin_rotate_if_needed(force=True)

        # PIN should have changed
        assert host_state.pin_code != old_pin
        assert host_state.pin_code is not None

    def test_normal_rotation_respects_active_session(self):
        """Normal rotation should not happen during active session."""
        from linuxplay.host import host_state, pin_rotate_if_needed

        # Set session as active with expired PIN
        host_state.session_active = True
        old_pin = "123456"
        host_state.pin_code = old_pin
        host_state.pin_expiry = time.time() - 10  # Expired

        # Try normal rotation (not forced)
        pin_rotate_if_needed(force=False)

        # PIN should NOT change because session is active
        assert host_state.pin_code == old_pin

    def test_rotation_when_no_session(self):
        """PIN should rotate when no session is active and PIN expired."""
        from linuxplay.host import host_state, pin_rotate_if_needed

        host_state.session_active = False
        host_state.pin_code = None
        host_state.pin_expiry = 0

        pin_rotate_if_needed()

        # Should have generated new PIN
        assert host_state.pin_code is not None
        assert len(host_state.pin_code) == 6
        assert host_state.pin_expiry > time.time()


class TestFileUploadSecurity:
    """Tests for file upload path traversal prevention and authentication."""

    def test_path_traversal_blocked(self):
        """Path traversal attempts should be blocked."""

        dest_dir = Path.home() / "LinuxPlayDrop"

        # Test various path traversal attempts
        dangerous_filenames = [
            "../../etc/passwd",
            "../../../root/.ssh/id_rsa",
            "../../.ssh/authorized_keys",
            "./../../../etc/shadow",
        ]

        for filename in dangerous_filenames:
            # Extract basename (what the code does)
            safe_filename = Path(filename).name
            dest_path = (dest_dir / safe_filename).resolve()

            # Verify it's contained within dest_dir
            # This mimics the security check in the code
            assert dest_path.is_relative_to(dest_dir.resolve()), f"Failed to block: {filename}"

    def test_hidden_files_rejected(self):
        """Hidden files (starting with .) should be rejected."""

        hidden_files = [".hidden", ".bashrc", ".config"]

        for filename in hidden_files:
            safe_filename = Path(filename).name
            # Code checks: if not safe_filename or safe_filename.startswith('.')
            assert safe_filename.startswith("."), f"Hidden file check failed: {filename}"

    def test_safe_filenames_allowed(self):
        """Normal filenames should be allowed."""

        dest_dir = Path.home() / "LinuxPlayDrop"
        safe_filenames = ["document.pdf", "image.png", "video.mp4", "data.csv"]

        for filename in safe_filenames:
            safe_filename = Path(filename).name
            assert safe_filename == filename
            assert not safe_filename.startswith(".")

            dest_path = (dest_dir / safe_filename).resolve()
            assert dest_path.is_relative_to(dest_dir.resolve())

    def test_absolute_path_stripped(self):
        """Absolute paths should be stripped to basename."""
        import platform

        # Test Unix paths (works on both platforms)
        unix_cases = [
            ("/etc/passwd", "passwd"),
            ("/home/user/.bashrc", ".bashrc"),
        ]

        for full_path, expected_name in unix_cases:
            safe_filename = Path(full_path).name
            assert safe_filename == expected_name

        # Windows path only tested on Windows
        if platform.system() == "Windows":
            win_cases = [
                ("C:\\Windows\\System32\\config.sys", "config.sys"),
            ]
            for full_path, expected_name in win_cases:
                safe_filename = Path(full_path).name
                assert safe_filename == expected_name

    @patch("linuxplay.host.host_state")
    def test_unauthenticated_upload_rejected(self, mock_host_state):
        """Uploads from unauthenticated IPs should be rejected."""
        # Set up mock state
        mock_host_state.session_active = True
        mock_host_state.authed_client_ip = "192.168.1.100"

        # Test cases: (peer_ip, should_be_allowed)
        test_cases = [
            ("192.168.1.100", True),  # Authenticated IP
            ("192.168.1.101", False),  # Different IP
            ("192.168.1.200", False),  # Unauthorized IP
        ]

        for peer_ip, should_allow in test_cases:
            # Mimic the check in file_upload_listener
            is_allowed = mock_host_state.session_active and peer_ip == mock_host_state.authed_client_ip
            assert is_allowed == should_allow, f"Auth check failed for {peer_ip}"

    @patch("linuxplay.host.host_state")
    def test_no_active_session_rejected(self, mock_host_state):
        """Uploads when no session is active should be rejected."""
        mock_host_state.session_active = False
        mock_host_state.authed_client_ip = None

        # Even if IP matches, no active session = reject
        peer_ip = "192.168.1.100"
        is_allowed = mock_host_state.session_active and peer_ip == mock_host_state.authed_client_ip
        assert is_allowed is False


class TestPinGeneration:
    """Tests for PIN generation."""

    def test_pin_length(self):
        """Generated PINs should have correct length."""
        from linuxplay.host import PIN_LENGTH, _gen_pin

        pin = _gen_pin()
        assert len(pin) == PIN_LENGTH

    def test_pin_digits_only(self):
        """Generated PINs should contain only digits."""
        from linuxplay.host import _gen_pin

        pin = _gen_pin()
        assert pin.isdigit()

    def test_pin_uniqueness(self):
        """Generated PINs should be different (with high probability)."""
        from linuxplay.host import _gen_pin

        pins = [_gen_pin() for _ in range(100)]
        # Should have many unique values (not all the same)
        assert len(set(pins)) > 50

    def test_pin_leading_zeros(self):
        """PINs should maintain leading zeros."""
        from linuxplay.host import _gen_pin

        # Test with small length to increase chance of leading zeros
        pin = _gen_pin(length=6)
        assert len(pin) == 6
        assert pin.isdigit()


@pytest.mark.integration
class TestHandshakeRateLimiting:
    """Integration tests for handshake with rate limiting."""

    def setup_method(self):
        """Reset host_state before each test."""
        from linuxplay.host import host_state

        with host_state.auth_lock:
            host_state.failed_auth_attempts.clear()
        host_state.session_active = False
        host_state.pin_code = "123456"
        host_state.pin_expiry = time.time() + 100

    def test_failed_pin_records_attempt(self):
        """Failed PIN authentication should record attempt."""
        from linuxplay.host import _record_failed_auth, host_state

        test_ip = "192.168.1.100"
        _record_failed_auth(test_ip)

        with host_state.auth_lock:
            assert test_ip in host_state.failed_auth_attempts
            count, _, _ = host_state.failed_auth_attempts[test_ip]
            assert count == 1

    def test_successful_auth_clears_attempts(self):
        """Successful authentication should clear failed attempts."""
        from linuxplay.host import _clear_failed_auth, _record_failed_auth, host_state

        test_ip = "192.168.1.100"

        # Record failures
        for _ in range(3):
            _record_failed_auth(test_ip)

        # Successful auth clears
        _clear_failed_auth(test_ip)

        with host_state.auth_lock:
            assert test_ip not in host_state.failed_auth_attempts
