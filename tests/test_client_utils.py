"""Unit tests for client.py utility functions."""

import subprocess
from pathlib import Path

from linuxplay.client import (
    CLIENT_STATE,
    _best_ts_pkt_size,
    _clear_network_mode_cache,
    _probe_hardware_capabilities,
    choose_auto_hwaccel,
    detect_network_mode,
    ffmpeg_hwaccels,
    pick_best_renderer,
)


class TestNetworkModeDetection:
    """Tests for network mode detection."""

    def test_detect_network_mode_wifi_linux(self, monkeypatch):
        """Test WiFi detection on Linux."""
        _clear_network_mode_cache()  # Clear cache before test

        def mock_check_output(cmd, **_kwargs):
            if cmd[0] == "ip":
                return "dev wlp3s0 src 192.168.1.100"
            return ""

        def mock_path_exists(_self):
            # /sys/class/net/wlp3s0/wireless exists for WiFi
            return "wireless" in str(_self)

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        monkeypatch.setattr(Path, "exists", mock_path_exists)

        mode = detect_network_mode("192.168.1.1")
        assert mode == "wifi"

    def test_detect_network_mode_lan_linux(self, monkeypatch):
        """Test LAN detection on Linux."""
        _clear_network_mode_cache()  # Clear cache before test

        def mock_check_output(cmd, **_kwargs):
            if cmd[0] == "ip":
                return "dev eth0 src 192.168.1.100"
            return ""

        def mock_path_exists(_self):
            return False  # No wireless directory

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        monkeypatch.setattr(Path, "exists", mock_path_exists)

        mode = detect_network_mode("192.168.1.1")
        assert mode == "lan"

    def test_detect_network_mode_fallback(self, monkeypatch):
        """Test fallback to LAN on detection failure."""
        _clear_network_mode_cache()  # Clear cache before test

        def mock_check_output(*_args, **_kwargs):
            raise Exception("Command failed")

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)

        mode = detect_network_mode("192.168.1.1")
        assert mode == "lan"  # Should default to LAN on error


class TestNetworkModeCaching:
    """Tests for network mode detection caching."""

    def test_cache_returns_same_result_on_second_call(self, monkeypatch):
        """Test that cache returns same result without re-executing subprocess."""
        _clear_network_mode_cache()

        call_count = 0

        def mock_check_output(cmd, **_kwargs):
            nonlocal call_count
            call_count += 1
            if cmd[0] == "ip":
                return "dev eth0 src 192.168.1.100"
            return ""

        def mock_path_exists(_self):
            return False

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        monkeypatch.setattr(Path, "exists", mock_path_exists)

        # First call - should execute subprocess
        mode1 = detect_network_mode("192.168.1.1")
        assert mode1 == "lan"
        first_call_count = call_count
        assert first_call_count == 1

        # Second call - should use cache
        mode2 = detect_network_mode("192.168.1.1")
        assert mode2 == "lan"
        assert call_count == first_call_count  # Should NOT increment

    def test_cache_different_ips_tracked_separately(self, monkeypatch):
        """Test that different host IPs are cached separately."""
        _clear_network_mode_cache()

        def mock_check_output(cmd, **_kwargs):
            if cmd[0] == "ip":
                # Return different interfaces based on destination
                if "192.168.1.1" in " ".join(cmd):
                    return "dev wlp3s0 src 192.168.1.100"
                return "dev eth0 src 10.0.0.100"
            return ""

        def mock_path_exists(_self):
            return "wlp3s0" in str(_self)

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        monkeypatch.setattr(Path, "exists", mock_path_exists)

        mode1 = detect_network_mode("192.168.1.1")
        mode2 = detect_network_mode("10.0.0.1")

        # Different IPs should have different cached modes
        assert mode1 == "wifi"
        assert mode2 == "lan"

    def test_cache_expires_after_ttl(self, monkeypatch):
        """Test that cache expires after TTL period."""
        import time

        _clear_network_mode_cache()

        call_count = 0

        def mock_check_output(cmd, **_kwargs):
            nonlocal call_count
            call_count += 1
            if cmd[0] == "ip":
                return "dev eth0 src 192.168.1.100"
            return ""

        def mock_path_exists(_self):
            return False

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        monkeypatch.setattr(Path, "exists", mock_path_exists)

        # Mock time to control cache expiry
        original_time = time.time
        fake_time = [original_time()]

        def mock_time():
            return fake_time[0]

        monkeypatch.setattr(time, "time", mock_time)

        # First call at time 0
        mode1 = detect_network_mode("192.168.1.1")
        assert mode1 == "lan"
        first_call_count = call_count
        assert first_call_count == 1

        # Second call at time 0 (within TTL) - should use cache
        mode2 = detect_network_mode("192.168.1.1")
        assert mode2 == "lan"
        assert call_count == first_call_count  # Verify cache was used (no new call)

        # Advance time beyond TTL (5 minutes = 300 seconds)
        fake_time[0] += 301

        # Third call after TTL expiry - should re-execute
        mode3 = detect_network_mode("192.168.1.1")
        assert mode3 == "lan"
        assert call_count == 2

    def test_clear_cache_clears_all_entries(self, monkeypatch):
        """Test that clearing cache removes all entries."""
        _clear_network_mode_cache()

        call_count = 0

        def mock_check_output(cmd, **_kwargs):
            nonlocal call_count
            call_count += 1
            if cmd[0] == "ip":
                return "dev eth0 src 192.168.1.100"
            return ""

        def mock_path_exists(_self):
            return False

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        monkeypatch.setattr(Path, "exists", mock_path_exists)

        # First call
        detect_network_mode("192.168.1.1")
        assert call_count == 1

        # Clear cache
        _clear_network_mode_cache()

        # Should re-execute after cache clear
        detect_network_mode("192.168.1.1")
        assert call_count == 2


class TestHardwareAccelSelection:
    """Tests for hardware acceleration selection."""

    def test_choose_auto_hwaccel_windows(self, monkeypatch):
        """Test auto hardware accel selection on Windows."""

        def mock_hwaccels():
            return {"d3d11va", "cuda", "dxva2"}

        monkeypatch.setattr("linuxplay.client.ffmpeg_hwaccels", mock_hwaccels)

        result = choose_auto_hwaccel()
        assert result in ["d3d11va", "cuda", "dxva2", "qsv"]

    def test_choose_auto_hwaccel_linux(self, monkeypatch):
        """Test auto hardware accel selection on Linux."""

        def mock_hwaccels():
            return {"vaapi", "cuda"}

        monkeypatch.setattr("linuxplay.client.ffmpeg_hwaccels", mock_hwaccels)

        result = choose_auto_hwaccel()
        assert result in ["vaapi", "cuda", "qsv"]

    def test_choose_auto_hwaccel_cpu_fallback(self, monkeypatch):
        """Test CPU fallback when no hardware accel available."""

        def mock_hwaccels():
            return set()  # No hardware acceleration

        monkeypatch.setattr("linuxplay.client.ffmpeg_hwaccels", mock_hwaccels)

        result = choose_auto_hwaccel()
        assert result == "cpu"


class TestMPEGTSPacketSize:
    """Tests for MPEG-TS packet size calculation in client."""

    def test_best_ts_pkt_size_ipv4(self):
        """Test packet size for IPv4."""
        result = _best_ts_pkt_size(1500, False)
        assert result == 1316
        assert result % 188 == 0

    def test_best_ts_pkt_size_ipv6(self):
        """Test packet size for IPv6."""
        result = _best_ts_pkt_size(1500, True)
        assert result == 1316
        assert result % 188 == 0

    def test_best_ts_pkt_size_minimum(self):
        """Test minimum packet size handling."""
        result = _best_ts_pkt_size(400, False)
        assert result >= 188
        assert result % 188 == 0


class TestClientStateManagement:
    """Tests for client state management."""

    def test_client_state_initial(self):
        """Test initial client state."""
        assert CLIENT_STATE["connected"] is False
        assert CLIENT_STATE["last_heartbeat"] >= 0
        assert CLIENT_STATE["net_mode"] in ["lan", "wifi"]
        assert CLIENT_STATE["reconnecting"] is False

    def test_client_state_update(self):
        """Test updating client state."""
        # Update state
        CLIENT_STATE["connected"] = True
        CLIENT_STATE["net_mode"] = "wifi"

        assert CLIENT_STATE["connected"] is True
        assert CLIENT_STATE["net_mode"] == "wifi"

        # Reset for other tests
        CLIENT_STATE["connected"] = False
        CLIENT_STATE["net_mode"] = "lan"


class TestRendererSelection:
    """Tests for renderer backend selection."""

    def test_pick_best_renderer_returns_valid(self):
        """Test that pick_best_renderer returns a valid renderer."""
        renderer = pick_best_renderer()
        assert renderer is not None
        assert hasattr(renderer, "render_frame")
        assert hasattr(renderer, "is_valid")
        assert hasattr(renderer, "name")

    def test_renderer_has_name(self):
        """Test that renderer has a name."""
        renderer = pick_best_renderer()
        name = renderer.name()
        assert isinstance(name, str)
        assert len(name) > 0


class TestKeyMapping:
    """Tests for key name mapping."""


class TestHardwareCapabilities:
    """Tests for hardware capability probing."""

    def test_probe_hardware_capabilities_no_error(self, monkeypatch):
        """Test hardware probing doesn't raise errors."""

        def mock_path_exists(_self):
            return False

        monkeypatch.setattr(Path, "exists", mock_path_exists)

        # Should not raise an exception
        _probe_hardware_capabilities()

    def test_ffmpeg_hwaccels_returns_set(self, monkeypatch):
        """Test ffmpeg_hwaccels returns a set."""

        def mock_check_output(*_args, **_kwargs):
            return "Hardware acceleration methods:\ncuda\nvaapi\n"

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)

        result = ffmpeg_hwaccels()
        assert isinstance(result, set)
        assert "cuda" in result
        assert "vaapi" in result

    def test_ffmpeg_hwaccels_handles_error(self, monkeypatch):
        """Test ffmpeg_hwaccels handles errors gracefully."""

        def mock_check_output(*_args, **_kwargs):
            raise Exception("Command failed")

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)

        result = ffmpeg_hwaccels()
        assert isinstance(result, set)
        assert len(result) == 0  # Empty set on error
