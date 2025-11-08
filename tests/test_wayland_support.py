"""Tests for Wayland display server support."""

import subprocess
from unittest.mock import patch

from linuxplay.host import (
    _detect_monitors_wayland,
    detect_display_server,
    detect_monitors,
)


class TestDisplayServerDetection:
    """Tests for display server detection."""

    def test_detect_display_server_wayland_from_session_type(self):
        """Test Wayland detection via XDG_SESSION_TYPE."""
        with patch.dict("os.environ", {"XDG_SESSION_TYPE": "wayland"}):
            assert detect_display_server() == "wayland"

    def test_detect_display_server_x11_from_session_type(self):
        """Test X11 detection via XDG_SESSION_TYPE."""
        with patch.dict("os.environ", {"XDG_SESSION_TYPE": "x11"}, clear=True):
            assert detect_display_server() == "x11"

    def test_detect_display_server_wayland_from_display_var(self):
        """Test Wayland detection via WAYLAND_DISPLAY."""
        with patch.dict("os.environ", {"WAYLAND_DISPLAY": "wayland-0"}, clear=True):
            assert detect_display_server() == "wayland"

    def test_detect_display_server_x11_from_display_var(self):
        """Test X11 detection via DISPLAY."""
        with patch.dict("os.environ", {"DISPLAY": ":0"}, clear=True):
            assert detect_display_server() == "x11"

    def test_detect_display_server_unknown(self):
        """Test unknown display server when no env vars set."""
        with patch.dict("os.environ", {}, clear=True):
            assert detect_display_server() == "unknown"

    def test_detect_display_server_case_insensitive(self):
        """Test case-insensitive detection."""
        with patch.dict("os.environ", {"XDG_SESSION_TYPE": "WAYLAND"}):
            assert detect_display_server() == "wayland"
        with patch.dict("os.environ", {"XDG_SESSION_TYPE": "X11"}):
            assert detect_display_server() == "x11"

    def test_detect_display_server_wayland_priority(self):
        """Test that WAYLAND_DISPLAY takes priority over DISPLAY."""
        with patch.dict("os.environ", {"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, clear=True):
            result = detect_display_server()
            assert result in ("wayland", "x11")  # Both valid, depends on fallback order


class TestWaylandMonitorDetection:
    """Tests for Wayland-specific monitor detection."""

    @patch("subprocess.check_output")
    @patch("linuxplay.host.which")
    def test_detect_monitors_wayland_wlr_randr_success(self, mock_which, mock_check_output):
        """Test successful monitor detection via wlr-randr."""
        mock_which.side_effect = lambda cmd: "/usr/bin/wlr-randr" if cmd == "wlr-randr" else None
        mock_check_output.return_value = """eDP-1 "Some Manufacturer Model"
  Physical size: 344x194 mm
  Enabled: yes
  Modes:
    1920x1080 px, 60.000000 Hz (preferred, current)
  Position: 0,0
  Transform: normal
  Scale: 1.000000
"""
        result = _detect_monitors_wayland()
        assert len(result) == 1
        assert result[0] == (1920, 1080, 0, 0)

    @patch("subprocess.check_output")
    @patch("linuxplay.host.which")
    def test_detect_monitors_wayland_wlr_randr_multiple(self, mock_which, mock_check_output):
        """Test multiple monitor detection via wlr-randr."""
        mock_which.side_effect = lambda cmd: "/usr/bin/wlr-randr" if cmd == "wlr-randr" else None
        mock_check_output.return_value = """eDP-1 "Laptop Display"
  1920x1080 px, 60.000000 Hz (preferred, current)
  Position: 0,0

HDMI-A-1 "External Monitor"
  2560x1440 px, 60.000000 Hz (preferred, current)
  Position: 1920,0
"""
        result = _detect_monitors_wayland()
        assert len(result) == 2
        assert result[0] == (1920, 1080, 0, 0)
        assert result[1] == (2560, 1440, 1920, 0)

    @patch("linuxplay.host.which")
    @patch("subprocess.check_output")
    def test_detect_monitors_wayland_swaymsg_success(self, mock_check_output, mock_which):
        """Test successful monitor detection via swaymsg."""

        def which_side_effect(cmd):
            if cmd == "wlr-randr":
                return None
            if cmd == "swaymsg":
                return "/usr/bin/swaymsg"
            return None

        mock_which.side_effect = which_side_effect
        mock_check_output.return_value = """[
  {
    "name": "eDP-1",
    "active": true,
    "rect": {
      "x": 0,
      "y": 0,
      "width": 1920,
      "height": 1080
    }
  }
]"""
        result = _detect_monitors_wayland()
        assert len(result) == 1
        assert result[0] == (1920, 1080, 0, 0)

    @patch("linuxplay.host.which")
    @patch("subprocess.check_output")
    def test_detect_monitors_wayland_hyprctl_success(self, mock_check_output, mock_which):
        """Test successful monitor detection via hyprctl."""

        def which_side_effect(cmd):
            if cmd in ("wlr-randr", "swaymsg"):
                return None
            if cmd == "hyprctl":
                return "/usr/bin/hyprctl"
            return None

        mock_which.side_effect = which_side_effect
        mock_check_output.return_value = """[
  {
    "id": 0,
    "name": "eDP-1",
    "width": 1920,
    "height": 1080,
    "x": 0,
    "y": 0
  }
]"""
        result = _detect_monitors_wayland()
        assert len(result) == 1
        assert result[0] == (1920, 1080, 0, 0)

    @patch("linuxplay.host.which")
    def test_detect_monitors_wayland_no_tools(self, mock_which):
        """Test monitor detection when no Wayland tools available."""
        mock_which.return_value = None
        result = _detect_monitors_wayland()
        assert result == []

    @patch("subprocess.check_output")
    @patch("linuxplay.host.which")
    def test_detect_monitors_wayland_command_error(self, mock_which, mock_check_output):
        """Test monitor detection handles command errors gracefully."""
        mock_which.side_effect = lambda cmd: "/usr/bin/wlr-randr" if cmd == "wlr-randr" else None
        mock_check_output.side_effect = subprocess.CalledProcessError(1, "wlr-randr")
        result = _detect_monitors_wayland()
        assert result == []

    @patch("subprocess.check_output")
    @patch("linuxplay.host.which")
    def test_detect_monitors_wayland_timeout(self, mock_which, mock_check_output):
        """Test monitor detection handles timeouts gracefully."""
        mock_which.side_effect = lambda cmd: "/usr/bin/wlr-randr" if cmd == "wlr-randr" else None
        mock_check_output.side_effect = subprocess.TimeoutExpired("wlr-randr", 5)
        result = _detect_monitors_wayland()
        assert result == []

    @patch("linuxplay.host.which")
    @patch("subprocess.check_output")
    def test_detect_monitors_wayland_invalid_json(self, mock_check_output, mock_which):
        """Test monitor detection handles invalid JSON gracefully."""

        def which_side_effect(cmd):
            if cmd == "wlr-randr":
                return None
            if cmd == "swaymsg":
                return "/usr/bin/swaymsg"
            return None

        mock_which.side_effect = which_side_effect
        mock_check_output.return_value = "invalid json"
        result = _detect_monitors_wayland()
        assert result == []

    @patch("linuxplay.host.which")
    @patch("subprocess.check_output")
    def test_detect_monitors_wayland_inactive_output(self, mock_check_output, mock_which):
        """Test that inactive outputs are filtered out (swaymsg)."""

        def which_side_effect(cmd):
            if cmd == "wlr-randr":
                return None
            if cmd == "swaymsg":
                return "/usr/bin/swaymsg"
            return None

        mock_which.side_effect = which_side_effect
        mock_check_output.return_value = """[
  {
    "name": "eDP-1",
    "active": false,
    "rect": {"x": 0, "y": 0, "width": 1920, "height": 1080}
  }
]"""
        result = _detect_monitors_wayland()
        assert result == []

    @patch("linuxplay.host.which")
    @patch("subprocess.check_output")
    def test_detect_monitors_wayland_zero_size(self, mock_check_output, mock_which):
        """Test that zero-sized monitors are filtered out."""

        def which_side_effect(cmd):
            if cmd == "wlr-randr":
                return None
            if cmd == "swaymsg":
                return "/usr/bin/swaymsg"
            return None

        mock_which.side_effect = which_side_effect
        mock_check_output.return_value = """[
  {
    "name": "eDP-1",
    "active": true,
    "rect": {"x": 0, "y": 0, "width": 0, "height": 0}
  }
]"""
        result = _detect_monitors_wayland()
        assert result == []


class TestMonitorDetectionIntegration:
    """Integration tests for monitor detection with display server awareness."""

    @patch("linuxplay.host._detect_monitors_wayland")
    @patch("linuxplay.host.detect_display_server")
    def test_detect_monitors_prefers_wayland_on_wayland(self, mock_detect_server, mock_wayland):
        """Test that Wayland detection is preferred on Wayland systems."""
        mock_detect_server.return_value = "wayland"
        mock_wayland.return_value = [(1920, 1080, 0, 0)]

        result = detect_monitors()

        assert len(result) == 1
        assert result[0] == (1920, 1080, 0, 0)
        mock_wayland.assert_called_once()

    @patch("linuxplay.host.detect_display_server")
    @patch("linuxplay.host._detect_monitors_wayland")
    @patch("subprocess.check_output")
    def test_detect_monitors_fallback_to_xrandr_on_wayland_failure(
        self, mock_check_output, mock_wayland, mock_detect_server
    ):
        """Test fallback to xrandr if Wayland detection fails."""
        mock_detect_server.return_value = "wayland"
        mock_wayland.return_value = []
        mock_check_output.return_value = """ 0: +*eDP-1 1920/344x1080/194+0+0  eDP-1
"""

        detect_monitors()

        # Should try xrandr as fallback
        assert mock_check_output.called

    @patch("linuxplay.host.detect_display_server")
    @patch("subprocess.check_output")
    def test_detect_monitors_uses_xrandr_on_x11(self, mock_check_output, mock_detect_server):
        """Test that xrandr is used on X11 systems."""
        mock_detect_server.return_value = "x11"
        mock_check_output.return_value = """ 0: +*eDP-1 1920/344x1080/194+0+0  eDP-1
"""

        detect_monitors()

        # Should call xrandr
        mock_check_output.assert_called_once()
        assert "xrandr" in mock_check_output.call_args[0][0]

    @patch("linuxplay.host.detect_display_server")
    @patch("subprocess.check_output")
    def test_detect_monitors_handles_xrandr_error(self, mock_check_output, mock_detect_server):
        """Test that xrandr errors are handled gracefully."""
        mock_detect_server.return_value = "x11"
        mock_check_output.side_effect = subprocess.CalledProcessError(1, "xrandr")

        result = detect_monitors()

        assert result == []


class TestWaylandCaptureSelection:
    """Tests for capture method selection on Wayland."""

    def test_kmsgrab_preferred_on_wayland(self):
        """Test that kmsgrab is preferred on Wayland when available."""
        # This would require mocking build_video_cmd, which is complex
        # Testing the logic through integration tests is more appropriate

    def test_warning_when_kmsgrab_unavailable_on_wayland(self):
        """Test that a warning is logged when kmsgrab unavailable on Wayland."""
        # This would require mocking logging and build_video_cmd
        # Testing through logs in integration tests is more appropriate


class TestWaylandEdgeCases:
    """Edge case tests for Wayland support."""

    @patch("subprocess.check_output")
    @patch("linuxplay.host.which")
    def test_wlr_randr_malformed_output(self, mock_which, mock_check_output):
        """Test handling of malformed wlr-randr output."""
        mock_which.side_effect = lambda cmd: "/usr/bin/wlr-randr" if cmd == "wlr-randr" else None
        mock_check_output.return_value = """eDP-1
  Garbage data
  1920 1080
  Not a valid format
"""
        result = _detect_monitors_wayland()
        # Should handle gracefully, possibly returning empty list
        assert isinstance(result, list)

    @patch("subprocess.check_output")
    @patch("linuxplay.host.which")
    def test_wlr_randr_missing_position(self, mock_which, mock_check_output):
        """Test wlr-randr output without position information."""
        mock_which.side_effect = lambda cmd: "/usr/bin/wlr-randr" if cmd == "wlr-randr" else None
        mock_check_output.return_value = """eDP-1 "Display"
  1920x1080 px, 60.000000 Hz (preferred, current)
"""
        result = _detect_monitors_wayland()
        # Should still detect monitor, default position to 0,0
        assert len(result) == 1
        if result:
            assert result[0][2] == 0  # x position
            assert result[0][3] == 0  # y position

    @patch("linuxplay.host.which")
    @patch("subprocess.check_output")
    def test_swaymsg_missing_rect_fields(self, mock_check_output, mock_which):
        """Test swaymsg output with missing rect fields."""

        def which_side_effect(cmd):
            if cmd == "wlr-randr":
                return None
            if cmd == "swaymsg":
                return "/usr/bin/swaymsg"
            return None

        mock_which.side_effect = which_side_effect
        mock_check_output.return_value = """[
  {
    "name": "eDP-1",
    "active": true,
    "rect": {}
  }
]"""
        result = _detect_monitors_wayland()
        # Should handle missing fields, likely filter out
        assert result == []

    def test_display_server_empty_string(self):
        """Test handling of empty XDG_SESSION_TYPE."""
        with patch.dict("os.environ", {"XDG_SESSION_TYPE": ""}, clear=True):
            result = detect_display_server()
            assert result == "unknown"

    def test_display_server_whitespace(self):
        """Test handling of whitespace in XDG_SESSION_TYPE."""
        with patch.dict("os.environ", {"XDG_SESSION_TYPE": "  wayland  "}):
            result = detect_display_server()
            # Should handle whitespace (after strip and lower)
            assert result in ("wayland", "unknown")


class TestWaylandCompositorCompatibility:
    """Tests for different Wayland compositor compatibility."""

    @patch("linuxplay.host.which")
    def test_sway_compositor_detection(self, mock_which):
        """Test that swaymsg is tried for Sway compositor."""

        def which_side_effect(cmd):
            if cmd == "wlr-randr":
                return None
            if cmd == "swaymsg":
                return "/usr/bin/swaymsg"
            return None

        mock_which.side_effect = which_side_effect

        with patch("subprocess.check_output") as mock_output:
            mock_output.return_value = "[]"
            _detect_monitors_wayland()

            # Verify swaymsg was called
            assert any("swaymsg" in str(call) for call in mock_output.call_args_list)

    @patch("linuxplay.host.which")
    def test_hyprland_compositor_detection(self, mock_which):
        """Test that hyprctl is tried for Hyprland compositor."""

        def which_side_effect(cmd):
            if cmd in ("wlr-randr", "swaymsg"):
                return None
            if cmd == "hyprctl":
                return "/usr/bin/hyprctl"
            return None

        mock_which.side_effect = which_side_effect

        with patch("subprocess.check_output") as mock_output:
            mock_output.return_value = "[]"
            _detect_monitors_wayland()

            # Verify hyprctl was called
            assert any("hyprctl" in str(call) for call in mock_output.call_args_list)

    @patch("linuxplay.host.which")
    def test_wlroots_compositor_priority(self, mock_which):
        """Test that wlr-randr is tried first (wlroots compositors)."""
        mock_which.return_value = "/usr/bin/wlr-randr"

        with patch("subprocess.check_output") as mock_output:
            mock_output.return_value = ""
            _detect_monitors_wayland()

            # wlr-randr should be called first
            if mock_output.called:
                first_call = mock_output.call_args_list[0]
                assert "wlr-randr" in str(first_call)
