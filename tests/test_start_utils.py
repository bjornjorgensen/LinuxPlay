#!/usr/bin/env python3
"""
Unit tests for start.py utility functions.

Tests the launcher utility functions without requiring GUI interaction.
"""

import subprocess
from unittest.mock import MagicMock, Mock, patch

import pytest

from linuxplay.start import (
    ENCODER_NAME_MAP,
    _client_cert_present,
    _ffmpeg_running_for_us,
    _proc_is_running,
    ffmpeg_has_encoder,
    ffmpeg_ok,
    load_cfg,
    save_cfg,
)


class TestCertificateDetection:
    """Test certificate presence detection."""

    def test_cert_present_when_both_exist(self, tmp_path):
        """Both cert and key files exist."""
        (tmp_path / "client_cert.pem").write_text("cert")
        (tmp_path / "client_key.pem").write_text("key")
        assert _client_cert_present(tmp_path) is True

    def test_cert_missing_when_only_cert(self, tmp_path):
        """Only cert file exists."""
        (tmp_path / "client_cert.pem").write_text("cert")
        assert _client_cert_present(tmp_path) is False

    def test_cert_missing_when_only_key(self, tmp_path):
        """Only key file exists."""
        (tmp_path / "client_key.pem").write_text("key")
        assert _client_cert_present(tmp_path) is False

    def test_cert_missing_when_neither_exist(self, tmp_path):
        """Neither cert nor key exists."""
        assert _client_cert_present(tmp_path) is False

    def test_handles_invalid_path(self):
        """Handles invalid path gracefully."""
        assert _client_cert_present(None) is False
        assert _client_cert_present(123) is False


class TestFFmpegDetection:
    """Test FFmpeg detection utilities."""

    @patch("subprocess.check_output")
    def test_ffmpeg_ok_when_available(self, mock_check):
        """FFmpeg is available."""
        mock_check.return_value = "ffmpeg version 4.4.2"
        assert ffmpeg_ok() is True

    @patch("subprocess.check_output")
    def test_ffmpeg_ok_when_not_found(self, mock_check):
        """FFmpeg not found."""
        mock_check.side_effect = FileNotFoundError()
        assert ffmpeg_ok() is False

    @patch("subprocess.check_output")
    def test_ffmpeg_ok_when_error(self, mock_check):
        """FFmpeg command fails."""
        mock_check.side_effect = subprocess.CalledProcessError(1, "ffmpeg")
        assert ffmpeg_ok() is False

    @patch("subprocess.check_output")
    def test_ffmpeg_has_encoder_caches_results(self, mock_check):
        """Encoder check caches results."""
        mock_check.return_value = "h264_nvenc\nh264_qsv\nlibx264"

        # First call
        assert ffmpeg_has_encoder("h264_nvenc") is True
        assert mock_check.call_count == 1

        # Second call should use cache
        assert ffmpeg_has_encoder("h264_nvenc") is True
        assert mock_check.call_count == 1  # No additional call

    @patch("subprocess.check_output")
    def test_ffmpeg_has_encoder_case_insensitive(self, mock_check):
        """Encoder check is case insensitive."""
        mock_check.return_value = "H264_NVENC\nH264_QSV\nLIBX264"

        assert ffmpeg_has_encoder("h264_nvenc") is True
        assert ffmpeg_has_encoder("H264_NVENC") is True

    @patch("subprocess.check_output")
    @patch("linuxplay.start._FFENC_CACHE", {})
    def test_ffmpeg_has_encoder_not_found(self, mock_check):
        """Encoder not available."""
        mock_check.return_value = "libx264\nlibx265"
        assert ffmpeg_has_encoder("hevc_nvenc") is False  # Use different encoder to avoid cache


class TestConfigPersistence:
    """Test configuration save/load."""

    def test_save_and_load_cfg(self, tmp_path, monkeypatch):
        """Save and load config successfully."""
        cfg_path = tmp_path / "test_cfg.json"
        monkeypatch.setattr("linuxplay.start.CFG_PATH", cfg_path)

        data = {"host": "192.168.1.1", "port": 7001, "debug": True}
        save_cfg(data)
        loaded = load_cfg()
        assert loaded == data

    def test_load_cfg_missing_file(self, tmp_path, monkeypatch):
        """Load config when file doesn't exist."""
        cfg_path = tmp_path / "nonexistent.json"
        monkeypatch.setattr("linuxplay.start.CFG_PATH", cfg_path)

        assert load_cfg() == {}

    def test_load_cfg_invalid_json(self, tmp_path, monkeypatch):
        """Load config with invalid JSON."""
        cfg_path = tmp_path / "invalid.json"
        cfg_path.write_text("not valid json {")
        monkeypatch.setattr("linuxplay.start.CFG_PATH", cfg_path)

        assert load_cfg() == {}

    def test_save_cfg_permission_error(self, tmp_path, monkeypatch):
        """Handle permission errors gracefully."""
        cfg_path = tmp_path / "readonly" / "config.json"
        cfg_path.parent.mkdir()
        cfg_path.parent.chmod(0o444)
        monkeypatch.setattr("linuxplay.start.CFG_PATH", cfg_path)

        # Should not raise, just log warning
        save_cfg({"test": "data"})


class TestProcessDetection:
    """Test process detection utilities."""

    def test_proc_is_running_with_running_process(self):
        """Process is running."""
        mock_proc = Mock()
        mock_proc.poll.return_value = None
        assert _proc_is_running(mock_proc) is True

    def test_proc_is_running_with_finished_process(self):
        """Process has finished."""
        mock_proc = Mock()
        mock_proc.poll.return_value = 0
        assert _proc_is_running(mock_proc) is False

    def test_proc_is_running_with_none(self):
        """Process is None."""
        assert _proc_is_running(None) is False

    def test_proc_is_running_with_error(self):
        """Process raises error."""
        mock_proc = Mock()
        mock_proc.poll.side_effect = OSError()
        assert _proc_is_running(mock_proc) is False

    @patch("psutil.process_iter")
    def test_ffmpeg_running_for_us_found(self, mock_iter):
        """FFmpeg process found with our marker."""
        mock_proc = MagicMock()
        mock_proc.info = {"name": "ffmpeg", "cmdline": ["/usr/bin/ffmpeg", "-metadata", "title=LinuxPlayHost"]}
        mock_iter.return_value = [mock_proc]

        assert _ffmpeg_running_for_us("LinuxPlayHost") is True

    @patch("psutil.process_iter")
    def test_ffmpeg_running_for_us_not_found(self, mock_iter):
        """FFmpeg process not found."""
        mock_proc = MagicMock()
        mock_proc.info = {"name": "python", "cmdline": ["/usr/bin/python", "script.py"]}
        mock_iter.return_value = [mock_proc]

        assert _ffmpeg_running_for_us("LinuxPlayHost") is False

    @patch("psutil.process_iter")
    def test_ffmpeg_running_for_us_error(self, mock_iter):
        """Handle psutil errors gracefully."""
        mock_iter.side_effect = RuntimeError("Access denied")
        assert _ffmpeg_running_for_us("LinuxPlayHost") is False


class TestEncoderMapping:
    """Test encoder name mapping."""

    def test_encoder_map_completeness(self):
        """All common codec+backend combos mapped."""
        codecs = ["h.264", "h.265"]
        backends = ["nvenc", "qsv", "amf", "vaapi", "cpu"]

        for codec in codecs:
            for backend in backends:
                key = (codec, backend)
                assert key in ENCODER_NAME_MAP, f"Missing mapping for {key}"

    def test_encoder_map_h264_nvenc(self):
        """H.264 NVENC maps correctly."""
        assert ENCODER_NAME_MAP[("h.264", "nvenc")] == "h264_nvenc"

    def test_encoder_map_h265_vaapi(self):
        """H.265 VAAPI maps correctly."""
        assert ENCODER_NAME_MAP[("h.265", "vaapi")] == "hevc_vaapi"

    def test_encoder_map_cpu_fallback(self):
        """CPU encoders use libx264/libx265."""
        assert ENCODER_NAME_MAP[("h.264", "cpu")] == "libx264"
        assert ENCODER_NAME_MAP[("h.265", "cpu")] == "libx265"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
