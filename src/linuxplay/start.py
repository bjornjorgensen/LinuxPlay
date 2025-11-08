#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import platform as py_platform
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import psutil
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# Constants
FFMPEG_OUTPUT_MIN_PARTS: int = 2  # Minimum parts when parsing ffmpeg output "d <name>"
FFMPEG_CACHE_TTL: int = 300  # Cache encoder/device detection for 5 minutes
WG_POLL_INTERVAL_MS: int = 1500  # WireGuard status check interval
PROC_POLL_INTERVAL_MS: int = 1000  # Host process status check interval
CERT_POLL_INTERVAL_MS: int = 2000  # Certificate detection check interval


HERE: Path = Path(__file__).resolve().parent
try:
    FFBIN = HERE / "ffmpeg" / "bin"
    if os.name == "nt" and (FFBIN / "ffmpeg.exe").exists():
        os.environ["PATH"] = str(FFBIN) + os.pathsep + os.environ.get("PATH", "")
except (OSError, KeyError) as e:
    logging.debug("FFmpeg path setup failed: %s", e)

# Platform detection (cached at module level for performance)
IS_WINDOWS: bool = py_platform.system() == "Windows"
IS_LINUX: bool = py_platform.system() == "Linux"
IS_MACOS: bool = py_platform.system() == "Darwin"
WG_INFO_PATH: Path = Path("/tmp/linuxplay_wg_info.json")
CFG_PATH: Path = Path.home() / ".linuxplay_start_cfg.json"
LINUXPLAY_MARKER: str = "LinuxPlayHost"


def _client_cert_present(base_dir: Path | str) -> bool:
    """Check if client certificate and key files exist in directory.

    Args:
        base_dir: Directory containing client certificate files

    Returns:
        True if both client_cert.pem and client_key.pem exist
    """
    try:
        base_path = Path(base_dir)
        cert_p = base_path / "client_cert.pem"
        key_p = base_path / "client_key.pem"
        return cert_p.exists() and key_p.exists()
    except (OSError, TypeError, ValueError) as e:
        logging.debug(f"Cert check failed for {base_dir}: {e}")
        return False


def ffmpeg_ok() -> bool:
    """Check if ffmpeg command is available and working.

    Returns:
        True if ffmpeg is installed and responds to version check
    """
    try:
        subprocess.check_output(
            ["ffmpeg", "-hide_banner", "-version"],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=5,  # Prevent hanging on broken FFmpeg installations
        )
        return True
    except FileNotFoundError:
        logging.debug("FFmpeg not found in PATH")
        return False
    except subprocess.TimeoutExpired:
        logging.warning("FFmpeg check timed out (5s) - may be unresponsive")
        return False
    except (subprocess.CalledProcessError, OSError) as e:
        logging.debug("FFmpeg check failed: %s", e)
        return False


# FFmpeg capability caches with timestamps for TTL
_FFENC_CACHE: dict[str, tuple[bool, float]] = {}  # {encoder: (available, timestamp)}
_FFDEV_CACHE: dict[str, tuple[bool, float]] = {}  # {device: (available, timestamp)}
# Cache for full encoder/device lists to avoid repeated subprocess calls.
_FFMPEG_ENCODERS_CACHE: tuple[str, float] | None = None  # (encoder_list_output, timestamp)
_FFMPEG_DEVICES_CACHE: tuple[str, float] | None = None  # (device_list_output, timestamp)


def ffmpeg_has_encoder(name: str) -> bool:
    """Check if ffmpeg has specified encoder (cached with TTL).

    Args:
        name: Encoder name to check (e.g., 'h264_nvenc', 'libx264')

    Returns:
        True if encoder is available in FFmpeg build
    """
    global _FFMPEG_ENCODERS_CACHE
    name = name.lower()
    # Check cache with TTL
    if name in _FFENC_CACHE:
        available, timestamp = _FFENC_CACHE[name]
        if time.time() - timestamp < FFMPEG_CACHE_TTL:
            return available

    # Fetch and cache full encoder list if not cached or expired
    try:
        # Check if cache needs refresh
        if _FFMPEG_ENCODERS_CACHE is None or (time.time() - _FFMPEG_ENCODERS_CACHE[1] >= FFMPEG_CACHE_TTL):
            encoder_list = subprocess.check_output(
                ["ffmpeg", "-hide_banner", "-encoders"],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=5,
            ).lower()
            _FFMPEG_ENCODERS_CACHE = (encoder_list, time.time())
        else:
            # Use cached output
            encoder_list = _FFMPEG_ENCODERS_CACHE[0]

        result = name in encoder_list
        _FFENC_CACHE[name] = (result, time.time())
        return result
    except (subprocess.CalledProcessError, FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        logging.debug(f"Encoder check for '{name}' failed: {e}")
        _FFENC_CACHE[name] = (False, time.time())
        return False


def ffmpeg_has_device(name: str) -> bool:
    """Check if ffmpeg has specified input device (cached with TTL).

    Args:
        name: Device name to check (e.g., 'kmsgrab', 'x11grab')

    Returns:
        True if input device is available in FFmpeg build
    """
    global _FFMPEG_DEVICES_CACHE
    name = name.lower()
    # Check cache with TTL
    if name in _FFDEV_CACHE:
        available, timestamp = _FFDEV_CACHE[name]
        if time.time() - timestamp < FFMPEG_CACHE_TTL:
            return available

    # Fetch and cache full device list if not cached or expired
    try:
        # Check if cache needs refresh
        if _FFMPEG_DEVICES_CACHE is None or (time.time() - _FFMPEG_DEVICES_CACHE[1] >= FFMPEG_CACHE_TTL):
            device_list = subprocess.check_output(
                ["ffmpeg", "-hide_banner", "-devices"],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=5,
            ).lower()
            _FFMPEG_DEVICES_CACHE = (device_list, time.time())
        else:
            # Use cached output
            device_list = _FFMPEG_DEVICES_CACHE[0]

        found = False
        for line in device_list.splitlines():
            s = line.strip()
            if s.startswith(("d ", " d ")):
                parts = s.split()
                if len(parts) >= FFMPEG_OUTPUT_MIN_PARTS and parts[1] == name:
                    found = True
                    break
        _FFDEV_CACHE[name] = (found, time.time())
        return found
    except (subprocess.CalledProcessError, FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        logging.debug(f"Device check for '{name}' failed: {e}")
        _FFDEV_CACHE[name] = (False, time.time())
        return False


def check_encoder_support(codec: str) -> bool:
    """Check if FFmpeg has encoder support for specified codec (h.264 or h.265).

    Args:
        codec: Codec name ('h.264' or 'h.265')

    Returns:
        True if at least one encoder variant is available (hardware or software)
    """
    key = codec.lower().replace(".", "")
    if key == "h264":
        names = ["h264_nvenc", "h264_qsv", "h264_amf", "h264_vaapi", "libx264"]
    elif key == "h265":
        names = ["hevc_nvenc", "hevc_qsv", "hevc_amf", "hevc_vaapi", "libx265"]
    else:
        logging.debug(f"Unknown codec '{codec}' for encoder check")
        return False
    # Check hardware encoders first (faster), then software fallback
    return any(ffmpeg_has_encoder(n) for n in names)


def check_decoder_support(codec: str) -> bool:
    """Check if FFmpeg has decoder support for specified codec (h.264 or h.265).

    Args:
        codec: Codec name ('h.264' or 'h.265')

    Returns:
        True if decoder is available in FFmpeg build
    """
    try:
        output = subprocess.check_output(
            ["ffmpeg", "-hide_banner", "-decoders"],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=5,
        ).lower()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        logging.debug(f"Decoder check for '{codec}' failed: {e}")
        return False
    key = codec.lower().replace(".", "")
    if key == "h264":
        return " h264 " in output or "\nh264\n" in output
    if key == "h265":
        return " hevc " in output or "\nhevc\n" in output
    logging.debug(f"Unknown codec '{codec}' for decoder check")
    return False


def load_cfg() -> dict:
    """Load launcher configuration from JSON file.

    Returns:
        Configuration dict or empty dict if file doesn't exist or is invalid
    """
    try:
        with CFG_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.debug(f"Config file not found: {CFG_PATH}")
        return {}
    except json.JSONDecodeError as e:
        logging.warning(f"Corrupted config file {CFG_PATH}: {e}")
        # Backup corrupted file and start fresh
        try:
            backup_path = CFG_PATH.with_suffix(".json.bak")
            CFG_PATH.rename(backup_path)
            logging.info(f"Backed up corrupted config to {backup_path}")
        except OSError as backup_err:
            logging.debug(f"Failed to backup corrupted config: {backup_err}")
        return {}
    except OSError as e:
        logging.debug(f"Failed to load config: {e}")
        return {}


def save_cfg(data: dict) -> None:
    """Save launcher configuration to JSON file.

    Args:
        data: Configuration dict to persist
    """
    try:
        with CFG_PATH.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except (OSError, TypeError) as e:
        logging.warning(f"Failed to save config: {e}")


ENCODER_NAME_MAP: dict[tuple[str, str], str] = {
    ("h.264", "nvenc"): "h264_nvenc",
    ("h.264", "qsv"): "h264_qsv",
    ("h.264", "amf"): "h264_amf",
    ("h.264", "vaapi"): "h264_vaapi",
    ("h.264", "cpu"): "libx264",
    ("h.265", "nvenc"): "hevc_nvenc",
    ("h.265", "qsv"): "hevc_qsv",
    ("h.265", "amf"): "hevc_amf",
    ("h.265", "vaapi"): "hevc_vaapi",
    ("h.265", "cpu"): "libx265",
}

BACKEND_READABLE: dict[str, str] = {
    "auto": "Auto (detect in host.py)",
    "cpu": "CPU (libx264/libx265/libaom)",
    "nvenc": "NVIDIA NVENC",
    "qsv": "Intel Quick Sync (QSV)",
    "amf": "AMD AMF",
    "vaapi": "Linux VAAPI",
}


def backends_for_codec(codec: str) -> tuple[list[str], list[str]]:
    """Get available encoder backends for codec with human-readable labels.

    Args:
        codec: Codec name ('h.264' or 'h.265')

    Returns:
        Tuple of (backend_keys, display_labels) - both lists in same order
    """
    base = ["auto", "cpu", "nvenc", "qsv", "amf", "vaapi"]
    if IS_WINDOWS:
        if "vaapi" in base:
            base.remove("vaapi")
    elif "amf" in base:
        base.remove("amf")
    pruned = []
    for b in base:
        if b in ("auto", "cpu"):
            pruned.append(b)
            continue
        enc_name = ENCODER_NAME_MAP.get((codec, b))
        if enc_name and ffmpeg_has_encoder(enc_name):
            pruned.append(b)
    items = [f"{b} - {BACKEND_READABLE[b]}" for b in pruned]
    return pruned, items


def _proc_is_running(p: subprocess.Popen | None) -> bool:
    """Check if subprocess is still running.

    Args:
        p: Process object to check

    Returns:
        True if process exists and hasn't terminated
    """
    if p is None:
        return False
    try:
        return p.poll() is None
    except (OSError, ValueError) as e:
        logging.debug(f"Process check failed: {e}")
        return False


def _ffmpeg_running_for_us(marker: str = LINUXPLAY_MARKER) -> bool:
    """Check if FFmpeg is running with our marker using psutil cross-platform API.

    Args:
        marker: Process marker to identify LinuxPlay FFmpeg instances

    Returns:
        True if at least one FFmpeg process with marker is running
    """
    try:
        # Pre-define exceptions to avoid try-except overhead inside loop
        error_types = (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess)
        for proc in psutil.process_iter(["name", "cmdline"]):
            try:
                info = proc.info
                name = info.get("name", "")
                # Quick name check first (cheaper than cmdline parsing)
                if not name or name.lower() not in ("ffmpeg", "ffmpeg.exe"):
                    continue

                cmdline = info.get("cmdline")
                if cmdline and any(marker in arg for arg in cmdline if isinstance(arg, str)):
                    return True  # Early return on first match
            except error_types:
                continue
    except (RuntimeError, KeyError, TypeError) as e:
        logging.debug(f"FFmpeg process check failed: {e}")
    return False


def _warn_ffmpeg(parent: QWidget | None) -> None:
    """Display critical warning dialog when FFmpeg is not available."""
    QMessageBox.critical(
        parent,
        "FFmpeg not found",
        "FFmpeg was not found on PATH.\n\n"
        "Windows: keep ffmpeg\\bin next to the app or install FFmpeg.\n"
        "Linux: install ffmpeg via your package manager.",
    )


class HostTab(QWidget):
    """Host configuration tab for LinuxPlay launcher."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        main_layout = QVBoxLayout()
        wg_group = QGroupBox("Security Status")
        wg_layout = QVBoxLayout()
        self.wgStatus = QLabel("WireGuard: checking…")
        self.wgStatus.setWordWrap(True)
        wg_layout.addWidget(self.wgStatus)
        wg_group.setLayout(wg_layout)
        main_layout.addWidget(wg_group)
        form_group = QGroupBox("Host Configuration")
        form_layout = QFormLayout()
        self.profileCombo = QComboBox()
        self.profileCombo.addItems(["Default", "Lowest Latency", "Balanced", "High Quality"])
        self.profileCombo.currentIndexChanged.connect(self.profileChanged)
        form_layout.addRow("Profile:", self.profileCombo)
        self.encoderCombo = QComboBox()
        self.encoderCombo.addItem("none")
        if check_encoder_support("h.264"):
            self.encoderCombo.addItem("h.264")
        if check_encoder_support("h.265"):
            self.encoderCombo.addItem("h.265")
        self.encoderCombo.currentIndexChanged.connect(self._refresh_backend_choices)
        self.hwencCombo = QComboBox()
        self.framerateCombo = QComboBox()
        self.framerateCombo.addItems(
            ["15", "24", "30", "45", "60", "75", "90", "100", "120", "144", "165", "200", "240", "300", "360"]
        )
        self.bitrateCombo = QComboBox()
        self.bitrateCombo.addItems(
            [
                "0",
                "50k",
                "100k",
                "200k",
                "300k",
                "400k",
                "500k",
                "750k",
                "1M",
                "1.5M",
                "2M",
                "3M",
                "4M",
                "5M",
                "6M",
                "8M",
                "10M",
                "12M",
                "15M",
                "20M",
                "25M",
                "30M",
                "35M",
                "40M",
                "45M",
                "50M",
                "60M",
                "70M",
                "80M",
                "90M",
                "100M",
            ]
        )
        self.audioCombo = QComboBox()
        self.audioCombo.addItems(["enable", "disable"])
        self.audioModeCombo = QComboBox()
        self.audioModeCombo.addItems(["Voice (low-latency)", "Music (quality)"])
        self.adaptiveCheck = QCheckBox("Enable Adaptive Bitrate")
        self.displayCombo = QComboBox()
        self.displayCombo.addItems([":0", ":1", ":2", ":3", ":4", ":5", ":6"])
        self.presetCombo = QComboBox()
        self.presetCombo.addItems(
            [
                "Default",
                "zerolatency",
                "ultra-low-latency",
                "realtime",
                "ultrafast",
                "superfast",
                "veryfast",
                "faster",
                "fast",
                "medium",
                "slow",
                "slower",
                "veryslow",
                "llhp",
                "llhq",
                "hp",
                "hq",
                "p1",
                "p2",
                "p3",
                "p4",
                "p5",
                "p6",
                "p7",
                "lossless",
                "speed",
                "balanced",
                "quality",
            ]
        )

        self.gopCombo = QComboBox()
        self.gopCombo.addItems(["Auto", "1", "2", "3", "4", "5", "8", "10", "15", "20", "30"])

        self.qpCombo = QComboBox()
        self.qpCombo.addItems(
            ["None", "0", "5", "10", "15", "18", "20", "22", "25", "28", "30", "32", "35", "38", "40", "45", "50"]
        )
        self.tuneCombo = QComboBox()
        self.tuneCombo.addItems(
            [
                "None",
                "auto",
                "default",
                "low-latency",
                "ultra-low-latency",
                "zerolatency",
                "high-quality",
                "high-performance",
                "performance",
                "lossless",
                "lossless-highperf",
                "blu-ray",
            ]
        )
        self.pixFmtCombo = QComboBox()
        self.pixFmtCombo.addItems(
            [
                "yuv420p",
                "nv12",
                "yuv422p",
                "yuyv422",
                "uyvy422",
                "yuv444p",
                "rgb0",
                "bgr0",
                "rgba",
                "bgra",
                "p010le",
                "yuv420p10le",
                "yuv422p10le",
                "yuv444p10le",
                "p016le",
                "yuv444p12le",
                "yuv444p16le",
            ]
        )
        self.debugCheck = QCheckBox("Enable Debug")
        self.captureHint = QLabel("")
        if ffmpeg_has_device("kmsgrab"):
            self.captureHint.setText(
                "Capture: kmsgrab available (requires CAP_SYS_ADMIN; cursor not shown). Fallback: x11grab."
            )
        else:
            self.captureHint.setText("Capture: x11grab (kmsgrab not detected).")
        form_layout.addRow("Encoder (codec):", self.encoderCombo)
        form_layout.addRow("Encoder Backend:", self.hwencCombo)
        form_layout.addRow("Framerate:", self.framerateCombo)
        form_layout.addRow("Max Bitrate:", self.bitrateCombo)
        form_layout.addRow("Audio:", self.audioCombo)
        form_layout.addRow("Audio Mode:", self.audioModeCombo)
        form_layout.addRow("Adaptive:", self.adaptiveCheck)
        self.linuxCaptureCombo = QComboBox()
        self.linuxCaptureCombo.addItem("auto", userData="auto")
        self.linuxCaptureCombo.addItem("kmsgrab", userData="kmsgrab")
        self.linuxCaptureCombo.addItem("x11grab", userData="x11grab")
        form_layout.addRow("Linux Capture:", self.linuxCaptureCombo)
        form_layout.addRow("X Display:", self.displayCombo)
        form_layout.addRow("Preset:", self.presetCombo)
        form_layout.addRow("GOP:", self.gopCombo)
        form_layout.addRow("QP:", self.qpCombo)
        form_layout.addRow("Tune:", self.tuneCombo)
        form_layout.addRow("Pixel Format:", self.pixFmtCombo)
        form_layout.addRow("Debug:", self.debugCheck)
        form_layout.addRow("Capture:", self.captureHint)
        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)
        button_layout = QHBoxLayout()
        self.startButton = QPushButton("Start Host")
        self.startButton.clicked.connect(self.start_host)
        button_layout.addWidget(self.startButton)
        button_layout.addStretch(1)
        main_layout.addLayout(button_layout)
        self.statusLabel = QLabel("Ready")
        self.statusLabel.setStyleSheet("color: #bbb")
        main_layout.addWidget(self.statusLabel)
        main_layout.addStretch()
        self.setLayout(main_layout)
        self.host_process = None
        self._exit_watcher_thread = None
        self.pollTimerWG = QTimer(self)
        self.pollTimerWG.timeout.connect(self.refresh_wg_status)
        self.pollTimerWG.start(WG_POLL_INTERVAL_MS)
        self.procTimer = QTimer(self)
        self.procTimer.timeout.connect(self._poll_process_state)
        self.procTimer.start(PROC_POLL_INTERVAL_MS)
        self.profileChanged(0)
        self._refresh_backend_choices()
        self._load_saved()
        self._update_buttons()

    def refresh_wg_status(self) -> None:
        """Update WireGuard status display (Linux only).

        Checks WireGuard installation and tunnel status using native tools.
        Fallback chain: wg command → ip link → kernel module check.
        """
        if not IS_LINUX:
            self.wgStatus.setText("WireGuard: not supported on this OS")
            self.wgStatus.setStyleSheet("color: #bbb")
            return

        # Check WireGuard status using native tools
        active = False
        installed = shutil.which("wg") is not None

        if installed:
            # Primary method: wg command (userspace tools)
            try:
                out = subprocess.check_output(
                    ["wg", "show"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=2,
                )
                active = "interface:" in out.lower()
            except subprocess.TimeoutExpired:
                logging.warning("WireGuard 'wg show' timed out (2s)")
            except (subprocess.CalledProcessError, OSError) as e:
                logging.debug(f"WireGuard 'wg' command failed: {e}")

        # Fallback: ip command (kernel-level check)
        if not active and shutil.which("ip"):
            try:
                out = subprocess.check_output(
                    ["ip", "-d", "link", "show", "type", "wireguard"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=2,
                )
                active = bool(out.strip())
                if active:
                    installed = True
            except subprocess.TimeoutExpired:
                logging.warning("WireGuard 'ip link' check timed out (2s)")
            except (subprocess.CalledProcessError, OSError) as e:
                logging.debug(f"WireGuard 'ip' command failed: {e}")

        # Update UI based on status
        if active:
            self.wgStatus.setText("WireGuard detected and active")
            self.wgStatus.setStyleSheet("color: #7CFC00")  # Lawn green
        elif installed:
            self.wgStatus.setText("WireGuard installed, no active tunnel")
            self.wgStatus.setStyleSheet("color: #f44")  # Red warning
        else:
            self.wgStatus.setText("WireGuard not installed")
            self.wgStatus.setStyleSheet("color: #f44")  # Red warning

    def profileChanged(self, _idx: int) -> None:
        """Update UI controls when profile preset is changed."""
        profile = self.profileCombo.currentText()
        if profile == "Lowest Latency":
            self.encoderCombo.setCurrentText("h.264" if self.encoderCombo.findText("h.264") != -1 else "none")
            self.framerateCombo.setCurrentText("60")
            self.bitrateCombo.setCurrentText("2M")
            self.audioCombo.setCurrentText("disable")
            self.adaptiveCheck.setChecked(False)
            self.displayCombo.setCurrentText(":0")
            self.presetCombo.setCurrentText("llhp" if self.presetCombo.findText("llhp") != -1 else "zerolatency")
            self.gopCombo.setCurrentText("1")
            self.qpCombo.setCurrentText("23")
            self.tuneCombo.setCurrentText("ultra-low-latency")
            self.pixFmtCombo.setCurrentText("yuv420p")
            self._refresh_backend_choices(preselect="auto")
        elif profile == "Balanced":
            self.encoderCombo.setCurrentText("h.264" if self.encoderCombo.findText("h.264") != -1 else "none")
            self.framerateCombo.setCurrentText("45")
            self.bitrateCombo.setCurrentText("4M")
            self.audioCombo.setCurrentText("enable")
            self.adaptiveCheck.setChecked(True)
            self.displayCombo.setCurrentText(":0")
            self.presetCombo.setCurrentText("fast")
            self.gopCombo.setCurrentText("15")
            self.qpCombo.setCurrentText("None")
            self.tuneCombo.setCurrentText("film")
            self.pixFmtCombo.setCurrentText("yuv420p")
            self._refresh_backend_choices(preselect="auto")
        elif profile == "High Quality":
            self.encoderCombo.setCurrentText("h.265" if self.encoderCombo.findText("h.265") != -1 else "h.264")
            self.framerateCombo.setCurrentText("30")
            self.bitrateCombo.setCurrentText("16M")
            self.audioCombo.setCurrentText("enable")
            self.adaptiveCheck.setChecked(False)
            self.displayCombo.setCurrentText(":0")
            self.presetCombo.setCurrentText("slow")
            self.gopCombo.setCurrentText("30")
            self.qpCombo.setCurrentText("None")
            self.tuneCombo.setCurrentText("None")
            self.pixFmtCombo.setCurrentText("yuv444p")
            self._refresh_backend_choices(preselect="auto")
        else:
            self.encoderCombo.setCurrentText(
                "h.265"
                if self.encoderCombo.findText("h.265") != -1
                else ("h.264" if self.encoderCombo.findText("h.264") != -1 else "none")
            )
            self.framerateCombo.setCurrentText("30")
            self.bitrateCombo.setCurrentText("8M")
            self.audioCombo.setCurrentText("enable")
            self.adaptiveCheck.setChecked(False)
            self.displayCombo.setCurrentText(":0")
            self.presetCombo.setCurrentText("Default")
            self.gopCombo.setCurrentText("30")
            self.qpCombo.setCurrentText("None")
            self.tuneCombo.setCurrentText("None")
            self.pixFmtCombo.setCurrentText("yuv420p")
            self._refresh_backend_choices(preselect="auto")

    def _refresh_backend_choices(self, preselect: str | None = None) -> None:
        """Update hardware encoder backend choices based on selected codec."""
        codec = self.encoderCombo.currentText()
        self.hwencCombo.clear()
        if codec == "none":
            for key, label in [("auto", BACKEND_READABLE["auto"]), ("cpu", BACKEND_READABLE["cpu"])]:
                self.hwencCombo.addItem(f"{key} - {label}", key)
            idx = self.hwencCombo.findData("cpu")
            if idx != -1:
                self.hwencCombo.setCurrentIndex(idx)
            return
        keys, pretty = backends_for_codec(codec)
        if "auto" not in keys:
            keys.insert(0, "auto")
            pretty.insert(0, f"auto - {BACKEND_READABLE['auto']}")
        if "cpu" not in keys:
            ins = 1 if "auto" in keys else 0
            keys.insert(ins, "cpu")
            pretty.insert(ins, f"cpu - {BACKEND_READABLE['cpu']}")
        for k, label in zip(keys, pretty, strict=False):
            self.hwencCombo.addItem(label, k)
        want = preselect or "auto"
        idx = self.hwencCombo.findData(want)
        if idx == -1:
            idx = 0
        self.hwencCombo.setCurrentIndex(idx)

    def _poll_process_state(self) -> None:
        """Poll host process state and update internal tracking."""
        if self.host_process is not None and self.host_process.poll() is not None:
            self.host_process = None
        self._update_buttons()

    def _update_buttons(self) -> None:
        """Update button states based on host and FFmpeg process status."""
        running_host = _proc_is_running(self.host_process)
        running_ffmpeg = _ffmpeg_running_for_us()
        can_start = not (running_host or running_ffmpeg)
        self.startButton.setEnabled(can_start)
        if running_host:
            self.startButton.setToolTip("Disabled: Host is running.")
            self.statusLabel.setText("Host running…")
        elif running_ffmpeg:
            self.startButton.setToolTip("Disabled: LinuxPlay FFmpeg still running.")
            self.statusLabel.setText("LinuxPlay ffmpeg still running…")
        else:
            self.startButton.setToolTip("Start the host.")
            self.statusLabel.setText("Ready")

    def _validate_host_start(self) -> tuple[bool, str | None]:
        """Validate host start conditions. Returns (success, encoder) tuple."""
        if not IS_LINUX:
            QMessageBox.critical(
                self,
                "Unsupported OS",
                "Hosting is only supported on Linux. Use the Client tab instead.",
            )
            return False, None

        if not ffmpeg_ok():
            _warn_ffmpeg(self)
            self._update_buttons()
            return False, None

        encoder = self.encoderCombo.currentText()
        if encoder == "none":
            QMessageBox.warning(
                self,
                "Select an encoder",
                "Encoder is set to 'none'. Pick h.264 or h.265 before starting the host.",
            )
            self._update_buttons()
            return False, None

        return True, encoder

    def _get_host_parameters(self) -> dict[str, str | bool]:
        """Extract host parameters from UI controls."""
        return {
            "framerate": self.framerateCombo.currentText(),
            "bitrate": self.bitrateCombo.currentText(),
            "audio": self.audioCombo.currentText(),
            "adaptive": self.adaptiveCheck.isChecked(),
            "display": self.displayCombo.currentText(),
            "preset": "" if self.presetCombo.currentText() in ("Default", "None") else self.presetCombo.currentText(),
            "gop": self.gopCombo.currentText(),
            "qp": "" if self.qpCombo.currentText() in ("None", "", None) else self.qpCombo.currentText(),
            "tune": "" if self.tuneCombo.currentText() in ("None", "", None) else self.tuneCombo.currentText(),
            "pix_fmt": self.pixFmtCombo.currentText(),
            "debug": self.debugCheck.isChecked(),
            "hwenc": self.hwencCombo.currentData() or "auto",
        }

    def _build_host_command(self, encoder: str, params: dict[str, str | bool]) -> list[str]:
        """Build the host command line."""
        cmd = [
            sys.executable,
            str(HERE / "host.py"),
            "--gui",
            "--encoder",
            encoder,
            "--framerate",
            params["framerate"],
            "--bitrate",
            params["bitrate"],
            "--audio",
            params["audio"],
            "--pix_fmt",
            params["pix_fmt"],
            "--hwenc",
            params["hwenc"],
        ]

        if params["adaptive"]:
            cmd.append("--adaptive")
        if params["preset"]:
            cmd.extend(["--preset", params["preset"]])
        if params["qp"]:
            cmd.extend(["--qp", params["qp"]])
        if params["tune"]:
            cmd.extend(["--tune", params["tune"]])
        if params["debug"]:
            cmd.append("--debug")
        cmd.extend(["--display", params["display"]])

        # Handle GOP setting
        try:
            gop_i = int(params["gop"])
        except Exception:
            gop_i = 0
        if gop_i > 0:
            cmd.extend(["--gop", str(gop_i)])
        elif params["preset"].lower() in ("llhp", "zerolatency", "ultra-low-latency", "ull"):
            cmd.extend(["--gop", "1"])

        return cmd

    def _setup_host_environment(self) -> dict[str, str]:
        """Setup environment variables for host process."""
        env = os.environ.copy()
        env["LINUXPLAY_MARKER"] = LINUXPLAY_MARKER
        env["LINUXPLAY_SID"] = env.get("LINUXPLAY_SID") or str(uuid.uuid4())

        audio_mode = self.audioModeCombo.currentText().lower()
        if "music" in audio_mode:
            env["LP_OPUS_APP"] = "audio"
            env["LP_OPUS_FD"] = "20"
        else:
            env["LP_OPUS_APP"] = "voip"
            env["LP_OPUS_FD"] = "10"

        cap_mode = getattr(self, "linuxCaptureCombo", None)
        if cap_mode:
            env["LINUXPLAY_CAPTURE"] = cap_mode.currentData() or "auto"
        else:
            env["LINUXPLAY_CAPTURE"] = "auto"

        kms_dev = getattr(self, "kmsDeviceEdit", None)
        if kms_dev and hasattr(kms_dev, "text"):
            val = kms_dev.text().strip()
            if val:
                env["LINUXPLAY_KMS_DEVICE"] = val

        return env

    def start_host(self) -> None:
        """Start host process with current configuration."""
        valid, encoder = self._validate_host_start()
        if not valid:
            return

        params = self._get_host_parameters()
        cmd = self._build_host_command(encoder, params)
        env = self._setup_host_environment()

        self._save_current()

        try:
            self.host_process = subprocess.Popen(
                cmd,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
        except Exception as e:
            logging.error("Failed to start host: %s", e)
            QMessageBox.critical(self, "Start Host Failed", str(e))
            self.host_process = None
            self._update_buttons()
            return

        def _watch() -> None:
            """Watch host process and cleanup on exit (prevents zombie processes)."""
            try:
                # Wait with timeout to prevent indefinite blocking
                exit_code = self.host_process.wait(timeout=300)  # 5 min max
                if exit_code != 0:
                    logging.warning(f"Host process exited with code {exit_code}")
            except subprocess.TimeoutExpired:
                logging.error("Host process did not exit within 5 minutes")
                with contextlib.suppress(OSError):
                    self.host_process.kill()
            except Exception as e:
                logging.debug(f"Host process watch failed: {e}")

            def done() -> None:
                self.host_process = None
                self._update_buttons()

            QTimer.singleShot(0, done)

        self._exit_watcher_thread = threading.Thread(target=_watch, name="HostExitWatcher", daemon=True)
        self._exit_watcher_thread.start()
        self._update_buttons()

    def _save_current(self) -> None:
        """Save current host configuration to disk."""
        data = load_cfg()
        data["host"] = {
            "profile": self.profileCombo.currentText(),
            "encoder": self.encoderCombo.currentText(),
            "hwenc": self.hwencCombo.currentData() or "auto",
            "framerate": self.framerateCombo.currentText(),
            "bitrate": self.bitrateCombo.currentText(),
            "audio": self.audioCombo.currentText(),
            "audio_mode": self.audioModeCombo.currentText(),
            "adaptive": self.adaptiveCheck.isChecked(),
            "display": self.displayCombo.currentText(),
            "preset": self.presetCombo.currentText(),
            "gop": self.gopCombo.currentText(),
            "qp": self.qpCombo.currentText(),
            "tune": self.tuneCombo.currentText(),
            "pix_fmt": self.pixFmtCombo.currentText(),
            "capture": (self.linuxCaptureCombo.currentData() if hasattr(self, "linuxCaptureCombo") else "auto"),
        }
        save_cfg(data)

    def _load_saved(self) -> None:
        """Load saved host configuration from disk."""
        cfg = load_cfg().get("host", {})
        if not cfg:
            return

        def set_combo(combo: QComboBox, val: str | None) -> None:
            if not val:
                return
            idx = combo.findText(val)
            if idx != -1:
                combo.setCurrentIndex(idx)

        set_combo(self.profileCombo, cfg.get("profile"))
        set_combo(self.encoderCombo, cfg.get("encoder"))
        self._refresh_backend_choices()
        saved_hwenc = cfg.get("hwenc", "auto")
        idx = self.hwencCombo.findData(saved_hwenc)
        if idx != -1:
            self.hwencCombo.setCurrentIndex(idx)
        set_combo(self.framerateCombo, cfg.get("framerate"))
        set_combo(self.bitrateCombo, cfg.get("bitrate"))
        set_combo(self.audioCombo, cfg.get("audio"))
        set_combo(self.audioModeCombo, cfg.get("audio_mode", "Voice (low-latency)"))
        self.adaptiveCheck.setChecked(bool(cfg.get("adaptive", False)))
        set_combo(self.displayCombo, cfg.get("display"))
        set_combo(self.presetCombo, cfg.get("preset"))
        set_combo(self.gopCombo, cfg.get("gop"))
        set_combo(self.qpCombo, cfg.get("qp"))
        set_combo(self.tuneCombo, cfg.get("tune"))
        set_combo(self.pixFmtCombo, cfg.get("pix_fmt"))
        if IS_LINUX and hasattr(self, "linuxCaptureCombo"):
            cap_val = cfg.get("capture", "auto")
            for i in range(self.linuxCaptureCombo.count()):
                if self.linuxCaptureCombo.itemData(i) == cap_val:
                    self.linuxCaptureCombo.setCurrentIndex(i)
                    break


class ClientTab(QWidget):
    """Client configuration tab for LinuxPlay launcher."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        main_layout = QVBoxLayout()

        form_group = QGroupBox("Client Configuration")
        form_layout = QFormLayout()

        self.decoderCombo = QComboBox()
        self.decoderCombo.addItem("none")
        if check_decoder_support("h.264"):
            self.decoderCombo.addItem("h.264")
        if check_decoder_support("h.265"):
            self.decoderCombo.addItem("h.265")

        self.hwaccelCombo = QComboBox()
        self.hwaccelCombo.addItems(["auto", "cpu", "cuda", "qsv", "d3d11va", "dxva2", "vaapi"])
        if IS_WINDOWS:
            idx = self.hwaccelCombo.findText("vaapi")
            if idx != -1:
                self.hwaccelCombo.removeItem(idx)
        else:
            for item in ["d3d11va", "dxva2"]:
                idx = self.hwaccelCombo.findText(item)
                if idx != -1:
                    self.hwaccelCombo.removeItem(idx)

        self.hostIPEdit = QComboBox()
        self.hostIPEdit.setEditable(True)
        self.hostIPEdit.setToolTip("Host IP (LAN) or WireGuard tunnel IP (e.g., 10.13.13.1)")

        if IS_LINUX and Path(WG_INFO_PATH).exists():
            try:
                with Path(WG_INFO_PATH).open() as f:
                    info = json.load(f)
                t_ip = info.get("host_tunnel_ip", "")
                if t_ip:
                    self.hostIPEdit.addItem(t_ip)
            except Exception as e:
                # WireGuard config file parse failed - may be corrupted or invalid JSON
                logging.debug(f"Failed to load WireGuard config from {WG_INFO_PATH}: {e}")

        last = load_cfg().get("client", {})
        for ip in last.get("recent_ips", []):
            self.hostIPEdit.addItem(ip)

        self.audioCombo = QComboBox()
        self.audioCombo.addItems(["enable", "disable"])
        self.audioModeCombo = QComboBox()
        self.audioModeCombo.addItems(["Voice (low-latency)", "Music (quality)"])

        self.monitorField = QLineEdit("0")
        self.netCombo = QComboBox()
        self.netCombo.addItems(["auto", "lan", "wifi"])
        self.ultraCheck = QCheckBox("Ultra (LAN only)")
        self.debugCheck = QCheckBox("Enable Debug")

        self.gamepadCombo = QComboBox()
        self.gamepadCombo.addItems(["enable", "disable"])
        self.gamepadDevEdit = QLineEdit()
        self.gamepadDevEdit.setPlaceholderText("/dev/input/eventX (optional)")

        self._load_saved_client_extras()

        form_layout.addRow("Decoder:", self.decoderCombo)
        form_layout.addRow("HW accel:", self.hwaccelCombo)
        form_layout.addRow("Host IP:", self.hostIPEdit)
        form_layout.addRow("Audio:", self.audioCombo)
        form_layout.addRow("Audio Mode:", self.audioModeCombo)
        form_layout.addRow("Monitor (index or 'all'):", self.monitorField)
        form_layout.addRow("Network Mode:", self.netCombo)
        form_layout.addRow("Ultra Mode:", self.ultraCheck)
        form_layout.addRow("Debug:", self.debugCheck)
        form_layout.addRow("Gamepad:", self.gamepadCombo)
        form_layout.addRow("Gamepad Device:", self.gamepadDevEdit)

        self.pinEdit = QLineEdit()
        self.pinEdit.setPlaceholderText("Enter 6-digit host PIN")
        form_layout.addRow("Host PIN:", self.pinEdit)

        _here = HERE
        self._cert_auth = _client_cert_present(_here)
        self._apply_cert_ui_state(self._cert_auth)

        self._cert_refresh_timer = QTimer(self)
        self._cert_refresh_timer.timeout.connect(self._refresh_cert_detection)
        self._cert_refresh_timer.start(CERT_POLL_INTERVAL_MS)

        form_group.setLayout(form_layout)
        button_layout = QHBoxLayout()
        self.startButton = QPushButton("Start Client")
        self.startButton.clicked.connect(self.start_client)
        button_layout.addWidget(self.startButton)

        main_layout.addWidget(form_group)
        main_layout.addLayout(button_layout)
        main_layout.addStretch()
        self.setLayout(main_layout)

    def _apply_cert_ui_state(self, has_cert: bool) -> None:
        """Update PIN field UI based on certificate detection."""
        if has_cert:
            self.pinEdit.clear()
            self.pinEdit.setEnabled(False)
            self.pinEdit.setPlaceholderText("Client certificate detected — PIN not required")
            self.pinEdit.setToolTip("Using certificate authentication (client_cert.pem + client_key.pem).")
        else:
            self.pinEdit.setEnabled(True)
            self.pinEdit.setPlaceholderText("Enter 6-digit host PIN")
            self.pinEdit.setToolTip("Enter PIN shown on host display.")

    def _refresh_cert_detection(self) -> None:
        """Periodically check for certificate changes and update UI.

        Detects when certificates are added/removed and updates PIN field accordingly.
        """
        try:
            now_has = _client_cert_present(HERE)
        except Exception as e:
            logging.debug("Certificate detection failed: %s", e)
            now_has = False
        if now_has != getattr(self, "_cert_auth", False):
            self._cert_auth = now_has
            self._apply_cert_ui_state(now_has)
            state = "detected" if now_has else "removed"
            logging.info("[AUTO] Client certificate %s, UI updated.", state)

    def _load_saved_client_extras(self) -> None:
        """Load saved client configuration from disk."""
        cfg = load_cfg().get("client", {})

        def set_combo(combo: QComboBox, val: str | None) -> None:
            if not val:
                return
            idx = combo.findText(val)
            if idx != -1:
                combo.setCurrentIndex(idx)

        set_combo(self.decoderCombo, cfg.get("decoder"))
        set_combo(self.hwaccelCombo, cfg.get("hwaccel"))
        set_combo(self.audioCombo, cfg.get("audio"))
        self.monitorField.setText(cfg.get("monitor", "0"))
        set_combo(self.netCombo, cfg.get("net", "auto"))
        self.ultraCheck.setChecked(bool(cfg.get("ultra", False)))
        self.debugCheck.setChecked(bool(cfg.get("debug", False)))
        set_combo(self.gamepadCombo, cfg.get("gamepad", "enable"))
        self.gamepadDevEdit.setText(cfg.get("gamepad_dev", ""))

    def start_client(self) -> None:
        """Start client process with current configuration.

        Validates configuration and launches client.py with appropriate flags.
        """
        if not ffmpeg_ok():
            _warn_ffmpeg(self)
            return

        decoder = self.decoderCombo.currentText()
        host_ip = self.hostIPEdit.currentText().strip()
        audio = self.audioCombo.currentText()
        monitor = self.monitorField.text().strip() or "0"
        debug = self.debugCheck.isChecked()
        hwaccel = self.hwaccelCombo.currentText()
        net = self.netCombo.currentText()
        ultra = self.ultraCheck.isChecked()
        gamepad = self.gamepadCombo.currentText()
        gamepad_dev = self.gamepadDevEdit.text().strip() or None
        pin = self.pinEdit.text().strip()
        if getattr(self, "_cert_auth", False):
            pin = ""  # Certificate auth bypasses PIN

        if not host_ip:
            QMessageBox.warning(
                self,
                "Missing Host IP",
                "Please enter the host IP address or WireGuard tunnel IP.",
            )
            self.hostIPEdit.setFocus()
            return

        # Basic IP validation (IPv4 format check)
        if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", host_ip):
            QMessageBox.warning(
                self,
                "Invalid Host IP",
                f"'{host_ip}' does not appear to be a valid IPv4 address.\n\n"
                "Expected format: xxx.xxx.xxx.xxx (e.g., 192.168.1.10)",
            )
            self.hostIPEdit.setFocus()
            return

        cfg = load_cfg()
        client_cfg = cfg.get("client", {})
        rec = client_cfg.get("recent_ips", [])
        if host_ip and host_ip not in rec:
            rec = [host_ip, *rec[:4]]

        client_cfg.update(
            {
                "recent_ips": rec,
                "decoder": decoder,
                "hwaccel": hwaccel,
                "audio": audio,
                "monitor": monitor,
                "debug": bool(debug),
                "net": net,
                "ultra": bool(ultra),
                "gamepad": gamepad,
                "gamepad_dev": gamepad_dev,
                "pin": pin,
            }
        )
        cfg["client"] = client_cfg
        save_cfg(cfg)

        cmd = [
            sys.executable,
            str(HERE / "client.py"),
            "--decoder",
            decoder,
            "--host_ip",
            host_ip,
            "--audio",
            audio,
            "--monitor",
            monitor,
            "--hwaccel",
            hwaccel,
            "--net",
            net,
            "--gamepad",
            gamepad,
        ]
        if gamepad_dev:
            cmd.extend(["--gamepad_dev", gamepad_dev])
        if ultra:
            cmd.append("--ultra")
        if debug:
            cmd.append("--debug")
        if pin:
            cmd.extend(["--pin", pin])

        try:
            subprocess.Popen(
                cmd,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logging.info(f"Client started successfully with host {host_ip}")
        except (OSError, ValueError) as e:
            logging.error(f"Failed to start client: {e}")
            QMessageBox.critical(self, "Start Client Failed", str(e))


class HelpTab(QWidget):
    """Help and documentation tab for LinuxPlay launcher."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout()

        help_text = (
            "<h1>LinuxPlay Help</h1>"
            "<p><b>LinuxPlay</b> provides ultra-low-latency desktop streaming using FFmpeg over UDP, "
            "with TCP used for session handshakes and UDP channels for input, clipboard, and optional audio.</p>"
            "<h2>Security</h2>"
            "<p>For internet (WAN) streaming, it is strongly recommended to tunnel all traffic through "
            "<b>WireGuard</b> on the host system. Clients should connect using the tunnel's internal IP. "
            "On trusted local networks (LAN), this step can be safely skipped.</p>"
            "<h2>Capture Backends</h2>"
            "<ul>"
            "<li><b>kmsgrab</b> (KMS/DRM): Provides the lowest capture latency but requires elevated privileges. "
            "Grant permission with:<br><code>sudo setcap cap_sys_admin+ep $(which ffmpeg)</code>."
            "Note that the hardware cursor is not drawn by kmsgrab.</li>"
            "<li><b>x11grab</b>: Compatible with most X11 sessions; easier to set up but slightly higher latency.</li>"
            "</ul>"
            "<h2>Platform Support</h2>"
            "<p>The <b>Host</b> is supported on Linux only. Clients are available for Linux and Windows. "
            "macOS clients may function via compatibility layers but are not officially supported.</p>"
            "<h2>Performance Tips</h2>"
            "<ul>"
            "<li>Enable <b>Ultra Mode</b> for LAN use only; it disables internal buffering for minimum delay.</li>"
            "<li>Recommended baseline for smooth playback: "
            "<code>H.264</code> codec, preset <code>llhq</code> or <code>ultrafast</code>, GOP <code>10</code>, "
            "audio disabled (optional), and moderate bitrates (e.g. 8-12&nbsp;Mbps for 1080p).</li>"
            "<li>Select your encoder backend explicitly — NVENC, QSV, AMF, VAAPI, or CPU — "
            "to ensure consistent performance across sessions.</li>"
            "</ul>"
            "<h2>General Notes</h2>"
            "<ul>"
            "<li>Multi-monitor streaming is supported. "
            "Choose a specific monitor index or <b>all</b> to capture every display.</li>"
            "<li>The host window includes a Stop button; closing it also terminates the active session safely.</li>"
            "<li>Clipboard sync and drag-and-drop are available in compatible clients.</li>"
            "</ul>"
        )

        help_view = QTextEdit()
        help_view.setReadOnly(True)
        help_view.setHtml(help_text)
        layout.addWidget(help_view)
        self.setLayout(layout)


class StartWindow(QWidget):
    """Main launcher window for LinuxPlay with tabbed interface."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("LinuxPlay")
        self.tabs = QTabWidget()
        self.clientTab = ClientTab()
        self.helpTab = HelpTab()
        if IS_LINUX:
            self.hostTab = HostTab()
            self.tabs.addTab(self.hostTab, "Host")
        self.tabs.addTab(self.clientTab, "Client")
        self.tabs.addTab(self.helpTab, "Help")
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

    def closeEvent(self, event) -> None:
        """Handle window close event."""
        event.accept()


def main() -> None:
    """Main entry point for LinuxPlay launcher GUI."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    args, _ = parser.parse_known_args()
    logging.basicConfig(
        level=(logging.DEBUG if args.debug else logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = app.palette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.Highlight, QColor(38, 128, 218))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    w = StartWindow()
    w.resize(860, 620)
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
