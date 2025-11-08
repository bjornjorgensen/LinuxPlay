#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import hashlib
import importlib.util
import json
import logging
import mmap
import os
import platform as py_platform
import re
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from queue import Queue
from tkinter import messagebox, simpledialog
from typing import TYPE_CHECKING

import av
import numpy as np
import psutil
from OpenGL.GL import (
    GL_CLAMP_TO_EDGE,
    GL_COLOR_BUFFER_BIT,
    GL_DEPTH_TEST,
    GL_DITHER,
    GL_LINEAR,
    GL_PIXEL_UNPACK_BUFFER,
    GL_QUADS,
    GL_RGB,
    GL_STREAM_DRAW,
    GL_TEXTURE_2D,
    GL_TEXTURE_MAG_FILTER,
    GL_TEXTURE_MIN_FILTER,
    GL_TEXTURE_WRAP_S,
    GL_TEXTURE_WRAP_T,
    GL_UNPACK_ALIGNMENT,
    GL_UNSIGNED_BYTE,
    GL_WRITE_ONLY,
    glBegin,
    glBindBuffer,
    glBindTexture,
    glBufferData,
    glClear,
    glClearColor,
    glDeleteBuffers,
    glDisable,
    glEnable,
    glEnd,
    glFlush,
    glGenBuffers,
    glGenTextures,
    glMapBuffer,
    glPixelStorei,
    glTexCoord2f,
    glTexImage2D,
    glTexParameteri,
    glTexSubImage2D,
    glUnmapBuffer,
    glVertex2f,
)


if TYPE_CHECKING:
    from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt5.QtGui import QSurfaceFormat
    from PyQt5.QtWidgets import QApplication, QMainWindow, QOpenGLWidget
else:
    from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt5.QtGui import QSurfaceFormat
    from PyQt5.QtWidgets import QApplication, QMainWindow, QOpenGLWidget


try:
    from evdev import InputDevice, ecodes, list_devices

    HAVE_EVDEV = True
except ImportError:
    HAVE_EVDEV = False

# Note: pynvml module provided by nvidia-ml-py package (official NVIDIA library)
# nvidia-ml-py is the maintained successor to deprecated pynvml package
try:
    import pynvml

    HAVE_PYNVML = True
except ImportError:
    HAVE_PYNVML = False


# Tkinter dialog helpers
def _show_error(title: str, message: str) -> None:
    """Show error dialog (thread-safe)."""
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message, parent=root)
        root.destroy()
    except Exception as e:
        logging.error(f"{title}: {message} (dialog error: {e})")


def _show_info(title: str, message: str) -> None:
    """Show info dialog (thread-safe)."""
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(title, message, parent=root)
        root.destroy()
    except Exception as e:
        logging.info(f"{title}: {message} (dialog error: {e})")


def _ask_pin(title: str = "Enter Host PIN", prompt: str = "6-digit PIN (rotates every 30s):") -> str:
    """Show PIN input dialog."""
    try:
        root = tk.Tk()
        root.withdraw()
        result = simpledialog.askstring(title, prompt, show="*", parent=root)
        root.destroy()
        return (result or "").strip()
    except Exception:
        # Tkinter dialog failure (missing display, X11 error) - error already logged
        logging.error("PIN dialog failed")
        return ""


DEFAULT_UDP_PORT = 5000
CONTROL_PORT = 7000
TCP_HANDSHAKE_PORT = 7001
UDP_CLIPBOARD_PORT = 7002
UDP_FILE_PORT = 7003
UDP_HEARTBEAT_PORT = 7004
UDP_GAMEPAD_PORT = 7005
UDP_AUDIO_PORT = 6001

# Authentication constants
PIN_LENGTH = 6  # PIN must be exactly 6 digits
PROTOCOL_MIN_PARTS = 2  # Minimum parts for protocol messages
PROTOCOL_WITH_DATA = 3  # Protocol messages with additional data (e.g., "OK:<encoder>:<monitors>")
HEARTBEAT_TIMEOUT_SECS = 10  # Consider connection lost after 10s without heartbeat

# UDP socket buffer sizes (bytes)
UDP_SEND_BUFFER_SIZE = 2_097_152  # 2MB send buffer for control
UDP_RECV_BUFFER_SIZE = 524_288  # 512KB receive buffer
UDP_BUSY_POLL_USEC = 50  # SO_BUSY_POLL: 50µs for ultra-low latency (requires root or CAP_NET_ADMIN)

DEFAULT_RESOLUTION = "1920x1080"

IS_WINDOWS = py_platform.system() == "Windows"
IS_LINUX = py_platform.system() == "Linux"

CLIPBOARD_INBOX = Queue()


class AudioProcessManager:
    """Manages the audio process to avoid global state."""

    proc = None


audio_proc_manager = AudioProcessManager()
CLIENT_STATE = {"connected": False, "last_heartbeat": 0.0, "net_mode": "lan", "reconnecting": False}

# Network mode detection cache (avoid repeated subprocess calls)
_NETWORK_MODE_CACHE: dict[str, tuple[str, float]] = {}  # {host_ip: (mode, timestamp)}
NETWORK_MODE_CACHE_TTL: int = 300  # Cache for 5 minutes (networks don't change often)


def _clear_network_mode_cache() -> None:
    """Clear network mode cache (primarily for testing)."""
    _NETWORK_MODE_CACHE.clear()


try:
    HERE = Path(__file__).resolve().parent
    ffbin = HERE / "ffmpeg" / "bin"

    if os.name == "nt":
        ffmpeg_exe = ffbin / "ffmpeg.exe"
        if ffmpeg_exe.exists():
            os.environ["PATH"] = str(ffbin) + os.pathsep + os.environ.get("PATH", "")
    else:
        ffmpeg_bin = ffbin / "ffmpeg"
        if ffmpeg_bin.exists():
            os.environ["PATH"] = str(ffbin) + os.pathsep + os.environ.get("PATH", "")
except Exception as e:
    logging.debug(f"FFmpeg path init failed: {e}")


def _probe_hardware_capabilities() -> None:
    try:
        vk_spec = importlib.util.find_spec("vulkan")
        vk_available = vk_spec is not None
    except Exception:
        # Vulkan module not available - graceful degradation to non-Vulkan mode
        vk_available = False

    gbm_exists = any(Path(p).exists() for p in ("/dev/dri/renderD128", "/dev/dri/renderD129"))
    kms_exists = any(Path(p).exists() for p in ("/dev/dri/card0", "/dev/dri/card1"))
    logging.info(f"Hardware paths: GBM={gbm_exists}, KMS={kms_exists}, Vulkan={vk_available}")


_probe_hardware_capabilities()


def ffmpeg_hwaccels() -> set[str]:
    try:
        out = subprocess.check_output(
            ["ffmpeg", "-hide_banner", "-hwaccels"], stderr=subprocess.STDOUT, universal_newlines=True
        )
        accels = set()
        for line in out.splitlines():
            name = line.strip()
            if name and not name.lower().startswith("hardware acceleration methods"):
                accels.add(name)
        return accels
    except Exception:
        # FFmpeg not available or command failed - return empty set for software fallback
        return set()


def choose_auto_hwaccel() -> str:
    accels = ffmpeg_hwaccels()
    if IS_WINDOWS:
        for cand in ("d3d11va", "cuda", "dxva2", "qsv"):
            if cand in accels:
                return cand
        return "cpu"
    for cand in ("vaapi", "qsv", "cuda"):
        if cand in accels:
            return cand
    return "cpu"


def _best_ts_pkt_size(mtu_guess: int, ipv6: bool = False) -> int:
    """Calculate optimal MPEG-TS packet size for UDP transport.

    MPEG-TS uses 188-byte packets. We fit as many as possible into MTU
    while leaving room for UDP/IP headers (28 bytes IPv4, 48 bytes IPv6).

    Args:
        mtu_guess: Estimated MTU (default 1500 if invalid)
        ipv6: True if using IPv6 (larger headers)

    Returns:
        Optimal packet size (multiple of 188 bytes, minimum 188)

    Example:
        >>> _best_ts_pkt_size(1500, False)  # Standard Ethernet
        1316  # 7 TS packets (7 * 188 = 1316) + 28 bytes headers = 1344 < 1500
    """
    if mtu_guess <= 0:
        mtu_guess = 1500
    overhead = 48 if ipv6 else 28
    max_payload = max(512, mtu_guess - overhead)
    return max(188, (max_payload // 188) * 188)


def _detect_linux_network_mode(host_ip: str) -> str:
    """Detect network mode on Linux by inspecting routing interface.

    Performance note: Uses subprocess, cache result if called frequently.
    """
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", host_ip],
            universal_newlines=True,
            stderr=subprocess.STDOUT,
            timeout=2,  # Prevent hanging on network issues
        )
        m = re.search(r"\bdev\s+(\S+)", out)
        iface = m.group(1) if m else ""
        if iface and Path(f"/sys/class/net/{iface}/wireless").exists():
            return "wifi"
        if iface.startswith("wl"):
            return "wifi"
        return "lan"
    except (subprocess.SubprocessError, subprocess.TimeoutExpired, Exception) as e:
        logging.debug(f"Network detection failed: {e}")
        return "lan"


def _detect_windows_network_mode() -> str:
    """Detect network mode on Windows by checking interface names."""
    try:
        # Get network interfaces and check for wireless adapters
        stats = psutil.net_if_stats()

        # Find active interfaces and check for common wireless patterns
        for iface_name in stats:
            if not stats[iface_name].isup:
                continue
            # Common patterns for wireless interfaces on Windows
            iface_lower = iface_name.lower()
            if any(pattern in iface_lower for pattern in ["wi-fi", "wireless", "wlan", "802.11"]):
                return "wifi"
        return "lan"
    except Exception as e:
        # psutil network detection failed - assume LAN for performance
        logging.debug(f"Windows network detection failed: {e}")
        return "lan"


def detect_network_mode(host_ip: str) -> str:
    """Detect if connection is over LAN or WiFi with caching.

    Performance optimization: Caches results per host IP to avoid repeated
    subprocess calls. Cache TTL is 5 minutes (networks rarely change mid-session).

    Args:
        host_ip: Target host IP for route inspection (Linux only)

    Returns:
        "lan" or "wifi" (defaults to "lan" on detection failure)
    """
    # Check cache first (avoids expensive subprocess calls)
    if host_ip in _NETWORK_MODE_CACHE:
        mode, timestamp = _NETWORK_MODE_CACHE[host_ip]
        if time.time() - timestamp < NETWORK_MODE_CACHE_TTL:
            return mode

    # Cache miss or expired - perform detection
    if IS_LINUX:
        mode = _detect_linux_network_mode(host_ip)
    elif IS_WINDOWS:
        mode = _detect_windows_network_mode()
    else:
        mode = "lan"

    # Update cache
    _NETWORK_MODE_CACHE[host_ip] = (mode, time.time())
    return mode


def _read_pem_cert_fingerprint(pem_path: str) -> str:
    """Extract SHA256 fingerprint from PEM certificate.

    Args:
        pem_path: Path to PEM certificate file

    Returns:
        Uppercase hex fingerprint, or empty string on error
    """
    try:
        data = Path(pem_path).read_text(encoding="utf-8")
        m = re.search(r"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END CERTIFICATE-----", data, re.S)
        if not m:
            return ""
        der = base64.b64decode("".join(m.group(1).split()))
        return hashlib.sha256(der).hexdigest().upper()
    except Exception as e:
        # Certificate file missing or malformed - return empty string for auth fallback
        logging.debug(f"Certificate fingerprint extraction failed: {e}")
        return ""


def _ensure_client_keypair(key_path: Path) -> bool:
    """
    Generate client RSA keypair if not exists.

    Returns:
        True if newly generated, False if already exists.

    Security:
        Private key stays on client - NEVER transmitted.
        File permissions set to 0600 (owner read/write only).
    """
    if key_path.exists():
        # Verify permissions on existing key
        try:
            if key_path.stat().st_mode & 0o777 != 0o600:
                logging.warning("Client key has insecure permissions, fixing...")
                key_path.chmod(0o600)
        except Exception as e:
            logging.debug(f"Failed to check key permissions: {e}")
        logging.debug("Client keypair already exists at %s", key_path)
        return False

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        logging.info("Generating client RSA keypair (4096-bit)...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        # Ensure directory exists with secure permissions
        key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Write private key with secure permissions
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_pem)
        key_path.chmod(0o600)  # Owner read/write only

        logging.info("Client keypair generated and saved to %s (permissions: 0600)", key_path)
        return True
    except Exception as e:
        logging.error("Failed to generate client keypair: %s", e)
        return False


def _generate_csr(private_key_path: Path, client_id: str) -> bytes:
    """
    Generate Certificate Signing Request.
    Returns CSR in PEM format (bytes).
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID

        # Load private key
        key_pem = private_key_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_pem, password=None)

        # Create subject name
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, client_id),
            ]
        )

        # Build and sign CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

        return csr.public_bytes(serialization.Encoding.PEM)
    except Exception as e:
        logging.error("Failed to generate CSR: %s", e)
        return b""


def _validate_host_ca_fingerprint(ca_cert_pem: bytes, host_ip: str) -> bool:
    """
    Validate host CA fingerprint using Trust On First Use (TOFU).
    On first connection, pins the fingerprint.
    On subsequent connections, verifies it matches (detects MITM).
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        fingerprint = ca_cert.fingerprint(hashes.SHA256()).hex()

        pinned_file = Path.home() / ".linuxplay" / "pinned_hosts.json"

        # Load existing pins
        pinned = {}
        if pinned_file.exists():
            try:
                with pinned_file.open() as f:
                    pinned = json.load(f)
            except Exception as e:
                logging.warning("Failed to load pinned hosts: %s", e)

        # Check if host is already pinned
        if host_ip in pinned:
            if pinned[host_ip] != fingerprint:
                logging.error(
                    "Host CA fingerprint mismatch for %s! Expected %s, got %s. Possible MITM attack.",
                    host_ip,
                    pinned[host_ip][:16],
                    fingerprint[:16],
                )
                return False
            logging.info("Host CA fingerprint verified for %s (pinned)", host_ip)
            return True

        # Pin on first use
        pinned[host_ip] = fingerprint
        pinned_file.parent.mkdir(parents=True, exist_ok=True)
        with pinned_file.open("w") as f:
            json.dump(pinned, f, indent=2)

        logging.info("Host CA fingerprint pinned for %s: %s...", host_ip, fingerprint[:16])
        return True
    except Exception as e:
        logging.error("Failed to validate host CA fingerprint: %s", e)
        return False


def _sign_challenge(private_key_path: Path, challenge: bytes) -> bytes:
    """
    Sign challenge with client's private key.
    Returns signature bytes.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        # Load private key
        key_pem = private_key_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_pem, password=None)

        # Sign challenge
        return private_key.sign(
            challenge,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    except Exception as e:
        logging.error("Failed to sign challenge: %s", e)
        return b""


def _get_client_paths() -> tuple[Path, Path, Path, Path]:
    """Get paths for client certificates and keys.

    Returns:
        Tuple of (client_dir, cert_path, key_path, ca_path)
    """
    try:
        client_dir = Path.home() / ".linuxplay"
    except Exception:
        # Path.home() failure (rare) - fallback to same path (will fail downstream with clear error)
        client_dir = Path.home() / ".linuxplay"

    return (
        client_dir,
        client_dir / "client_cert.pem",
        client_dir / "client_key.pem",
        client_dir / "host_ca.pem",
    )


def _handle_challenge_response(
    sock: socket.socket, cert_path: Path, key_path: Path, ca_path: Path, host_ip: str
) -> tuple[bool | None, tuple[str, str] | str | None]:
    """Handle challenge-response authentication with existing certificate.

    Returns: (success: bool, result: tuple | None)
    """
    logging.info("[AUTH] Attempting secure challenge-response authentication")
    try:
        # Validate host CA fingerprint (TOFU)
        ca_pem = ca_path.read_bytes()
        if not _validate_host_ca_fingerprint(ca_pem, host_ip):
            logging.error("[AUTH] Host CA fingerprint validation failed - possible MITM!")
            _show_error(
                "Security Error",
                f"Host CA fingerprint mismatch for {host_ip}!\nPossible Man-in-the-Middle attack.",
            )
            return (False, None)

        # Try new challenge-response protocol
        fp_hex = _read_pem_cert_fingerprint(cert_path)
        sock.sendall(f"AUTH CERT:{fp_hex}".encode())
        resp = sock.recv(2048).decode("utf-8", errors="replace").strip()

        # Handle non-challenge responses
        if resp.startswith("FAIL:DEPRECATED"):
            logging.warning("[AUTH] Host requires protocol upgrade - falling back to legacy")
            return (None, "deprecated")
        if resp.startswith("BUSY"):
            logging.error("Host is already in a session")
            _show_error("Host Busy", "The host is already connected to another client.")
            return (False, None)
        if not resp.startswith("CHALLENGE:"):
            return (None, "failed")

        # Process challenge
        challenge_b64 = resp[10:]
        challenge = base64.b64decode(challenge_b64)

        # Sign challenge
        signature = _sign_challenge(key_path, challenge)
        if not signature:
            raise Exception("Failed to sign challenge")

        # Send signature
        sig_b64 = base64.b64encode(signature).decode()
        sock.sendall(f"SIGNATURE:{sig_b64}".encode())

        # Receive result
        final_resp = sock.recv(2048).decode("utf-8", errors="replace").strip()

        if final_resp.startswith("OK:"):
            parts = final_resp.split(":", PROTOCOL_MIN_PARTS)
            host_encoder = parts[1].strip()
            monitor_info = parts[2].strip() if len(parts) > PROTOCOL_MIN_PARTS else DEFAULT_RESOLUTION
            CLIENT_STATE["connected"] = True
            CLIENT_STATE["last_heartbeat"] = time.time()
            logging.info("[AUTH] ✓ Authenticated via challenge-response (SECURE)")
            return (True, (host_encoder, monitor_info))

        if final_resp.startswith("FAIL:DEPRECATED"):
            logging.warning("[AUTH] Host requires upgrade to new protocol")
            return (None, "deprecated")

        logging.warning("[AUTH] Challenge-response failed: %s", final_resp)

    except Exception as e:
        logging.debug("[AUTH] Secure auth failed (%s), trying legacy", e)
        return (None, "error")

    return (None, "failed")


def _handle_csr_submission(  # noqa: PLR0913
    sock: socket.socket, key_path: Path, cert_path: Path, ca_path: Path, host_ip: str, pin: str
) -> tuple[bool | None, tuple[str, str] | str | None]:
    """Handle CSR submission for first-time authentication.

    Returns: (success: bool, result: tuple | None)
    """
    logging.info("[AUTH] No certificates found - using CSR flow (first-time secure auth)")

    # Get PIN
    code = (pin or "").strip()
    if not code or len(code) != PIN_LENGTH or not code.isdigit():
        code = _ask_pin()
        if not code or not code.isdigit() or len(code) != PIN_LENGTH:
            logging.error("PIN entry cancelled or invalid")
            _show_error("Invalid PIN", "PIN entry was cancelled or invalid.")
            return (False, None)

    try:
        # Send CSR request with PIN
        sock.sendall(f"AUTH CSR {code}".encode())
        resp = sock.recv(2048).decode("utf-8", errors="replace").strip()

        # Handle error responses
        if resp.startswith("FAIL:BADPIN"):
            logging.error("Incorrect or expired PIN")
            _show_error("Authentication Failed", "The PIN is incorrect or expired.")
            return (False, None)
        if resp.startswith("FAIL:RATELIMIT"):
            logging.error("Rate limited: %s", resp)
            _show_error("Rate Limited", "Too many failed attempts. Please wait.")
            return (False, None)
        if resp.startswith("BUSY"):
            logging.error("Host is already in a session")
            _show_error("Host Busy", "The host is already connected to another client.")
            return (False, None)
        if resp != "SENDCSR":
            logging.error("[AUTH] Unexpected response: %s", resp)
            return (None, "failed")

        # Generate and send CSR
        client_id = f"linuxplay-{socket.gethostname()}"
        csr_pem = _generate_csr(key_path, client_id)
        if not csr_pem:
            raise Exception("Failed to generate CSR")

        csr_b64 = base64.b64encode(csr_pem).decode()
        sock.sendall(f"CSR:{csr_b64}".encode())

        # Receive certificate
        cert_resp = sock.recv(16384).decode("utf-8", errors="replace").strip()

        if not cert_resp.startswith("CERT:"):
            logging.error("[AUTH] CSR flow failed: %s", cert_resp)
            return (None, "failed")

        cert_data = cert_resp[5:]
        parts = cert_data.split("|")
        if len(parts) != 2:
            raise Exception("Invalid certificate response")

        cert_b64, ca_b64 = parts
        cert_pem = base64.b64decode(cert_b64)
        ca_pem = base64.b64decode(ca_b64)

        # Save certificates
        client_dir = cert_path.parent
        client_dir.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(cert_pem)
        ca_path.write_bytes(ca_pem)
        cert_path.chmod(0o600)
        ca_path.chmod(0o600)

        # Validate and pin CA
        if not _validate_host_ca_fingerprint(ca_pem, host_ip):
            logging.error("[AUTH] CA fingerprint validation failed after issuance!")
            return (False, None)

        # Receive final OK
        final_resp = sock.recv(2048).decode("utf-8", errors="replace").strip()
        if final_resp.startswith("OK:"):
            parts = final_resp.split(":", 2)
            host_encoder = parts[1].strip()
            monitor_info = parts[2].strip() if len(parts) > 2 else DEFAULT_RESOLUTION
            CLIENT_STATE["connected"] = True
            CLIENT_STATE["last_heartbeat"] = time.time()
            logging.info("[AUTH] ✓ Authenticated via CSR (SECURE - first time)")
            _show_info(
                "Certificate Issued",
                "Client certificate issued successfully!\nFuture connections will use secure authentication.",
            )
            return (True, (host_encoder, monitor_info))

        logging.error("[AUTH] Final OK not received: %s", final_resp)

    except Exception as e:
        logging.error("[AUTH] CSR flow failed: %s", e)
        return (None, "error")

    return (None, "failed")


def _handle_legacy_fingerprint_auth(
    sock: socket.socket, cert_path: Path
) -> tuple[bool | None, tuple[str, str] | str | None]:
    """Handle legacy fingerprint-only authentication.

    Returns: (success: bool, result: tuple | None)
    """
    logging.warning("[AUTH] Falling back to LEGACY fingerprint-only auth (DEPRECATED)")
    try:
        fp_hex = _read_pem_cert_fingerprint(cert_path)
        if fp_hex:
            sock.sendall(f"HELLO CERTFP:{fp_hex}".encode())
            resp = sock.recv(2048).decode("utf-8", errors="replace").strip()

            if resp.startswith("OK:"):
                parts = resp.split(":", 2)
                host_encoder = parts[1].strip()
                monitor_info = parts[2].strip() if len(parts) > 2 else DEFAULT_RESOLUTION
                CLIENT_STATE["connected"] = True
                CLIENT_STATE["last_heartbeat"] = time.time()
                logging.warning("[AUTH] ✓ Authenticated via fingerprint (LEGACY - insecure)")
                return (True, (host_encoder, monitor_info))

            logging.warning("[AUTH] Legacy fingerprint auth failed: %s", resp)
    except Exception as e:
        logging.debug("[AUTH] Legacy fingerprint auth error: %s", e)

    return (None, "failed")


def _handle_legacy_pin_auth(sock: socket.socket, pin: str) -> tuple[bool | None, tuple[str, str] | str | None]:
    """Handle legacy PIN-only authentication.

    Returns: (success: bool, result: tuple | None)
    """
    logging.warning("[AUTH] Falling back to LEGACY PIN-only auth (INSECURE)")
    code = (pin or "").strip()
    if not code or len(code) != 6 or not code.isdigit():
        code = _ask_pin()
        if not code or not code.isdigit() or len(code) != 6:
            logging.error("PIN entry cancelled or invalid")
            _show_error("Invalid PIN", "PIN entry was cancelled or invalid.")
            return (False, None)

    sock.sendall(f"HELLO {code}".encode())
    resp = sock.recv(2048).decode("utf-8", errors="replace").strip()

    if resp.startswith("OK:"):
        parts = resp.split(":", 2)
        host_encoder = parts[1].strip()
        monitor_info = parts[2].strip() if len(parts) > 2 else DEFAULT_RESOLUTION
        CLIENT_STATE["connected"] = True
        CLIENT_STATE["last_heartbeat"] = time.time()
        logging.warning("[AUTH] ✓ Authenticated via PIN-only (LEGACY - insecure)")
        return (True, (host_encoder, monitor_info))

    if resp.startswith("BUSY"):
        logging.error("Host is already in a session")
        _show_error("Host Busy", "The host is already connected to another client.")
        return (False, None)

    if resp.startswith("FAIL:BADPIN"):
        logging.error("Incorrect or expired PIN")
        _show_error("Authentication Failed", "The PIN is incorrect or expired.")
        return (False, None)

    if resp.startswith("FAIL:RATELIMIT"):
        logging.error("Rate limited")
        _show_error("Rate Limited", "Too many failed attempts. Please wait.")
        return (False, None)

    logging.error("Unexpected handshake response: %s", resp)
    _show_error("Handshake Error", f"Unexpected response from host:\n{resp}")
    return (False, None)


def tcp_handshake_client(host_ip: str, pin: str | None = None) -> tuple[bool, tuple[str, str] | None]:
    """Authenticate with host using secure certificate-based protocol.

    Authentication Priority (tries in order):
    1. NEW: Challenge-response with existing cert (RSA signature verification)
    2. NEW: CSR submission with PIN (first-time secure auth)
    3. LEGACY: Fingerprint-only (deprecated, for old hosts)
    4. LEGACY: PIN-only (deprecated, insecure)

    Security:
        - RSA 4096-bit challenge-response (modern)
        - Trust On First Use (TOFU) for host CA fingerprint
        - Private keys never transmitted

    Args:
        host_ip: Host IP address to connect to
        pin: Optional 6-digit PIN for first-time auth (prompted if needed)

    Returns:
        Tuple of (success: bool, result: tuple[encoder, monitor_info] | None)
        On success: (True, ("nvenc", "1920x1080+0+0;1920x1080+1920+0"))
        On failure: (False, None)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)  # Increased timeout for crypto operations (was 10s)

    try:
        logging.info("Handshake to %s:%s", host_ip, TCP_HANDSHAKE_PORT)
        sock.connect((host_ip, TCP_HANDSHAKE_PORT))

        # Get client paths
        _, cert_path, key_path, ca_path = _get_client_paths()

        # Ensure client has keypair
        _ensure_client_keypair(key_path)

        # PATH 1: NEW SECURE - Challenge-response with existing cert
        if cert_path.exists() and key_path.exists() and ca_path.exists():
            result = _handle_challenge_response(sock, cert_path, key_path, ca_path, host_ip)
            if result[0] is not None:  # Definitive result (success or failure)
                sock.close()
                return result

            # Need to reconnect for legacy attempt
            with contextlib.suppress(Exception):
                sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host_ip, TCP_HANDSHAKE_PORT))

        # PATH 2: NEW SECURE - CSR submission (first time with this client)
        if not cert_path.exists() or not ca_path.exists():
            result = _handle_csr_submission(sock, key_path, cert_path, ca_path, host_ip, pin)
            if result[0] is not None:  # Definitive result
                sock.close()
                return result

        # PATH 3: LEGACY - Fingerprint-only (deprecated)
        if cert_path.exists() and key_path.exists():
            result = _handle_legacy_fingerprint_auth(sock, cert_path)
            if result[0] is not None:
                sock.close()
                return result

        # PATH 4: LEGACY - PIN-only (most insecure)
        result = _handle_legacy_pin_auth(sock, pin)
        sock.close()
        return result

    except (TimeoutError, socket.gaierror) as e:
        logging.error("Network error during handshake: %s", e)
        _show_error("Network Error", f"Cannot reach host {host_ip}:{TCP_HANDSHAKE_PORT}\n{e}")
        with contextlib.suppress(Exception):
            sock.close()
        return (False, None)
    except (ConnectionRefusedError, ConnectionResetError) as e:
        logging.error("Connection rejected: %s", e)
        _show_error("Connection Refused", f"Host refused connection\n{e}")
        with contextlib.suppress(Exception):
            sock.close()
        return (False, None)
    except Exception as e:
        logging.error("Handshake failed: %s", e, exc_info=True)
        _show_error("Connection Error", f"Handshake failed:\n{e}")
        with contextlib.suppress(Exception):
            sock.close()
        return (False, None)


def heartbeat_responder(host_ip: str) -> threading.Thread:
    """Start heartbeat responder thread for connection keepalive.

    Protocol: Host sends PING every 1s, client responds with PONG.
    Connection considered lost if no PING received for HEARTBEAT_TIMEOUT_SECS (10s).

    Firewall-free: Uses outbound-only ephemeral port (no inbound port needed).

    Args:
        host_ip: Host IP address for heartbeat destination

    Returns:
        Started daemon thread (automatically cleaned up on exit)
    """

    def loop() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Optimize for heartbeat responsiveness
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_RECV_BUFFER_SIZE)
                if IS_LINUX:
                    # SO_BUSY_POLL for ultra-low latency
                    with contextlib.suppress(OSError):
                        sock.setsockopt(socket.SOL_SOCKET, 46, UDP_BUSY_POLL_USEC)  # SO_BUSY_POLL=46
            except OSError as e:
                logging.debug(f"Heartbeat socket optimization failed (non-critical): {e}")
            # No bind() - use ephemeral port for outbound connection
            sock.settimeout(2)
            logging.info("Heartbeat responder active (outbound-only, no firewall port needed)")
            host_addr = (host_ip, UDP_HEARTBEAT_PORT)

            # Send initial PONG to establish connection with host
            try:
                sock.sendto(b"PONG", host_addr)
                logging.debug("Sent initial PONG to establish heartbeat connection")
            except Exception as e:
                logging.warning(f"Initial PONG send failed: {e}")

            while CLIENT_STATE["connected"]:
                try:
                    # Receive PING from host (will arrive on our ephemeral port)
                    data, addr = sock.recvfrom(256)
                    if data == b"PING" and addr[0] == host_ip:
                        # Reply to host
                        sock.sendto(b"PONG", host_addr)
                        CLIENT_STATE["last_heartbeat"] = time.time()
                except TimeoutError:
                    if time.time() - CLIENT_STATE["last_heartbeat"] > HEARTBEAT_TIMEOUT_SECS:
                        CLIENT_STATE["connected"] = False
                        CLIENT_STATE["reconnecting"] = True
                        logging.warning("Heartbeat timeout after %ds", HEARTBEAT_TIMEOUT_SECS)
                except Exception as e:
                    logging.debug(f"Heartbeat error: {e}")
                    time.sleep(0.2)
                    continue

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def clipboard_listener(app_clipboard: object, host_ip: str) -> threading.Thread:
    """Start clipboard sync thread.

    Returns:
        Started daemon thread (automatically cleaned up on exit)
    """

    def loop() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Optimize for clipboard data transfer
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_RECV_BUFFER_SIZE)
            except OSError as e:
                logging.debug(f"Clipboard socket optimization failed (non-critical): {e}")
            # No bind() - use ephemeral port for receiving on same socket used for sending
            sock.settimeout(2)
            logging.info("Clipboard listener active (outbound-only, no firewall port needed)")
            host_addr = (host_ip, UDP_CLIPBOARD_PORT)

            # Send a keepalive to establish connection path through NAT/firewall
            try:
                sock.sendto(b"CLIPBOARD_KEEPALIVE", host_addr)
                logging.debug("Sent clipboard keepalive to establish connection")
            except Exception as e:
                logging.warning(f"Clipboard keepalive send failed: {e}")

            while CLIENT_STATE["connected"]:
                try:
                    data, addr = sock.recvfrom(65535)
                    # Only accept from authenticated host
                    if addr[0] != host_ip:
                        continue
                    msg = data.decode("utf-8", errors="replace").strip()
                    if msg.startswith("CLIPBOARD_UPDATE HOST"):
                        text = msg.split("HOST", 1)[1].strip()
                        if text:
                            app_clipboard.blockSignals(True)
                            app_clipboard.setText(text)
                            app_clipboard.blockSignals(False)
                except TimeoutError:
                    # Normal timeout during wait for clipboard data - no action needed
                    pass
                except Exception:
                    # Network error or decode failure - retry after brief delay
                    time.sleep(0.2)
                    continue

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def audio_listener(host_ip: str) -> threading.Thread:
    """Start audio playback thread using ffplay.

    Returns:
        Started daemon thread (automatically cleaned up on exit)
    """

    def loop() -> None:
        cmd = [
            "ffplay",
            "-hide_banner",
            "-loglevel",
            "info",
            "-nodisp",
            "-autoexit",
            "-fflags",
            "nobuffer",
            "-flags",
            "low_delay",
            "-af",
            "aresample=matrix_encoding=none",
            "-f",
            "mpegts",
            f"udp://{host_ip}:{UDP_AUDIO_PORT}?overrun_nonfatal=1&buffer_size=32768",
        ]
        logging.info("Audio listener: %s", " ".join(cmd))
        try:
            audio_proc_manager.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True
            )
            # Log audio stream detection
            for line in audio_proc_manager.proc.stdout:
                if "Stream #" in line and "Audio" in line:
                    logging.info(line.strip())

            # Wait for process to complete
            ret = audio_proc_manager.proc.wait()
            if ret != 0:
                logging.warning(f"ffplay exited with code {ret}")
        except Exception as e:
            logging.error("Audio listener failed: %s", e)
        finally:
            audio_proc_manager.proc = None

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


class DecoderThread(QThread):
    frame_ready = pyqtSignal(object)

    def __init__(self, input_url: str, decoder_opts: dict[str, str] | None, ultra: bool = False) -> None:
        super().__init__()
        self.input_url = input_url
        self.decoder_opts = dict(decoder_opts or {})
        self.decoder_opts.setdefault("probesize", "32")
        self.decoder_opts.setdefault("analyzeduration", "0")
        self.decoder_opts.setdefault("scan_all_pmts", "1")
        self.decoder_opts.setdefault("fflags", "nobuffer")
        self.decoder_opts.setdefault("flags", "low_delay")
        self.decoder_opts.setdefault("reorder_queue_size", "0")
        self.decoder_opts.setdefault("rtbufsize", "2M")
        self.decoder_opts.setdefault("fpsprobesize", "1")

        self._running = True
        self._sw_fallback_done = False
        self.ultra = ultra
        self._emit_interval = 0.0
        self._last_emit = 0.0
        self._frame_count = 0
        self._avg_decode_time = 0.0
        self._restart_delay = 0.5
        self._last_error = ""
        self._has_first_frame = False
        self._hw_name = None

    def _open_container(self) -> av.container.InputContainer:
        logging.debug("Opening stream with opts: %s", self.decoder_opts)
        return av.open(self.input_url, format="mpegts", options=self.decoder_opts)

    def _setup_codec_context(self, cc: av.codec.CodecContext) -> None:
        """Configure codec context for low-latency decoding."""
        cc.thread_count = 1 if self.ultra else 2

        for attr, value in (
            ("low_delay", True),
            ("skip_frame", "NONREF"),
            ("has_b_frames", False),
            ("strict_std_compliance", "experimental"),
            ("framerate", None),
            ("delay", 0),
        ):
            with contextlib.suppress(Exception):
                setattr(cc, attr, value)

        with contextlib.suppress(Exception):
            cc.flags2 = "+fast"

    def _init_hardware_decode(self, cc: av.codec.CodecContext) -> None:
        """Initialize hardware decode context if available."""
        hw_device = getattr(cc, "hw_device_ctx", None)
        if hw_device is not None or "hwaccel" not in self.decoder_opts:
            return

        hw_type = self.decoder_opts["hwaccel"]
        dev = self.decoder_opts.get("hwaccel_device", None)

        hw_type_map = {
            "vaapi": "vaapi",
            "nvdec": "cuda",
            "cuda": "cuda",
            "qsv": "qsv",
            "d3d11va": "d3d11va",
            "dxva2": "dxva2",
        }
        hw_type_norm = hw_type_map.get(hw_type, hw_type)

        try:
            if not hasattr(av, "HwDeviceContext"):
                logging.warning(f"PyAV build lacks HwDeviceContext; using software decode for {hw_type_norm}.")
                self._hw_name = "CPU"
                self.decoder_opts.pop("hwaccel", None)
                self.decoder_opts.pop("hwaccel_device", None)
                return

            if not dev:
                if hw_type_norm == "vaapi":
                    dev = "/dev/dri/renderD128"
                elif hw_type_norm in ("cuda", "nvdec"):
                    dev = "cuda"

            hw_ctx = av.HwDeviceContext.create(hw_type_norm, device=dev)
            cc.hw_device_ctx = hw_ctx
            self._hw_name = hw_type_norm
            logging.info(f"DecoderThread: Using hardware decode via {hw_type_norm} ({dev or 'auto'})")
        except Exception as e:
            logging.warning(f"Hardware decode init failed for {hw_type_norm}: {e}")
            self._hw_name = "CPU"
            self.decoder_opts.pop("hwaccel", None)
            self.decoder_opts.pop("hwaccel_device", None)

    def _extract_dmabuf_fd(self, frame: av.VideoFrame) -> int | None:
        """Extract DMA-BUF file descriptor from hardware frame if available."""
        try:
            if not frame.hw_frames_ctx:
                return None
            if not hasattr(frame, "planes") or not frame.planes:
                return None

            p = frame.planes[0]
            if hasattr(p, "fd"):
                return p.fd
            if hasattr(p, "buffer_ptr") and isinstance(p.buffer_ptr, int):
                return p.buffer_ptr
        except Exception:
            # DMA-BUF extraction failed (driver/hardware incompatibility) - fall back to CPU decode
            pass
        return None

    def _process_frame(self, frame: av.VideoFrame, t_decode: float) -> bool:
        """Process and emit a decoded frame."""
        if not self._running or not frame or frame.is_corrupt:
            return False

        t0 = time.perf_counter()
        dmabuf_fd = self._extract_dmabuf_fd(frame)

        if dmabuf_fd is not None:
            self._has_first_frame = True
            self.frame_ready.emit(("dmabuf", dmabuf_fd, frame.width, frame.height))
        else:
            arr = frame.to_ndarray(format="rgb24")
            if not arr.flags["C_CONTIGUOUS"]:
                arr = np.ascontiguousarray(arr, dtype=np.uint8)
            self._has_first_frame = True
            self.frame_ready.emit((arr, frame.width, frame.height))

        t1 = time.perf_counter()
        self._frame_count += 1
        decode_time = (t1 - t0) * 1000
        self._avg_decode_time = (
            0.9 * self._avg_decode_time + 0.1 * decode_time if self._frame_count > 1 else decode_time
        )

        if len(t_decode) < 120:
            t_decode.append(decode_time)
        else:
            avg = statistics.mean(t_decode)
            logging.debug(f"Avg decode time: {avg:.2f} ms ({self._hw_name or 'CPU'})")
            t_decode.clear()

        if self._emit_interval > 0:
            elapsed = time.time() - self._last_emit
            if elapsed < self._emit_interval:
                return False
        self._last_emit = time.time()
        return True

    def _decode_loop(self, container: av.container.InputContainer) -> None:
        """Main decode loop for processing video frames."""
        vstream = next((s for s in container.streams if s.type == "video"), None)
        if not vstream:
            logging.warning("No video stream detected, retrying...")
            time.sleep(0.5)
            return

        cc = vstream.codec_context
        self._setup_codec_context(cc)
        self._init_hardware_decode(cc)

        t_decode = []
        for frame in container.decode(video=0):
            if not self._running:
                break
            self._process_frame(frame, t_decode)

    def run(self) -> None:
        while self._running:
            container = None
            try:
                container = self._open_container()
                self._decode_loop(container)

                if self._running:
                    if not self._has_first_frame:
                        logging.info("Still waiting for video data...")
                    else:
                        logging.warning("Stream ended — reconnecting in %.1fs...", self._restart_delay)
                    time.sleep(self._restart_delay)

            except Exception as e:
                err = str(e)
                if err != self._last_error:
                    logging.error(f"Decode error: {err}")
                    self._last_error = err

                if not self._sw_fallback_done and "hwaccel" in self.decoder_opts:
                    logging.warning("HW decode failed — switching to CPU.")
                    self.decoder_opts.pop("hwaccel", None)
                    self.decoder_opts.pop("hwaccel_device", None)
                    self._sw_fallback_done = True
                    continue

                if self._running:
                    time.sleep(self._restart_delay)

            finally:
                try:
                    if container:
                        container.close()
                except Exception:
                    # Container already closed or cleanup failed - ignore during shutdown
                    pass

    def stop(self) -> None:
        self._running = False
        time.sleep(0.05)


class RenderBackend:
    def render_frame(self, frame_tuple) -> None:
        pass

    def is_valid(self) -> bool:
        return False

    def name(self) -> str:
        return "unknown"


class RenderKMSDRM(RenderBackend):
    def __init__(self) -> None:
        self.valid = False
        self.fd = None
        self.gbm = None
        self.bo = None
        self.map = None
        self.stride = 0
        self.width = 0
        self.height = 0
        self.device_path = None

        for node in ("/dev/dri/renderD128", "/dev/dri/renderD129", "/dev/dri/card0", "/dev/dri/card1"):
            node_path = Path(node)
            if node_path.exists() and os.access(node, os.W_OK):
                try:
                    self.fd = os.open(node, os.O_RDWR | os.O_CLOEXEC)
                    self.device_path = node
                    self.valid = True
                    break
                except Exception:
                    # DRM device open failed (permission/busy) - try next device
                    continue

        if not self.valid:
            logging.debug("KMSDRM: no accessible DRM device found.")
            return

        try:
            self.libgbm = ctypes.CDLL("libgbm.so.1")

            self.libgbm.gbm_create_device.argtypes = [ctypes.c_int]
            self.libgbm.gbm_create_device.restype = ctypes.c_void_p

            self.libgbm.gbm_bo_create.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
            ]
            self.libgbm.gbm_bo_create.restype = ctypes.c_void_p

            self.libgbm.gbm_bo_get_stride.argtypes = [ctypes.c_void_p]
            self.libgbm.gbm_bo_get_stride.restype = ctypes.c_uint32

            self.libgbm.gbm_bo_destroy.argtypes = [ctypes.c_void_p]
            self.libgbm.gbm_device_destroy.argtypes = [ctypes.c_void_p]

            self.gbm = self.libgbm.gbm_create_device(self.fd)
            if not self.gbm:
                raise RuntimeError("gbm_create_device() failed")

            self.valid = True
            logging.info(f"KMSDRM initialized (safe render-node) via {self.device_path}")
        except Exception as e:
            logging.debug(f"KMSDRM init failed: {e}")
            self.valid = False

    def is_valid(self):
        return self.valid

    def name(self) -> str:
        return "KMSDRM"

    def _alloc_bo(self, w: int, h: int) -> None:
        if not self.valid or not self.gbm:
            return
        try:
            if self.bo:
                self.libgbm.gbm_bo_destroy(self.bo)
                self.bo = None

            DRM_FORMAT_ARGB8888 = 0x34325241
            GBM_BO_USE_RENDERING = 1 << 1

            self.bo = self.libgbm.gbm_bo_create(self.gbm, w, h, DRM_FORMAT_ARGB8888, GBM_BO_USE_RENDERING)
            if not self.bo:
                raise RuntimeError("gbm_bo_create() failed")

            self.stride = self.libgbm.gbm_bo_get_stride(self.bo)
            size = self.stride * h

            if self.map:
                self.map.close()
            self.map = mmap.mmap(self.fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
            self.width, self.height = w, h
            logging.debug(f"KMSDRM GBM buffer {w}x{h} stride={self.stride}")
        except Exception as e:
            logging.debug(f"KMSDRM alloc failed: {e}")
            self.valid = False

    def _import_dmabuf(self, fd: int, w: int, h: int) -> np.ndarray | None:
        try:
            size = w * h * 4
            with mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ) as buf:
                data = buf.read(size)
            logging.debug(f"KMSDRM: imported dmabuf FD={fd} ({w}x{h})")
            return np.frombuffer(data, dtype=np.uint8).reshape(h, w, 4)
        except Exception as e:
            logging.debug(f"KMSDRM: dmabuf import failed: {e}")
            return None

    def render_frame(self, frame_tuple: tuple) -> None:
        if not self.valid:
            return
        t0 = time.perf_counter()
        try:
            is_dmabuf = (
                isinstance(frame_tuple, tuple)
                and len(frame_tuple) == 4
                and isinstance(frame_tuple[0], str)
                and frame_tuple[0] == "dmabuf"
            )

            if is_dmabuf:
                _, fd, w, h = frame_tuple
                w, h = int(w), int(h)
                arr = self._import_dmabuf(fd, w, h)
                if not isinstance(arr, np.ndarray) or arr.size == 0:
                    return
            else:
                arr, w, h = frame_tuple
                w, h = int(w), int(h)
                if not isinstance(arr, np.ndarray) or arr.size == 0:
                    return

            cur_w = int(getattr(self, "width", 0) or 0)
            cur_h = int(getattr(self, "height", 0) or 0)
            if (w != cur_w) or (h != cur_h):
                self._alloc_bo(w, h)

            data = np.ascontiguousarray(arr, dtype=np.uint8)
            if self.map and hasattr(self.map, "write"):
                self.map.seek(0)
                self.map.write(data.tobytes())

            dt = (time.perf_counter() - t0) * 1000.0
            logging.debug(
                f"KMSDRM upload {w}x{h} ({data.nbytes / 1024 / 1024:.2f} MB) in {dt:.2f} ms to {self.device_path}"
            )
        except Exception as e:
            logging.debug(f"KMSDRM render error: {e}")


class RenderVulkan(RenderBackend):
    def __init__(self) -> None:
        try:
            self.valid = True
        except Exception:
            # Vulkan initialization failed - backend not available
            self.valid = False

    def is_valid(self):
        return self.valid

    def name(self) -> str:
        return "Vulkan"

    def render_frame(self, frame_tuple) -> None:
        try:
            if (
                isinstance(frame_tuple, tuple)
                and len(frame_tuple) == 4
                and isinstance(frame_tuple[0], str)
                and frame_tuple[0] == "dmabuf"
            ):
                return
            arr, w, h = frame_tuple
            if not isinstance(arr, np.ndarray) or arr.size == 0:
                return
            t0 = time.perf_counter()
            _ = np.mean(arr)
            dt = (time.perf_counter() - t0) * 1000.0
            logging.debug(f"Vulkan simulated render {int(w)}x{int(h)} in {dt:.2f} ms")
        except Exception as e:
            logging.debug(f"Vulkan render error: {e}")


class RenderOpenGL(RenderBackend):
    def __init__(self) -> None:
        self.valid = True

    def is_valid(self):
        return self.valid

    def name(self) -> str:
        return "OpenGL"

    def render_frame(self, frame_tuple) -> None:
        try:
            if (
                isinstance(frame_tuple, tuple)
                and len(frame_tuple) == 4
                and isinstance(frame_tuple[0], str)
                and frame_tuple[0] == "dmabuf"
            ):
                return
            arr, w, h = frame_tuple
            if not isinstance(arr, np.ndarray) or arr.size == 0:
                return
            t0 = time.perf_counter()
            _ = np.mean(arr)
            dt = (time.perf_counter() - t0) * 1000.0
            logging.debug(f"OpenGL simulated render {int(w)}x{int(h)} in {dt:.2f} ms")
        except Exception as e:
            logging.debug(f"OpenGL render error: {e}")


def pick_best_renderer():
    renderers = (RenderKMSDRM, RenderVulkan, RenderOpenGL)
    selected = None
    for renderer_cls in renderers:
        r = renderer_cls()
        logging.debug(f"Trying renderer: {r.name()} (valid={r.is_valid()})")
        if r.is_valid():
            selected = r
            logging.info(f"Renderer selected: {r.name()}")
            if hasattr(r, "device_path") and r.device_path:
                logging.info(f"Using device path: {r.device_path}")
            break

    if not selected:
        logging.warning("No GPU renderer found, using dummy software renderer.")
        selected = RenderBackend()
    return selected


class VideoWidgetGL(QOpenGLWidget):
    def __init__(self, control_callback, rwidth, rheight, offset_x, offset_y, host_ip, parent=None) -> None:  # noqa: PLR0913
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAutoFillBackground(False)
        self.setAttribute(Qt.WA_OpaquePaintEvent, True)
        self.setAttribute(Qt.WA_NoSystemBackground, True)

        self.host_ip = host_ip
        self.control_callback = control_callback
        self.texture_width = rwidth
        self.texture_height = rheight
        self.offset_x = offset_x
        self.offset_y = offset_y
        self.frame_data = None
        self._pending_resize = None

        self.clipboard = QApplication.clipboard()
        self.clipboard.dataChanged.connect(self.on_clipboard_change)
        self.last_clipboard = self.clipboard.text()
        self.ignore_clipboard = False

        self.texture_id = None
        self.pbo_ids = []
        self.current_pbo = 0
        self._last_frame_recv = time.time()
        self._last_mouse_ts = 0.0
        self._mouse_throttle = 0.0025

        if not logging.getLogger().hasHandlers():
            logging.basicConfig(
                level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
            )

        logging.info("────────────────────────────────────────────")
        logging.info("Renderer Initialization Summary")
        logging.info(f"Session type: {os.environ.get('XDG_SESSION_TYPE', 'unknown')}")
        logging.info(f"Desktop: {os.environ.get('XDG_CURRENT_DESKTOP', 'unknown')}")
        logging.info(f"Display server: {os.environ.get('WAYLAND_DISPLAY') or os.environ.get('DISPLAY', 'n/a')}")
        for node in ("/dev/dri/renderD128", "/dev/dri/renderD129", "/dev/dri/card0", "/dev/dri/card1"):
            exists = "✅" if Path(node).exists() else "❌"
            access = "🟢" if os.access(node, os.W_OK) else "🔴"
            logging.info(f"  {node:<20} exists={exists} access={access}")
        logging.info("Renderer priority order: KMSDRM → Vulkan → OpenGL")

        self.renderer = pick_best_renderer()
        logging.info(f"Using render backend: {self.renderer.name()}")
        if hasattr(self.renderer, "device_path") and self.renderer.device_path:
            logging.info(f"Bound to device: {self.renderer.device_path}")
        logging.info("────────────────────────────────────────────")

    def on_clipboard_change(self) -> None:
        new_text = self.clipboard.text()
        if self.ignore_clipboard or not new_text or new_text == self.last_clipboard:
            return
        self.last_clipboard = new_text
        msg = f"CLIPBOARD_UPDATE CLIENT {new_text}".encode()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(msg, (self.host_ip, UDP_CLIPBOARD_PORT))
        except Exception:
            # Clipboard sync failed (network error) - non-critical, skip update
            pass

    def initializeGL(self) -> None:
        """Initialize OpenGL context and resources.

        Creates texture and PBO triple buffer for zero-copy video upload.
        Defers initialization if context not ready (happens on first paintGL).
        """
        try:
            glDisable(GL_DEPTH_TEST)
            glDisable(GL_DITHER)
            glClearColor(0.0, 0.0, 0.0, 1.0)
            self.texture_id = glGenTextures(1)
            if self.texture_id:
                self._initialize_texture(self.texture_width, self.texture_height)
                logging.debug(f"OpenGL initialized: texture {self.texture_width}x{self.texture_height}")
        except Exception as e:
            logging.warning(f"OpenGL initialization deferred: {e}")
            # Context will be ready on first paintGL call
            self.texture_id = None

    def _initialize_texture(self, w, h) -> None:
        glBindTexture(GL_TEXTURE_2D, self.texture_id)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE)
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1)
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, w, h, 0, GL_RGB, GL_UNSIGNED_BYTE, None)
        glBindTexture(GL_TEXTURE_2D, 0)

        if self.pbo_ids:
            glDeleteBuffers(len(self.pbo_ids), self.pbo_ids)

        buf_size = w * h * 3
        self.pbo_ids = list(glGenBuffers(3))
        for pbo in self.pbo_ids:
            glBindBuffer(GL_PIXEL_UNPACK_BUFFER, pbo)
            glBufferData(GL_PIXEL_UNPACK_BUFFER, buf_size, None, GL_STREAM_DRAW)
        glBindBuffer(GL_PIXEL_UNPACK_BUFFER, 0)

        self.texture_width, self.texture_height = w, h
        self.current_pbo = 0
        glFlush()

    def resizeTexture(self, w, h) -> None:
        if (w, h) != (self.texture_width, self.texture_height):
            logging.info(f"Resize texture {self.texture_width}x{self.texture_height} → {w}x{h}")
            self._pending_resize = (w, h)

    def paintGL(self) -> None:
        """Render video frame using OpenGL with PBO triple buffering.

        PBO triple buffering workflow:
        1. Upload frame data to current PBO (asynchronous DMA)
        2. Bind previous PBO to texture (data already transferred)
        3. Rotate to next PBO for next frame

        Performance: Zero-copy upload, PBO enables async GPU transfer.
        """
        if not self.frame_data:
            glClear(GL_COLOR_BUFFER_BIT)
            return

        # Safety check: Ensure texture is initialized
        if not self.texture_id:
            logging.debug("Texture not ready, reinitializing...")
            try:
                self.texture_id = glGenTextures(1)
                self._initialize_texture(self.texture_width, self.texture_height)
            except Exception as e:
                logging.error(f"Texture initialization failed: {e}")
                return

        arr, fw, fh = self.frame_data
        if self._pending_resize:
            w, h = self._pending_resize
            self._initialize_texture(w, h)
            self._pending_resize = None

        data = np.ascontiguousarray(arr, dtype=np.uint8)
        size = data.nbytes
        current_pbo = self.pbo_ids[self.current_pbo]

        glBindBuffer(GL_PIXEL_UNPACK_BUFFER, current_pbo)
        glBufferData(GL_PIXEL_UNPACK_BUFFER, size, None, GL_STREAM_DRAW)
        ptr = glMapBuffer(GL_PIXEL_UNPACK_BUFFER, GL_WRITE_ONLY)
        if ptr:
            ctypes.memmove(ptr, data.ctypes.data, size)
            glUnmapBuffer(GL_PIXEL_UNPACK_BUFFER)

        glBindTexture(GL_TEXTURE_2D, self.texture_id)
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1)
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, fw, fh, GL_RGB, GL_UNSIGNED_BYTE, None)
        glBindBuffer(GL_PIXEL_UNPACK_BUFFER, 0)

        aspect_tex = fw / float(fh)
        aspect_win = self.width() / float(self.height())
        if aspect_win > aspect_tex:
            sx, sy = (aspect_tex / aspect_win), 1.0
        else:
            sx, sy = 1.0, (aspect_win / aspect_tex)

        glClear(GL_COLOR_BUFFER_BIT)
        glEnable(GL_TEXTURE_2D)
        glBegin(GL_QUADS)
        glTexCoord2f(0.0, 1.0)
        glVertex2f(-sx, -sy)
        glTexCoord2f(1.0, 1.0)
        glVertex2f(sx, -sy)
        glTexCoord2f(1.0, 0.0)
        glVertex2f(sx, sy)
        glTexCoord2f(0.0, 0.0)
        glVertex2f(-sx, sy)
        glEnd()
        glDisable(GL_TEXTURE_2D)
        glBindTexture(GL_TEXTURE_2D, 0)
        glFlush()

        self.current_pbo = (self.current_pbo + 1) % len(self.pbo_ids)

    def updateFrame(self, frame_tuple) -> None:
        self.frame_data = frame_tuple
        _, fw, fh = frame_tuple
        if (fw, fh) != (self.texture_width, self.texture_height):
            self.resizeTexture(fw, fh)
        self._last_frame_recv = time.time()

        now = time.time()
        if not hasattr(self, "_frame_times"):
            self._frame_times = []
        self._frame_times.append(now)
        if len(self._frame_times) > 90:
            self._frame_times.pop(0)
        if len(self._frame_times) >= 2:
            diffs = [t2 - t1 for t1, t2 in zip(self._frame_times, self._frame_times[1:], strict=False)]
            mean_diff = statistics.mean(diffs)
            self._fps = 1.0 / mean_diff if mean_diff > 0 else 0.0

        try:
            self.renderer.render_frame(frame_tuple)
        except Exception as e:
            logging.debug(f"Renderer {self.renderer.name()} failed: {e}")

        if self.isVisible():
            t = time.time()
            if not hasattr(self, "_last_draw") or (t - getattr(self, "_last_draw", 0)) > (1 / 240):
                self._last_draw = t
                self.update()

    def _flush_pending_mouse(self) -> None:
        if not hasattr(self, "_pending_mouse") or self._pending_mouse is None:
            return
        now = time.time()
        if now - self._last_mouse_ts < self._mouse_throttle:
            return
        rx, ry, buttons = self._pending_mouse
        self.send_mouse_packet(2, buttons, rx, ry)
        self._last_mouse_ts = now
        self._pending_mouse = None

    def send_mouse_packet(self, pkt_type, bmask, x, y) -> None:
        msg = f"MOUSE_PKT {pkt_type} {bmask} {x} {y}"
        with contextlib.suppress(Exception):
            self.control_callback(msg)

    def _scaled_mouse_coords(self, e) -> tuple[int, int]:
        """Transform window coordinates to remote display coordinates.

        Handles aspect ratio preservation with letterboxing (black bars).
        Maps click position in letterboxed window to actual pixel on remote display.

        Args:
            e: Mouse event with x() and y() methods

        Returns:
            Tuple of (remote_x, remote_y) in host display coordinates

        Example:
            Window: 1920x1200, Frame: 1920x1080 (16:9 in 16:10 window)
            Click at (960, 600) → Maps to center of frame (960, 540)
            Black bars: Top/bottom 60px each (letterbox)
        """
        ww, wh = self.width(), self.height()
        fw, fh = self.texture_width, self.texture_height

        # Prevent division by zero
        if fh == 0 or wh == 0:
            return self.offset_x, self.offset_y

        aspect_tex = fw / float(fh)
        aspect_win = ww / float(wh)

        if aspect_win > aspect_tex:
            view_h = wh
            view_w = aspect_tex / aspect_win * ww
            offset_x = (ww - view_w) / 2.0
            offset_y = 0
        else:
            view_w = ww
            view_h = aspect_win / aspect_tex * wh
            offset_x = 0
            offset_y = (wh - view_h) / 2.0

        # Prevent division by zero in coordinate transform
        if view_w == 0 or view_h == 0:
            return self.offset_x, self.offset_y

        nx = (e.x() - offset_x) / view_w
        ny = (e.y() - offset_y) / view_h

        # Clamp to valid normalized range
        nx = min(max(nx, 0.0), 1.0)
        ny = min(max(ny, 0.0), 1.0)

        rx = self.offset_x + int(nx * fw)
        ry = self.offset_y + int(ny * fh)
        return rx, ry

    def mousePressEvent(self, e) -> None:
        bmap = {Qt.LeftButton: 1, Qt.MiddleButton: 2, Qt.RightButton: 4}
        bmask = bmap.get(e.button(), 0)
        if bmask:
            rx, ry = self._scaled_mouse_coords(e)
            self.send_mouse_packet(1, bmask, rx, ry)
        e.accept()

    def mouseMoveEvent(self, e) -> None:
        rx, ry = self._scaled_mouse_coords(e)
        buttons = 0
        if e.buttons() & Qt.LeftButton:
            buttons |= 1
        if e.buttons() & Qt.MiddleButton:
            buttons |= 2
        if e.buttons() & Qt.RightButton:
            buttons |= 4

        if not hasattr(self, "_pending_mouse"):
            self._pending_mouse = None
        self._pending_mouse = (rx, ry, buttons)

        self._flush_pending_mouse()
        e.accept()

    def mouseReleaseEvent(self, e) -> None:
        bmap = {Qt.LeftButton: 1, Qt.MiddleButton: 2, Qt.RightButton: 4}
        bmask = bmap.get(e.button(), 0)
        if bmask:
            rx, ry = self._scaled_mouse_coords(e)
            self.send_mouse_packet(3, bmask, rx, ry)
        e.accept()

    def wheelEvent(self, e) -> None:
        d = e.angleDelta()
        if d.y() != 0:
            b = "4" if d.y() > 0 else "5"
            self.control_callback(f"MOUSE_SCROLL {b}")
        elif d.x() != 0:
            b = "6" if d.x() < 0 else "7"
            self.control_callback(f"MOUSE_SCROLL {b}")
        e.accept()

    def keyPressEvent(self, e) -> None:
        if e.isAutoRepeat():
            return
        key_name = self._get_key_name(e)
        if key_name:
            self.control_callback(f"KEY_PRESS {key_name}")
        e.accept()

    def keyReleaseEvent(self, e) -> None:
        if e.isAutoRepeat():
            return
        key_name = self._get_key_name(e)
        if key_name:
            self.control_callback(f"KEY_RELEASE {key_name}")
        e.accept()

    def _get_key_name(self, event):
        text = event.text()
        if text and len(text) == 1 and ord(text) >= 0x20:
            return "space" if text == " " else text
        key = event.key()
        key_map = {
            Qt.Key_Escape: "Escape",
            Qt.Key_Tab: "Tab",
            Qt.Key_Backtab: "Tab",
            Qt.Key_Backspace: "BackSpace",
            Qt.Key_Return: "Return",
            Qt.Key_Enter: "Return",
            Qt.Key_Insert: "Insert",
            Qt.Key_Delete: "Delete",
            Qt.Key_Pause: "Pause",
            Qt.Key_Print: "Print",
            Qt.Key_Home: "Home",
            Qt.Key_End: "End",
            Qt.Key_Left: "Left",
            Qt.Key_Up: "Up",
            Qt.Key_Right: "Right",
            Qt.Key_Down: "Down",
            Qt.Key_PageUp: "Page_Up",
            Qt.Key_PageDown: "Page_Down",
            Qt.Key_Shift: "Shift_L",
            Qt.Key_Control: "Control_L",
            Qt.Key_Meta: "Super_L",
            Qt.Key_Alt: "Alt_L",
            Qt.Key_AltGr: "Alt_R",
            Qt.Key_CapsLock: "Caps_Lock",
            Qt.Key_NumLock: "Num_Lock",
            Qt.Key_ScrollLock: "Scroll_Lock",
        }
        if key in key_map:
            return key_map[key]
        if (Qt.Key_A <= key <= Qt.Key_Z) or (Qt.Key_0 <= key <= Qt.Key_9):
            try:
                return chr(key).lower()
            except Exception:
                # Character conversion failed for special key code - return text fallback
                pass
        return text or None


class GamepadThread(threading.Thread):
    def __init__(self, host_ip, port, path_hint=None) -> None:
        super().__init__(daemon=True)
        self.host_ip = host_ip
        self.port = port
        self.path_hint = path_hint
        self._running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Optimize gamepad socket for low-latency input
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)
            if IS_LINUX:
                # SO_BUSY_POLL for gamepad input responsiveness
                with contextlib.suppress(OSError):
                    self.sock.setsockopt(socket.SOL_SOCKET, 46, UDP_BUSY_POLL_USEC)  # SO_BUSY_POLL=46
        except OSError as e:
            logging.debug(f"Gamepad socket optimization failed (non-critical): {e}")

    def _find_device(self):
        if not HAVE_EVDEV:
            return None
        if self.path_hint:
            try:
                return InputDevice(self.path_hint)
            except Exception:
                # Path hint invalid (device disconnected/removed) - fall back to auto-detection
                return None
        candidates = []
        for p in list_devices():
            try:
                d = InputDevice(p)
                name = (d.name or "").lower()
                if any(k in name for k in ("controller", "gamepad", "xbox", "dualshock", "dual sense", "8bitdo", "ps")):
                    candidates.append(d)
                    continue
                caps = d.capabilities(verbose=True)
                if any(n for (typ, codes) in caps for (code, n) in (codes or []) if n.startswith(("BTN_", "ABS_"))):
                    candidates.append(d)
            except Exception:
                # Device read failed (permission/disconnect) - skip this device
                pass
        if not candidates:
            return None

        def score(dev):
            s = 0
            try:
                n = (dev.name or "").lower()
                if "controller" in n or "gamepad" in n:
                    s += 5
                if "xbox" in n or "dual" in n or "8bitdo" in n or "ps" in n:
                    s += 3
                caps = dev.capabilities(verbose=True)
                if any((codes or []) for (_t, codes) in caps):
                    s += 1
            except Exception:
                # Device capabilities read failed - return current score without bonus
                pass
            return s

        candidates.sort(key=score, reverse=True)
        return candidates[0]

    def run(self) -> None:
        if not IS_LINUX:
            return
        if not HAVE_EVDEV:
            return

        dev = self._find_device()
        if not dev:
            return

        with contextlib.suppress(Exception):
            dev.grab()

        pack_event = struct.Struct("!Bhh").pack
        sendto = self.sock.sendto
        addr = (self.host_ip, self.port)

        try:
            for event in dev.read_loop():
                if not self._running:
                    break
                t = int(event.type)
                c = int(event.code)
                v = int(event.value)
                if t in (ecodes.EV_KEY, ecodes.EV_ABS, ecodes.EV_SYN):
                    with contextlib.suppress(Exception):
                        sendto(pack_event(t, c, v), addr)
        except Exception:
            # Gamepad device disconnected or read error - exit thread gracefully
            pass

        with contextlib.suppress(Exception):
            dev.ungrab()

    def stop(self) -> None:
        self._running = False
        with contextlib.suppress(Exception):
            self.sock.close()


class MainWindow(QMainWindow):
    def __init__(  # noqa: PLR0913
        self,
        decoder_opts,
        rwidth,
        rheight,
        host_ip,
        udp_port,
        offset_x,
        offset_y,
        net_mode="lan",
        parent=None,
        ultra=False,
        gamepad="disable",
        gamepad_dev=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("LinuxPlay")
        self.texture_width, self.texture_height = rwidth, rheight
        self.offset_x, self.offset_y = offset_x, offset_y
        self.host_ip, self.ultra = host_ip, ultra
        self._running, self._restarts = True, 0
        self.gamepad_mode = gamepad
        self.gamepad_dev = gamepad_dev

        self.control_addr = (host_ip, CONTROL_PORT)
        self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.control_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Optimize control socket for low-latency mouse/keyboard input
        try:
            self.control_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)
            if IS_LINUX:
                # SO_BUSY_POLL for control input responsiveness
                with contextlib.suppress(OSError):
                    self.control_sock.setsockopt(socket.SOL_SOCKET, 46, UDP_BUSY_POLL_USEC)  # SO_BUSY_POLL=46
        except OSError as e:
            logging.debug(f"Control socket optimization failed (non-critical): {e}")
        self.control_sock.setblocking(False)

        try:
            self.control_sock.sendto(f"NET {net_mode}".encode(), self.control_addr)
        except Exception as e:
            logging.debug(f"NET announce failed: {e}")

        self.video_widget = VideoWidgetGL(self.send_control, rwidth, rheight, offset_x, offset_y, host_ip)
        self.setCentralWidget(self.video_widget)
        self.video_widget.setFocus()
        self.setAcceptDrops(True)

        mtu_guess = int(os.environ.get("LINUXPLAY_MTU", "1500"))
        pkt = _best_ts_pkt_size(mtu_guess, False)
        self.video_url = (
            f"udp://@0.0.0.0:{udp_port}"
            f"?pkt_size={pkt}"
            f"&reuse=1&buffer_size=65536&fifo_size=32768"
            f"&overrun_nonfatal=1&max_delay=0"
        )

        self.decoder_opts = dict(decoder_opts)
        logging.debug("Decoder options: %s", self.decoder_opts)

        self._proc = psutil.Process(os.getpid())

        self._start_decoder_thread()
        self._start_background_threads()
        self._start_timers()

    def _start_timers(self) -> None:
        self.clip_timer = QTimer(self)
        self.clip_timer.timeout.connect(self._drain_clipboard_inbox)
        self.clip_timer.start(10)

        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self._poll_connection_state)
        self.status_timer.start(1000)

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self._update_stats)
        self.stats_timer.start(1000)

    def _start_background_threads(self) -> None:
        try:
            self._heartbeat_thread = heartbeat_responder(self.host_ip)
        except Exception as e:
            logging.error(f"Heartbeat responder failed: {e}")
            self._heartbeat_thread = None

        try:
            self._audio_thread = audio_listener(self.host_ip)
        except Exception as e:
            logging.error(f"Audio listener failed: {e}")
            self._audio_thread = None

        try:
            self._clip_thread = clipboard_listener(QApplication.clipboard(), self.host_ip)
        except Exception as e:
            logging.error(f"Clipboard listener failed: {e}")
            self._clip_thread = None

        self._gp_thread = None
        if self.gamepad_mode == "enable" and IS_LINUX:
            try:
                self._gp_thread = GamepadThread(self.host_ip, UDP_GAMEPAD_PORT, self.gamepad_dev)
                self._gp_thread.start()
                logging.info(
                    "Controller forwarding started from %s -> %s",
                    self.gamepad_dev or "/dev/input/event*",
                    f"{self.host_ip}:{UDP_GAMEPAD_PORT}",
                )
            except Exception as e:
                logging.error("Gamepad thread failed: %s", e)
                self._gp_thread = None

    def _start_decoder_thread(self) -> None:
        self.decoder_thread = DecoderThread(self.video_url, self.decoder_opts, ultra=self.ultra)
        self.decoder_thread.frame_ready.connect(self.video_widget.updateFrame, Qt.DirectConnection)
        self.decoder_thread.finished.connect(self._on_decoder_exit)
        self.decoder_thread.start()
        logging.info("Decoder thread started")

    def _on_decoder_exit(self) -> None:
        if not self._running:
            return
        self._restarts += 1
        delay = min(1.0 + (self._restarts * 0.3), 5.0)
        logging.warning(f"Decoder thread exited — attempting restart in {delay:.1f}s")
        QTimer.singleShot(int(delay * 1000), self._restart_decoder_safe)

    def _restart_decoder_safe(self) -> None:
        if self._running:
            try:
                self._start_decoder_thread()
            except Exception as e:
                logging.error(f"Decoder restart failed: {e}")

    def _poll_connection_state(self) -> None:
        now = time.time()
        age = now - CLIENT_STATE.get("last_heartbeat", 0)
        if age > 6 and CLIENT_STATE["connected"]:
            CLIENT_STATE["connected"], CLIENT_STATE["reconnecting"] = False, True
            logging.warning("Lost heartbeat from host")
        elif age <= 6 and CLIENT_STATE["reconnecting"]:
            CLIENT_STATE["connected"], CLIENT_STATE["reconnecting"] = True, False
            logging.info("Heartbeat restored")

    def _read_gpu_usage(self) -> str | None:
        if not HAVE_PYNVML:
            return None
        try:
            pynvml.nvmlInit()
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            return f"{util.gpu}% (NVENC)"
        except Exception:
            # NVML init failed (no NVIDIA GPU or driver) - try VAAPI
            pass

        try:
            for card in Path("/sys/class/drm").iterdir():
                busy_path = card / "device" / "gpu_busy_percent"
                if busy_path.exists():
                    val = busy_path.read_text().strip()
                    return f"{val}% (VAAPI)"
        except Exception:
            # sysfs read failed (permission/driver issue) - try intel_gpu_top
            pass

        try:
            cmd = ["timeout", "0.5", "intel_gpu_top", "-J"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            if '"Busy"' in out:
                j = json.loads(out)
                busy = j["engines"]["Render/3D/0"]["busy"]
                return f"{busy}% (iGPU)"
        except Exception:
            # intel_gpu_top not installed or failed - return N/A
            pass

        return "N/A"

    def _update_stats(self) -> None:
        try:
            cpu = self._proc.cpu_percent(interval=None)
            mem = self._proc.memory_info().rss / (1024 * 1024)
            gpu = self._read_gpu_usage()
            fps = getattr(self.video_widget, "_fps", 0.0)
            renderer_name = getattr(self.video_widget.renderer, "name", lambda: "Unknown")()
            device_info = getattr(self.video_widget.renderer, "device_path", None)
            backend = f"{renderer_name} ({Path(device_info).name})" if device_info else renderer_name

            base_title = "LinuxPlay"
            status = ""
            if not CLIENT_STATE["connected"]:
                status = " | RECONNECTING…"
            elif CLIENT_STATE["reconnecting"]:
                status = " | Weak Signal"

            new_title = (
                f"{base_title} — {backend} | FPS: {fps:.0f} | CPU: {cpu:.0f}% | RAM: {mem:.0f} MB | GPU: {gpu}{status}"
            )
            self.setWindowTitle(new_title)
        except Exception as e:
            logging.debug(f"Stats update failed: {e}")

    def _drain_clipboard_inbox(self) -> None:
        changed = False
        while not CLIPBOARD_INBOX.empty():
            text = CLIPBOARD_INBOX.get_nowait()
            cb = QApplication.clipboard()
            current = cb.text()
            if text and text != current:
                self.video_widget.ignore_clipboard = True
                cb.setText(text)
                self.video_widget.ignore_clipboard = False
                changed = True
        if changed:
            self.video_widget.last_clipboard = QApplication.clipboard().text()

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        if not urls:
            event.ignore()
            return

        files_to_upload = []
        for url in urls:
            path = url.toLocalFile()
            if Path(path).is_dir():
                for root, _, files in os.walk(path):
                    files_to_upload.extend(str(Path(root) / f) for f in files)
            elif Path(path).is_file():
                files_to_upload.append(path)

        for fpath in files_to_upload:
            threading.Thread(target=self.upload_file, args=(fpath,), daemon=True).start()
        event.acceptProposedAction()

    def upload_file(self, file_path) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.control_addr[0], UDP_FILE_PORT))
                filename = Path(file_path).name.encode("utf-8")
                header = len(filename).to_bytes(4, "big") + filename
                size = Path(file_path).stat().st_size
                header += size.to_bytes(8, "big")
                sock.sendall(header)
                with Path(file_path).open("rb") as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        sock.sendall(chunk)
            logging.info(f"Uploaded: {file_path}")
        except Exception as e:
            logging.error(f"Upload error for {file_path}: {e}")

    def send_control(self, msg) -> None:
        try:
            self.control_sock.sendto(msg.encode("utf-8"), self.control_addr)
        except Exception as e:
            logging.error(f"Control send error: {e}")

    def closeEvent(self, event) -> None:
        r"""Clean up resources on window close.

        Example commands:
            python.exe .\client.py --host_ip 192.168.1.128 --decoder h.264 --hwaccel auto --pin <CURRENT_PIN>
            python.exe .\client.py --host_ip 192.168.1.128 --decoder h.264 --hwaccel auto --audio disable

        Critical pattern: Always use timeouts on thread joins to prevent hangs.
        """
        self._running = False
        CLIENT_STATE["connected"] = False
        logging.info("Closing client window…")

        # Send goodbye message to host
        try:
            self.control_sock.sendto(b"GOODBYE", self.control_addr)
            logging.info("Sent GOODBYE to host")
        except Exception as e:
            logging.debug(f"GOODBYE send failed: {e}")

        # Stop Qt timers
        for timer_name in ("clip_timer", "status_timer", "stats_timer"):
            timer = getattr(self, timer_name, None)
            if timer:
                with contextlib.suppress(Exception):
                    timer.stop()

        # Stop decoder thread with timeout
        if hasattr(self, "decoder_thread"):
            try:
                self.decoder_thread.stop()
                if not self.decoder_thread.wait(2000):  # 2s timeout
                    logging.warning("Decoder thread did not stop cleanly")
            except Exception as e:
                logging.debug(f"Decoder cleanup error: {e}")

        # Stop gamepad thread
        if getattr(self, "_gp_thread", None):
            with contextlib.suppress(Exception):
                self._gp_thread.stop()
                # Thread is daemon, no need to join

        # Terminate audio process with timeout
        if audio_proc_manager.proc:
            try:
                audio_proc_manager.proc.terminate()
                try:
                    audio_proc_manager.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    logging.warning("ffplay did not terminate, forcing kill")
                    audio_proc_manager.proc.kill()
                    audio_proc_manager.proc.wait(timeout=1)
            except Exception as e:
                logging.error(f"ffplay term error: {e}")
            finally:
                audio_proc_manager.proc = None

        # Close control socket
        with contextlib.suppress(Exception):
            self.control_sock.close()

        event.accept()


def _setup_environment_vars() -> None:
    """Clean environment and set up OpenGL/Qt configuration.

    Performance rationale:
        - Removes MESA_*/LIBGL_* to prevent environment conflicts
        - Windows: Uses ANGLE (DirectX backend) for better compatibility
        - Linux: Uses desktop OpenGL with XCB-EGL for best performance
    """
    for var in list(os.environ):
        if var.startswith(("MESA_", "LIBGL_", "__GL_", "QT_LOGGING", "vblank_mode")):
            del os.environ[var]

    if IS_WINDOWS:
        os.environ["QT_OPENGL"] = "angle"
        os.environ["QT_ANGLE_PLATFORM"] = "d3d11"
    else:
        os.environ.setdefault("QT_OPENGL", "desktop")
        os.environ.setdefault("QT_XCB_GL_INTEGRATION", "xcb_egl")


def _setup_logging(debug: bool) -> None:
    """Configure logging handlers with console and file output.

    Args:
        debug: Enable DEBUG level logging (default: INFO)

    Output:
        - Console: stdout with colored timestamps
        - File: linuxplay_client.log (overwrite mode)
    """
    log_level = logging.DEBUG if debug else logging.INFO
    log_format = "%(asctime)s [%(levelname)s] %(message)s"
    log_datefmt = "%H:%M:%S"

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(log_level)
    console.setFormatter(logging.Formatter(log_format, datefmt=log_datefmt))
    root_logger.addHandler(console)

    try:
        file_handler = logging.FileHandler("linuxplay_client.log", mode="w", encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(log_format, datefmt=log_datefmt))
        root_logger.addHandler(file_handler)
    except Exception:
        # File logging setup failed (permission/disk full) - console logging still works
        pass


def _parse_monitor_info(monitor_info_str: str) -> list[tuple[int, int, int, int]]:
    """Parse monitor information from handshake response.

    Format: "1920x1080+0+0;1920x1080+1920+0" (width x height + offset_x + offset_y)

    Args:
        monitor_info_str: Semicolon-separated monitor specs

    Returns:
        List of (width, height, offset_x, offset_y) tuples

    Example:
        >>> _parse_monitor_info("1920x1080+0+0;1920x1080+1920+0")
        [(1920, 1080, 0, 0), (1920, 1080, 1920, 0)]
    """
    try:
        monitors = []
        parts = [p for p in monitor_info_str.split(";") if p]
        for part in parts:
            if "+" in part:
                res, ox, oy = part.split("+")
                w, h = map(int, res.split("x"))
                monitors.append((w, h, int(ox), int(oy)))
            else:
                w, h = map(int, part.split("x"))
                monitors.append((w, h, 0, 0))
        if not monitors:
            raise ValueError
        return monitors
    except Exception:
        logging.error("Monitor parse error, defaulting to %s", DEFAULT_RESOLUTION)
        w, h = map(int, DEFAULT_RESOLUTION.split("x"))
        return [(w, h, 0, 0)]


def _setup_decoder_opts(hwaccel: str, ultra: bool) -> dict[str, str]:
    """Configure PyAV decoder options for low-latency video decoding.

    Args:
        hwaccel: Hardware acceleration method ("vaapi", "cuda", "d3d11va", etc.)
        ultra: Enable ultra-low-latency mode (LAN only)

    Returns:
        Dictionary of FFmpeg/PyAV decoder options

    Ultra Mode Settings:
        - No buffering: fflags=nobuffer, flags=low_delay
        - Minimal probing: probesize=32, analyzeduration=0
        - Single thread: threads=1 (reduces latency)
        - Skip non-reference frames: skip_frame=noref
    """
    decoder_opts = {}
    if hwaccel != "cpu":
        decoder_opts["hwaccel"] = hwaccel
        if hwaccel == "vaapi":
            decoder_opts["hwaccel_device"] = "/dev/dri/renderD128"

    if ultra:
        decoder_opts.update(
            {
                "fflags": "nobuffer",
                "flags": "low_delay",
                "flags2": "+fast",
                "probesize": "32",
                "analyzeduration": "0",
                "rtbufsize": "512k",
                "threads": "1",
                "skip_frame": "noref",
            }
        )
    return decoder_opts


def _create_windows(args, monitors: list, decoder_opts: dict, ultra: bool) -> list:
    """Create MainWindow instances based on monitor selection."""
    windows = []
    if args.monitor.lower() == "all":
        for i, (w, h, ox, oy) in enumerate(monitors):
            win = MainWindow(
                decoder_opts,
                w,
                h,
                args.host_ip,
                DEFAULT_UDP_PORT + i,
                ox,
                oy,
                args.net if args.net != "auto" else "lan",
                ultra=ultra,
                gamepad=args.gamepad,
                gamepad_dev=args.gamepad_dev,
            )
            win.setWindowTitle(f"LinuxPlay — Monitor {i}")
            win.show()
            windows.append(win)
    else:
        try:
            idx = int(args.monitor)
        except Exception:
            idx = 0
        if idx < 0 or idx >= len(monitors):
            idx = 0
        w, h, ox, oy = monitors[idx]
        win = MainWindow(
            decoder_opts,
            w,
            h,
            args.host_ip,
            DEFAULT_UDP_PORT + idx,
            ox,
            oy,
            args.net if args.net != "auto" else "lan",
            ultra=ultra,
            gamepad=args.gamepad,
            gamepad_dev=args.gamepad_dev,
        )
        win.setWindowTitle(f"LinuxPlay — Monitor {idx}")
        win.show()
        windows.append(win)
    return windows


def main() -> None:
    p = argparse.ArgumentParser(description="LinuxPlay Client (Linux/Windows)")
    p.add_argument("--decoder", choices=["none", "h.264", "h.265"], default="none")
    p.add_argument("--host_ip", required=True)
    p.add_argument("--pin", default=None, help="6-digit host PIN (optional; will prompt if required)")
    p.add_argument("--audio", choices=["enable", "disable"], default="disable")
    p.add_argument("--monitor", default="0", help="Index or 'all'")
    p.add_argument("--hwaccel", choices=["auto", "cpu", "cuda", "qsv", "d3d11va", "dxva2", "vaapi"], default="auto")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--net", choices=["auto", "lan", "wifi"], default="auto")
    p.add_argument(
        "--ultra", action="store_true", help="Enable ultra-low-latency (LAN only). Auto-disabled on Wi-Fi/WAN."
    )
    p.add_argument("--gamepad", choices=["enable", "disable"], default="enable")
    p.add_argument("--gamepad_dev", default=None)
    args = p.parse_args()

    _setup_environment_vars()

    fmt = QSurfaceFormat()
    fmt.setSwapInterval(0)
    fmt.setSwapBehavior(QSurfaceFormat.SingleBuffer)
    QSurfaceFormat.setDefaultFormat(fmt)

    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
    try:
        ps = psutil.Process(os.getpid())
        ps.nice(-5)
    except Exception:
        # Process priority adjustment failed (insufficient permissions) - continue with default priority
        pass

    _setup_logging(args.debug)

    logging.info("────────────────────────────────────────────")
    logging.info("LinuxPlay Client starting up")
    logging.info(f"Python: {sys.version.split()[0]}, Platform: {sys.platform}")
    logging.info("────────────────────────────────────────────")

    app = QApplication(sys.argv)

    ok, host_info = tcp_handshake_client(args.host_ip, args.pin)
    if not ok or not host_info:
        _show_error("Handshake Failed", "Could not negotiate with host.")
        sys.exit(1)
    _host_encoder, monitor_info_str = host_info
    CLIENT_STATE["connected"] = True
    CLIENT_STATE["last_heartbeat"] = time.time()

    net_mode = args.net
    if net_mode == "auto":
        try:
            net_mode = detect_network_mode(args.host_ip)
        except Exception:
            net_mode = "lan"
    logging.info(f"Network mode: {net_mode}")

    ultra_active = args.ultra and (net_mode == "lan")
    if args.ultra and not ultra_active:
        logging.info("Ultra requested but disabled on %s; using safe buffering.", net_mode)
    elif ultra_active:
        logging.info(
            "Ultra mode enabled (LAN): minimal buffering, no B-frame reordering. "
            "For lowest latency, use H.264 codec (typically faster decode than H.265)."
        )

    monitors = _parse_monitor_info(monitor_info_str)

    chosen = args.hwaccel
    if chosen == "auto":
        chosen = choose_auto_hwaccel()
    logging.info(f"HW accel selected: {chosen}")

    decoder_opts = _setup_decoder_opts(chosen, ultra_active)
    _create_windows(args, monitors, decoder_opts, ultra_active)

    ret = app.exec_()

    try:
        if audio_proc_manager.proc:
            audio_proc_manager.proc.terminate()
    except Exception as e:
        logging.error("ffplay term error: %s", e)

    sys.exit(ret)


if __name__ == "__main__":
    main()
