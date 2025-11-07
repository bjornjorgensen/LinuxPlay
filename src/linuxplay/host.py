#!/usr/bin/env python3
import argparse
import atexit
import base64
import contextlib
import datetime
import json
import logging
import os
import platform as py_platform
import secrets
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from shutil import which
from tkinter import scrolledtext, ttk

import psutil


# Note: pynvml module provided by nvidia-ml-py package (official NVIDIA library)
# nvidia-ml-py is the maintained successor to deprecated pynvml package
try:
    import pynvml

    HAVE_PYNVML = True
except ImportError:
    HAVE_PYNVML = False


UDP_VIDEO_PORT = 5000
UDP_CONTROL_PORT = 7000
TCP_HANDSHAKE_PORT = 7001
UDP_CLIPBOARD_PORT = 7002
FILE_UPLOAD_PORT = 7003
UDP_HEARTBEAT_PORT = 7004
UDP_GAMEPAD_PORT = 7005
UDP_AUDIO_PORT = 6001

ACTIVE_CLIENT = None
ACTIVE_CLIENT_LOCK = threading.Lock()
PIN_LENGTH = 6
PIN_ROTATE_SECS = 30
ALLOW_SAME_IP_RECONNECT = True

# Hardware detection constants
INTEL_SKYLAKE_GEN = 6  # Minimum CPU generation for QSV support
INTEL_BROADWELL_GEN = 5
INTEL_HASWELL_GEN = 4
INTEL_KABYLAKE_GEN = 7
INTEL_FAMILY_CORE = 6  # Intel Core family ID in CPUID
INTEL_MODEL_KABYLAKE = 142  # 7th gen+
INTEL_MODEL_SKYLAKE = 94  # 6th gen
INTEL_MODEL_BROADWELL = 61  # 5th gen
INTEL_MODEL_HASWELL = 60  # 4th gen
MIN_CORES_FOR_AFFINITY = 4  # Systems with <= 4 cores use OS scheduler
MIN_P_CORES_REQUIRED = 4  # Minimum P-cores for heterogeneous CPU detection
MAX_P_CORES_FOR_ENCODING = 8  # Use up to 8 P-cores for encoding
P_CORE_FREQ_THRESHOLD = 0.9  # P-cores are within 10% of max frequency

# Auth and rate limiting
AUTH_ROTATION_THRESHOLD = 3  # Failed attempts before forcing PIN rotation
METRICS_LOG_INTERVAL_SECS = 60  # Log performance metrics every 60s
HEARTBEAT_RECONNECT_GRACE_SECS = 10  # Grace period after disconnect before timeout
HEARTBEAT_MAX_BACKOFF_SECS = 30.0  # Maximum cooldown between reconnect attempts
HEARTBEAT_BACKOFF_EXPONENT_MAX = 4  # Max exponent for exponential backoff (2^4 = 16x)
GAMEPAD_MIN_PACKET_SIZE = 5  # Minimum HID event packet size

# Protocol constants
MPEGTS_PACKET_SIZE = 188  # MPEG-TS packet size
TS_PACKETS_PER_UDP = 7  # 7 TS packets = 1316 bytes (fits in 1500 MTU)
CHALLENGE_SIZE_BYTES = 32  # Authentication challenge size
CSR_AUTH_MIN_PARTS = 3  # "AUTH CSR <pin>" requires 3 parts
CERT_AUTH_MIN_PARTS = 2  # "AUTH CERT:..." requires 2 parts
HELLO_MIN_PARTS = 2  # Legacy "HELLO" protocol
FFMPEG_OUTPUT_MIN_PARTS = 2  # Minimum parts when parsing ffmpeg output "d <name>"
PROTOCOL_CMD_AND_ARG = 2  # Minimum parts for commands with one argument
PACTL_OUTPUT_MIN_PARTS = 5  # pactl list output: index, name, driver, sample_spec, state
MOUSE_PKT_PARTS = 5  # MOUSE_PKT has 5 parts: cmd, type, bmask, x, y
MOUSE_PKT_TYPE_DOWN = 1  # Mouse button press
MOUSE_PKT_TYPE_UP = 3  # Mouse button release
CLIPBOARD_UPDATE_MIN_PARTS = 3  # CLIPBOARD_UPDATE CLIENT <data>

# Bitrate conversion constants
BITS_PER_KILOBIT = 1000
BITS_PER_MEGABIT = 1_000_000
BITS_PER_GIGABIT = 1_000_000_000

# Network overhead
IPV4_UDP_OVERHEAD = 28  # 20 (IP) + 8 (UDP)
IPV6_UDP_OVERHEAD = 48  # 40 (IPv6) + 8 (UDP)

# Performance thresholds
ENCODER_STARTUP_THRESHOLD_MS = 100  # Warn if encoder takes >100ms to start
HIGH_FPS_THRESHOLD = 90  # Adjust bitrate for high frame rates
STEREO_CHANNELS = 2  # Audio channel threshold
SURROUND_BITRATE_KBPS = 384  # Bitrate for >2 channels
STEREO_BITRATE_KBPS = 128  # Bitrate for stereo

# UDP socket buffer sizes (bytes)
UDP_SEND_BUFFER_SIZE = 2_097_152  # 2MB send buffer for video
UDP_RECV_BUFFER_SIZE = 524_288  # 512KB receive buffer for control/heartbeat
UDP_BUSY_POLL_USEC = 50  # SO_BUSY_POLL: 50µs for ultra-low latency (requires root or CAP_NET_ADMIN)

# Socket reuse flags for fast restarts
SOCKET_REUSE_FLAGS = socket.SO_REUSEADDR | (socket.SO_REUSEPORT if hasattr(socket, "SO_REUSEPORT") else 0)

DEFAULT_FPS = "30"
LEGACY_BITRATE = "8M"
DEFAULT_RES = "1920x1080"

IS_LINUX = py_platform.system() == "Linux"

HEARTBEAT_INTERVAL = 1.0
HEARTBEAT_TIMEOUT = 10.0
RECONNECT_COOLDOWN = 2.0

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

CA_CERT = "host_ca.pem"
CA_KEY = "host_ca.key"
TRUSTED_DB = "trusted_clients.json"


def _ensure_ca():
    if not HAVE_CRYPTO:
        logging.warning("[AUTH] cryptography not available; certificate auth disabled.")
        return False
    if Path(CA_CERT).exists() and Path(CA_KEY).exists():
        return True
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LinuxPlay Host CA")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        Path(CA_KEY).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        Path(CA_CERT).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        logging.info("[AUTH] Created new host CA (host_ca.pem / host_ca.key)")
        return True
    except Exception as e:
        logging.error("[AUTH] Failed to create CA: %s", e)
        return False


def _load_trust_db():
    db = {"trusted_clients": []}
    try:
        if Path(TRUSTED_DB).exists():
            with Path(TRUSTED_DB).open(encoding="utf-8") as f:
                db = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logging.warning("[AUTH] Failed to load trust database: %s", e)
    return db


def _save_trust_db(db):
    try:
        with Path(TRUSTED_DB).open("w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        return True
    except Exception:
        logging.error("[AUTH] Failed to write trust database")
        return False


def _trust_record_for(fp_hex: str, db: dict) -> dict | None:
    """Find trust record for fingerprint in database.

    Args:
        fp_hex: SHA256 fingerprint in hex format
        db: Trust database dictionary

    Returns:
        dict | None: Trust record or None if not found
    """
    for rec in db.get("trusted_clients", []):
        if rec.get("fingerprint") == fp_hex:
            return rec
    return None


def _verify_fingerprint_trusted(fp_hex: str) -> bool:
    """Verify if certificate fingerprint is in trusted database.

    Args:
        fp_hex: SHA256 fingerprint in hex format (uppercase)

    Returns:
        bool: True if fingerprint is trusted
    """
    db = _load_trust_db()
    rec = _trust_record_for(fp_hex, db)
    return (rec is not None) and (rec.get("status") == "trusted")


def _issue_client_cert(
    client_name: str = "linuxplay-client",
    export_hint_ip: str = "",
    csr_pem: bytes | None = None,
) -> tuple[bytes, bytes | None] | None:
    """
    Issue client certificate.

    NEW (secure): If csr_pem is provided, sign CSR (client generated keypair).
    OLD (legacy): If csr_pem is None, generate client keypair on server (INSECURE - deprecated).

    Args:
        client_name: Common name for certificate
        export_hint_ip: IP address hint for export directory naming
        csr_pem: PEM-encoded Certificate Signing Request (None = legacy mode)

    Returns:
        tuple[bytes, bytes | None]: (cert_pem, key_pem) or None on error
            - cert_pem: PEM-encoded certificate
            - key_pem: PEM-encoded private key (None in CSR mode)
    """
    if not _ensure_ca():
        return None

    try:
        with Path(CA_KEY).open("rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with Path(CA_CERT).open("rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        if csr_pem:
            # NEW SECURE PATH: Sign client's CSR
            logging.info("[AUTH] Signing client CSR (secure mode - client generated keypair)")
            csr = x509.load_pem_x509_csr(csr_pem, default_backend())
            public_key = csr.public_key()
            subject = csr.subject

            # Build certificate from CSR
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.UTC))
                .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1825))
                .sign(ca_key, hashes.SHA256())
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = None  # Client keeps private key

        else:
            # OLD LEGACY PATH: Server generates client keypair (INSECURE - deprecated)
            logging.warning("[AUTH] Generating client keypair on server (LEGACY MODE - INSECURE)")
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_name)])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.UTC))
                .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1825))
                .sign(ca_key, hashes.SHA256())
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )

        fp_hex = cert.fingerprint(hashes.SHA256()).hex().upper()

        db = _load_trust_db()
        if _trust_record_for(fp_hex, db) is None:
            now = datetime.datetime.now(datetime.UTC).isoformat() + "Z"
            db.setdefault("trusted_clients", []).append(
                {
                    "fingerprint": fp_hex,
                    "common_name": client_name,
                    "issued_on": now,
                    "trusted_since": now,
                    "last_seen": now,
                    "status": "trusted",
                    "cert_pem": cert_pem.decode("utf-8"),  # Save cert for signature verification
                }
            )
            _save_trust_db(db)

        stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
        export_dir = Path("issued_clients") / f"{stamp}_{export_hint_ip or 'client'}"
        export_dir.mkdir(parents=True, exist_ok=True)
        (export_dir / "client_cert.pem").write_bytes(cert_pem)
        if key_pem:  # Only write key in legacy mode
            (export_dir / "client_key.pem").write_bytes(key_pem)
        try:
            ca_pem = Path(CA_CERT).read_bytes()
            (export_dir / "host_ca.pem").write_bytes(ca_pem)
        except OSError as e:
            logging.warning("[AUTH] Failed to copy CA cert to export dir: %s", e)

        mode_str = "CSR-signed" if csr_pem else "server-generated (legacy)"
        logging.info(
            "[AUTH] Issued client cert '%s' (%s) (FP %s…), exported to %s",
            client_name,
            mode_str,
            fp_hex[:12],
            export_dir,
        )
        return {"fingerprint": fp_hex, "export_dir": export_dir, "cert_pem": cert_pem, "ca_pem": ca_pem}
    except Exception as e:
        logging.error("[AUTH] Issue client cert failed: %s", e)
        return None


def _marker_value() -> str:
    marker = os.environ.get("LINUXPLAY_MARKER", "LinuxPlayHost")
    sid = os.environ.get("LINUXPLAY_SID", "")
    return f"{marker}:{sid}" if sid else marker


def _generate_challenge() -> bytes:
    """Generate random 32-byte challenge for authentication."""
    import secrets

    return secrets.token_bytes(32)


def _verify_signature(cert_pem: bytes, challenge: bytes, signature: bytes) -> bool:
    """
    Verify client's signature of challenge using their certificate's public key.
    Returns True if signature is valid.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        # Load certificate and extract public key
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        public_key = cert.public_key()

        # Verify signature
        public_key.verify(
            signature,
            challenge,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        logging.warning("[AUTH] Signature verification failed: %s", e)
        return False


def _ffmpeg_base_cmd() -> list:
    """Return base FFmpeg command with error logging enabled.

    Uses -loglevel error to show only errors, not warnings.
    Stderr should be captured by caller for debugging.
    """
    return ["ffmpeg", "-hide_banner", "-loglevel", "error"]


def _marker_opt() -> list:
    """Return metadata marker for FFmpeg process identification."""
    return ["-metadata", f"comment={_marker_value()}"]


try:
    from pynput.keyboard import Controller as KeyCtl
    from pynput.keyboard import Key
    from pynput.mouse import Button
    from pynput.mouse import Controller as MouseCtl

    HAVE_PYNPUT = True
    _mouse = MouseCtl()
    _keys = KeyCtl()
except Exception:
    HAVE_PYNPUT = False

try:
    import pyperclip

    HAVE_PYPERCLIP = True
except Exception:
    HAVE_PYPERCLIP = False

try:
    from evdev import AbsInfo, UInput, ecodes

    HAVE_UINPUT = True
except Exception:
    HAVE_UINPUT = False


class HostState:
    def __init__(self):
        self.video_threads = []
        self.session_active = False
        self.authed_client_ip = None
        self.pin_code = None
        self.pin_expiry = 0.0
        self.pin_lock = threading.Lock()
        self.pin_paused = False
        self.audio_thread = None
        self.current_bitrate = LEGACY_BITRATE
        self.last_clipboard_content = ""
        self.ignore_clipboard_update = False
        self.should_terminate = False
        self.video_thread_lock = threading.Lock()
        self.clipboard_lock = threading.Lock()
        self.handshake_sock = None
        self.control_sock = None
        self.clipboard_listener_sock = None
        self.file_upload_sock = None
        self.heartbeat_sock = None
        self.last_pong_ts = 0.0
        self.last_disconnect_ts = 0.0
        self.client_ip = None
        self.monitors = []
        self.shutdown_lock = threading.Lock()
        self.shutdown_reason = None
        self.net_mode = "lan"
        self.starting_streams = False
        self.gamepad_thread = None
        # Rate limiting for PIN auth
        self.failed_auth_attempts = {}  # ip -> (count, first_attempt_time, lockout_until)
        self.auth_lock = threading.Lock()
        # Performance metrics
        self.perf_metrics = {
            "session_start": 0.0,
            "frames_encoded": 0,
            "bytes_sent": 0,
            "last_metric_log": 0.0,
            "encoder_restarts": 0,
            "heartbeat_timeouts": 0,
            "cpu_affinity_set": False,
            "numa_node": None,
        }


host_state = HostState()


def log_performance_metrics():
    """Log performance metrics at regular intervals for monitoring latency and health.

    Tracks:
    - Session uptime
    - CPU usage of encoder processes
    - Memory usage
    - Encoder restart count (indicates stability issues)
    - Network throughput (approximate)

    Called periodically from heartbeat thread to provide visibility into
    streaming performance without impacting latency.
    """
    now = time.time()
    metrics = host_state.perf_metrics

    # Log every 60 seconds
    if now - metrics["last_metric_log"] < METRICS_LOG_INTERVAL_SECS:
        return

    metrics["last_metric_log"] = now

    if not host_state.session_active:
        return

    uptime = now - metrics["session_start"] if metrics["session_start"] > 0 else 0

    # Collect CPU and memory stats for encoder processes
    total_cpu = 0.0
    total_mem_mb = 0.0
    process_count = 0

    with host_state.video_thread_lock:
        for thread in host_state.video_threads:
            if thread.process and thread.process.poll() is None:
                try:
                    ps = psutil.Process(thread.process.pid)
                    total_cpu += ps.cpu_percent(interval=0.1)
                    total_mem_mb += ps.memory_info().rss / (1024 * 1024)
                    process_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

    logging.info(
        f"[PERF] Uptime: {uptime:.1f}s | Encoders: {process_count} "
        f"| CPU: {total_cpu:.1f}% | Mem: {total_mem_mb:.0f}MB "
        f"| Restarts: {metrics['encoder_restarts']} "
        f"| HB Timeouts: {metrics['heartbeat_timeouts']} "
        f"| Net: {host_state.net_mode.upper()} "
        f"| NUMA: {metrics['numa_node'] if metrics['numa_node'] is not None else 'N/A'}"
    )


class HostArgsManager:
    """Manages the host arguments to avoid global state."""

    args = None


host_args_manager = HostArgsManager()


def _map_nvenc_tune(tune: str) -> str:
    t = (tune or "").strip().lower()
    if not t or t in ("auto", "default", "none"):
        return ""

    alias_map = {
        "ull": "ull",
        "ultra-low-latency": "ull",
        "ultra_low_latency": "ull",
        "zerolatency": "ull",
        "realtime": "ull",
        "low-latency": "ll",
        "low_latency": "ll",
        "ll": "ll",
        "hq": "hq",
        "high-quality": "hq",
        "high_quality": "hq",
        "hp": "hp",
        "high-performance": "hp",
        "high_performance": "hp",
        "performance": "hp",
        "lossless": "lossless",
        "lossless-highperf": "losslesshp",
        "lossless_highperf": "losslesshp",
        "blu-ray": "bd",
        "bluray": "bd",
    }

    mapped = alias_map.get(t)
    if mapped:
        return mapped

    logging.warning("Unrecognized NVENC tune '%s' — passing through as-is.", t)
    return t


def _vaapi_fmt_for_pix_fmt(pix_fmt: str, codec: str) -> str:
    pf = (pix_fmt or "").strip().lower()

    valid_vaapi_fmts = {
        "nv12",
        "yuv420p",
        "yuyv422",
        "uyvy422",
        "yuv422p",
        "yuv444p",
        "rgb0",
        "bgr0",
        "rgba",
        "bgra",
        "p010",
        "p010le",
        "yuv420p10",
        "yuv420p10le",
        "yuv422p10",
        "yuv422p10le",
        "yuv444p10",
        "yuv444p10le",
        "yuv444p12le",
        "yuv444p16le",
    }

    if pf in valid_vaapi_fmts:
        logging.info("Using requested VAAPI pix_fmt '%s' for codec %s.", pf, codec)
        return pf

    if pf in ("yuv420", "420p"):
        return "yuv420p"
    if pf in ("yuv420p10bit", "yuv420p10b"):
        return "yuv420p10le"
    if pf in ("yuv444", "444p"):
        return "yuv444p"

    logging.warning("Unrecognized pix_fmt '%s' — falling back to 'nv12'.", pf)
    return "nv12"


def trigger_shutdown(reason: str):
    with host_state.shutdown_lock:
        if host_state.should_terminate:
            return
        host_state.should_terminate = True
        host_state.shutdown_reason = reason
        logging.critical("FATAL/STOP: %s -- stopping all streams and listeners.", reason)

        for s in (
            host_state.handshake_sock,
            host_state.control_sock,
            host_state.clipboard_listener_sock,
            host_state.file_upload_sock,
        ):
            if s:
                with contextlib.suppress(Exception):
                    s.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(Exception):
                    s.close()

        set_status(f"Stopping… ({reason})")


def stop_all():
    host_state.should_terminate = True

    with host_state.video_thread_lock:
        for thread in host_state.video_threads:
            thread.stop()
            thread.join(timeout=2)
        host_state.video_threads.clear()

    if host_state.audio_thread:
        host_state.audio_thread.stop()
        host_state.audio_thread.join(timeout=2)
        host_state.audio_thread = None
    if host_state.gamepad_thread:
        try:
            host_state.gamepad_thread.stop()
            host_state.gamepad_thread.join(timeout=2)
        except (RuntimeError, AttributeError) as e:
            logging.debug("[GAMEPAD] Thread cleanup error: %s", e)
        host_state.gamepad_thread = None
    for s in (
        host_state.handshake_sock,
        host_state.control_sock,
        host_state.clipboard_listener_sock,
        host_state.file_upload_sock,
    ):
        if s:
            with contextlib.suppress(Exception):
                s.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(Exception):
                s.close()

    host_state.starting_streams = False


def stop_streams_only():
    with host_state.video_thread_lock:
        if host_state.video_threads:
            logging.info("Stopping active video streams...")
            for t in host_state.video_threads:
                with contextlib.suppress(Exception):
                    t.stop()
                    t.join(timeout=2)
            host_state.video_threads.clear()

        if host_state.audio_thread:
            try:
                host_state.audio_thread.stop()
                host_state.audio_thread.join(timeout=2)
            except Exception as e:
                logging.debug(f"Error stopping audio thread: {e}")
            host_state.audio_thread = None

        host_state.starting_streams = False
        host_state.last_disconnect_ts = time.time()
        logging.info("All streams stopped and cooldown set.")


def cleanup():
    stop_all()


atexit.register(cleanup)


def _gen_pin(length: int = PIN_LENGTH) -> str:
    """Generate random numeric PIN code.

    Args:
        length: Number of digits (default: PIN_LENGTH)

    Returns:
        str: Zero-padded PIN code
    """
    n = secrets.randbelow(10**length)
    return f"{n:0{length}d}"


# Rate limiting constants
MAX_AUTH_ATTEMPTS = 5
AUTH_LOCKOUT_DURATION = 300  # 5 minutes
AUTH_WINDOW = 60  # Track attempts within 60 seconds


def _check_rate_limit(peer_ip: str) -> tuple[bool, str]:
    """Check if IP is rate limited. Returns (is_allowed, reason)."""
    now = time.time()

    # Fast path: if IP not tracked, allow immediately
    if peer_ip not in host_state.failed_auth_attempts:
        return (True, "")

    with host_state.auth_lock:
        if peer_ip not in host_state.failed_auth_attempts:
            return (True, "")

        count, first_attempt, lockout_until = host_state.failed_auth_attempts[peer_ip]

        # Check if still in lockout period
        if lockout_until and now < lockout_until:
            remaining = int(lockout_until - now)
            return (False, f"Rate limited. Try again in {remaining}s")

        # Reset if outside time window
        if now - first_attempt > AUTH_WINDOW:
            del host_state.failed_auth_attempts[peer_ip]
            return (True, "")

        # Check if exceeded max attempts in window
        if count >= MAX_AUTH_ATTEMPTS:
            # Apply lockout
            lockout_until = now + AUTH_LOCKOUT_DURATION
            host_state.failed_auth_attempts[peer_ip] = (count, first_attempt, lockout_until)
            return (False, f"Too many failed attempts. Locked out for {AUTH_LOCKOUT_DURATION}s")

        return (True, "")


def _record_failed_auth(peer_ip: str):
    """Record a failed authentication attempt."""
    now = time.time()

    with host_state.auth_lock:
        if peer_ip in host_state.failed_auth_attempts:
            count, first_attempt, lockout_until = host_state.failed_auth_attempts[peer_ip]
            # Reset if outside window
            if now - first_attempt > AUTH_WINDOW:
                host_state.failed_auth_attempts[peer_ip] = (1, now, None)
            else:
                host_state.failed_auth_attempts[peer_ip] = (count + 1, first_attempt, lockout_until)
        else:
            host_state.failed_auth_attempts[peer_ip] = (1, now, None)

        count, _, _ = host_state.failed_auth_attempts[peer_ip]
        logging.warning(f"[AUTH] Failed attempt {count}/{MAX_AUTH_ATTEMPTS} from {peer_ip}")

        # Force PIN rotation after multiple failed attempts
        if count >= AUTH_ROTATION_THRESHOLD:
            logging.warning(f"[AUTH] Multiple failed attempts from {peer_ip} - rotating PIN")
            pin_rotate_if_needed(force=True)


def _clear_failed_auth(peer_ip: str) -> None:
    """Clear failed auth attempts for IP after successful auth."""
    with host_state.auth_lock:
        if peer_ip in host_state.failed_auth_attempts:
            del host_state.failed_auth_attempts[peer_ip]


def _optimize_udp_socket(sock: socket.socket, send_buf: bool = True, recv_buf: bool = True) -> None:
    """Apply performance optimizations to UDP socket.

    Optimizations:
    - SO_REUSEADDR for fast restart
    - SO_REUSEPORT for load balancing (if available)
    - Large send/receive buffers (reduces packet loss)
    - SO_BUSY_POLL for ultra-low latency (requires privilege)

    Args:
        sock: UDP socket to optimize
        send_buf: Apply send buffer optimization
        recv_buf: Apply receive buffer optimization
    """
    try:
        # Enable address reuse for fast restart
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Enable port reuse if available (Linux 3.9+, improves load balancing)
        if hasattr(socket, "SO_REUSEPORT"):
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # Optimize buffers to reduce packet loss
        if recv_buf:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
        if send_buf:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)

        # SO_BUSY_POLL for sub-100µs network latency (Linux only, requires privilege)
        if IS_LINUX:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, 46, UDP_BUSY_POLL_USEC)  # SO_BUSY_POLL=46
                logging.debug(f"UDP socket optimized with SO_BUSY_POLL={UDP_BUSY_POLL_USEC}µs")
    except OSError as e:
        logging.debug(f"Socket optimization failed (non-critical): {e}")


def pin_rotate_if_needed(force: bool = False) -> None:
    """Rotate PIN if expired or forced. Thread-safe."""
    now = time.time()

    # Fast path: check if rotation needed before acquiring lock
    if not force and host_state.pin_code and now < host_state.pin_expiry:
        return

    with host_state.pin_lock:
        # Re-check under lock (double-checked locking pattern)
        if force or not host_state.pin_code or now >= host_state.pin_expiry:
            # Only skip rotation if session is active AND not forced
            if host_state.session_active and not force:
                return

            host_state.pin_code = _gen_pin()
            host_state.pin_expiry = now + PIN_ROTATE_SECS
            logging.info("[AUTH] New PIN: %s (valid %ds)", host_state.pin_code, PIN_ROTATE_SECS)
            with contextlib.suppress(Exception):
                set_status(f"Waiting for PIN: {host_state.pin_code}")


def pin_manager_thread():
    while not host_state.should_terminate:
        if not host_state.session_active:
            pin_rotate_if_needed()
        time.sleep(1)


# Cache for hardware detection to avoid repeated expensive calls
_HW_CACHE = {}


def _clear_hw_cache():
    """Clear hardware detection cache. Used in tests and when hardware changes."""
    _HW_CACHE.clear()


def has_nvidia() -> bool:
    """Check if NVIDIA GPU is present and functional.

    Detection methods:
    1. pynvml library (preferred) - direct GPU query
    2. nvidia-smi command - fallback if pynvml unavailable

    Returns:
        bool: True if NVIDIA GPU detected and accessible
    """
    if "nvidia" not in _HW_CACHE:
        detected = False

        # Method 1: pynvml (fastest, most reliable)
        if HAVE_PYNVML:
            try:
                pynvml.nvmlInit()
                count = pynvml.nvmlDeviceGetCount()
                pynvml.nvmlShutdown()
                detected = count > 0
                if detected:
                    logging.debug(f"NVIDIA GPU detected via pynvml: {count} device(s)")
            except Exception as e:
                logging.debug(f"pynvml detection failed: {e}")

        # Method 2: nvidia-smi (fallback)
        if not detected:
            detected = which("nvidia-smi") is not None
            if detected:
                logging.debug("NVIDIA GPU detected via nvidia-smi")

        _HW_CACHE["nvidia"] = detected
    return _HW_CACHE["nvidia"]


def is_intel_cpu():
    """Check if CPU is Intel."""
    if "intel_cpu" not in _HW_CACHE:
        try:
            if IS_LINUX:
                _HW_CACHE["intel_cpu"] = "GenuineIntel" in Path("/proc/cpuinfo").read_text()
            else:
                p = (py_platform.processor() or "").lower()
                _HW_CACHE["intel_cpu"] = "intel" in p or "intel" in py_platform.platform().lower()
        except Exception:
            _HW_CACHE["intel_cpu"] = False
    return _HW_CACHE["intel_cpu"]


def get_intel_cpu_generation() -> int | None:
    """Get Intel CPU generation for QSV compatibility check.

    QSV requires Skylake (6th gen) or newer for low-latency streaming.
    Pre-Skylake CPUs (Haswell, Broadwell) have QSV but lack critical features.

    Returns:
        int: CPU generation (4-7+), or None if not Intel/unable to detect

    Generation mapping:
        - 4: Haswell (partial QSV, lacks low-latency)
        - 5: Broadwell (partial QSV, lacks low-latency)
        - 6: Skylake (full QSV with low-latency modes) ✅
        - 7+: Kaby Lake and newer (recommended) ✅
    """
    if "intel_generation" not in _HW_CACHE:
        if not is_intel_cpu():
            _HW_CACHE["intel_generation"] = None
            return None

        try:
            if IS_LINUX and Path("/proc/cpuinfo").exists():
                cpuinfo = Path("/proc/cpuinfo").read_text()
                import re

                # Intel microarchitecture detection via CPU family/model
                family_match = re.search(r"cpu family\s*:\s*(\d+)", cpuinfo)
                model_match = re.search(r"^model\s*:\s*(\d+)", cpuinfo, re.MULTILINE)

                if family_match and model_match:
                    family = int(family_match.group(1))
                    model = int(model_match.group(1))

                    if family == INTEL_FAMILY_CORE:
                        # Simplified model-to-generation mapping
                        # Full mapping: https://en.wikichip.org/wiki/intel/cpuid
                        if model >= INTEL_MODEL_KABYLAKE:  # Kaby Lake+ (7th gen+)
                            gen = INTEL_KABYLAKE_GEN
                        elif model >= INTEL_MODEL_SKYLAKE:  # Skylake (6th gen)
                            gen = INTEL_SKYLAKE_GEN
                        elif model >= INTEL_MODEL_BROADWELL:  # Broadwell (5th gen)
                            gen = INTEL_BROADWELL_GEN
                        elif model >= INTEL_MODEL_HASWELL:  # Haswell (4th gen)
                            gen = INTEL_HASWELL_GEN
                        else:
                            gen = None  # Older/unknown

                        _HW_CACHE["intel_generation"] = gen
                        logging.debug(f"Intel CPU generation detected: {gen} (family={family}, model={model})")
                        return gen
        except Exception as e:
            logging.debug(f"Intel CPU generation detection failed: {e}")

        _HW_CACHE["intel_generation"] = None

    return _HW_CACHE["intel_generation"]


def has_vaapi():
    """Check if VAAPI hardware acceleration is available.

    Returns True if:
    1. Linux system
    2. /dev/dri/renderD128 exists (Intel/AMD GPU render node)
    3. (Optionally) User has permission to access device
    """
    if "vaapi" not in _HW_CACHE:
        if not IS_LINUX:
            _HW_CACHE["vaapi"] = False
            return False

        device_path = Path("/dev/dri/renderD128")
        if not device_path.exists():
            _HW_CACHE["vaapi"] = False
            return False

        # Check if we can actually access the device
        try:
            # Try to open device (read-only check)
            with device_path.open("rb"):
                # Just check permissions, don't read
                pass
            _HW_CACHE["vaapi"] = True
        except PermissionError:
            # Device exists but not accessible (not in video group)
            logging.warning(
                "VAAPI device /dev/dri/renderD128 exists but not accessible. "
                "Add user to 'video' group: sudo usermod -aG video $USER"
            )
            _HW_CACHE["vaapi"] = False
        except Exception as e:
            logging.debug(f"VAAPI device check failed: {e}")
            _HW_CACHE["vaapi"] = False

    return _HW_CACHE["vaapi"]


def ffmpeg_has_encoder(name: str) -> bool:
    """Check if FFmpeg has specific encoder (with timeout and better error handling)."""
    cache_key = f"encoder_{name}"
    if cache_key not in _HW_CACHE:
        try:
            out = subprocess.check_output(
                ["ffmpeg", "-hide_banner", "-encoders"],
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                timeout=5,
            ).lower()
            _HW_CACHE[cache_key] = name.lower() in out
        except subprocess.TimeoutExpired:
            logging.warning(f"FFmpeg encoder check timed out for '{name}'")
            _HW_CACHE[cache_key] = False
        except FileNotFoundError:
            logging.error("FFmpeg not found in PATH")
            _HW_CACHE[cache_key] = False
        except subprocess.CalledProcessError as e:
            logging.debug(f"FFmpeg encoder check failed for '{name}': exit code {e.returncode}")
            _HW_CACHE[cache_key] = False
        except Exception as e:
            logging.warning(f"Unexpected error checking encoder '{name}': {e}")
            _HW_CACHE[cache_key] = False
    return _HW_CACHE[cache_key]


def ffmpeg_has_demuxer(name: str) -> bool:
    """Check if FFmpeg has specific demuxer (with timeout)."""
    try:
        out = subprocess.check_output(
            ["ffmpeg", "-hide_banner", "-demuxers"],
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=5,
        ).lower()
        # Parse output: "D <name> <description>"
        for line in out.splitlines():
            stripped_line = line.strip().lower()
            if stripped_line.startswith(("d ", " d ")):
                parts = stripped_line.split()
                if len(parts) >= FFMPEG_OUTPUT_MIN_PARTS and parts[1] == name.lower():
                    return True
        return False
    except subprocess.TimeoutExpired:
        logging.warning(f"FFmpeg demuxer check timed out for '{name}'")
        return False
    except FileNotFoundError:
        logging.error("FFmpeg not found in PATH")
        return False
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        logging.debug(f"Demuxer check for '{name}' failed: {e}")
        return False


def ffmpeg_has_device(name: str) -> bool:
    """Check if FFmpeg has specific input device (with timeout)."""
    try:
        out = subprocess.check_output(
            ["ffmpeg", "-hide_banner", "-devices"],
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=5,
        ).lower()
        # Parse output: "D <name> <description>"
        for line in out.splitlines():
            stripped_line = line.strip().lower()
            if stripped_line.startswith(("d ", " d ")):
                parts = stripped_line.split()
                if len(parts) >= FFMPEG_OUTPUT_MIN_PARTS and parts[1] == name.lower():
                    return True
        return False
    except subprocess.TimeoutExpired:
        logging.warning(f"FFmpeg device check timed out for '{name}'")
        return False
    except FileNotFoundError:
        logging.error("FFmpeg not found in PATH")
        return False
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        logging.debug(f"Device check for '{name}' failed: {e}")
        return False


def ffmpeg_hwaccels() -> set:
    """Probe FFmpeg for available hardware accelerators.
    Returns a set of hwaccel names (e.g., 'qsv', 'cuda', 'vaapi').

    NOTE: Presence of 'qsv' in this set does NOT guarantee encoder support.
    Intel QSV requires Skylake+ CPU (6th gen or later) and specific SKUs with
    functioning iGPU. Always verify with ffmpeg_has_encoder() AND test_qsv_encode()
    before using QSV encoders in production.

    Common QSV failure modes:
    - iGPU disabled in BIOS/UEFI
    - Pre-Skylake CPUs (QSV exists but lacks low-latency modes)
    - Missing i915 kernel driver
    - Incorrect /dev/dri/renderD128 permissions
    """
    if "hwaccels" not in _HW_CACHE:
        try:
            out = subprocess.check_output(
                ["ffmpeg", "-hide_banner", "-hwaccels"], stderr=subprocess.STDOUT, universal_newlines=True, timeout=5
            )
            hwaccels = set()
            for raw_line in out.splitlines():
                line = raw_line.strip().lower()
                if line and not line.startswith("hardware"):
                    hwaccels.add(line)
            _HW_CACHE["hwaccels"] = hwaccels
            logging.debug(f"Detected hardware accelerators: {hwaccels}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.debug(f"Hardware accelerator detection failed: {e}")
            _HW_CACHE["hwaccels"] = set()
        except Exception as e:
            logging.warning(f"Unexpected error detecting hwaccels: {e}")
            _HW_CACHE["hwaccels"] = set()
    return _HW_CACHE["hwaccels"]


def test_qsv_encode() -> bool:
    """Test if QSV encoder actually works (not just present).

    QSV detection is notoriously unreliable. This function:
    1. Checks Intel CPU generation (requires Skylake/6th gen+)
    2. Verifies 'qsv' in ffmpeg hwaccels
    3. Attempts real encode to confirm functionality

    Returns True if QSV encoding succeeds, False otherwise.

    Common failures:
    - Pre-Skylake CPUs: QSV exists but lacks low-latency modes
    - F-series CPUs (e.g., i9-12900KF): No iGPU hardware
    - iGPU disabled in BIOS
    - Missing i915 driver or /dev/dri permissions
    """
    if "qsv_encode_works" not in _HW_CACHE:
        # First check: Intel CPU generation
        cpu_gen = get_intel_cpu_generation()
        if cpu_gen is not None and cpu_gen < INTEL_SKYLAKE_GEN:
            logging.info(
                f"Intel CPU generation {cpu_gen} detected. QSV requires Skylake ({INTEL_SKYLAKE_GEN}th gen) or newer. "
                "Pre-Skylake QSV lacks low-latency modes needed for streaming."
            )
            _HW_CACHE["qsv_encode_works"] = False
            return False

        # Second check: hwaccels reports QSV
        if "qsv" not in ffmpeg_hwaccels():
            logging.debug("QSV not in ffmpeg -hwaccels output")
            _HW_CACHE["qsv_encode_works"] = False
            return False

        # Third check: actual encode test
        try:
            cmd = [
                "ffmpeg",
                "-hide_banner",
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=0.1:size=320x240:rate=1",
                "-c:v",
                "h264_qsv",
                "-frames:v",
                "1",
                "-f",
                "null",
                "-",
            ]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5, check=False)
            works = result.returncode == 0

            if not works:
                stderr = result.stderr.decode("utf-8", errors="ignore") if result.stderr else ""
                logging.warning(
                    f"QSV encoder test failed (Intel gen {cpu_gen or 'unknown'}). "
                    "Common causes: iGPU disabled in BIOS, F-series CPU without iGPU, "
                    "missing i915 driver, or /dev/dri/renderD128 permissions. "
                    f"FFmpeg error: {stderr[:200]}"
                )
            else:
                logging.info(f"QSV encoder validated (Intel gen {cpu_gen or 'unknown'})")

            _HW_CACHE["qsv_encode_works"] = works
        except Exception as e:
            logging.debug(f"QSV encoder test exception: {e}")
            _HW_CACHE["qsv_encode_works"] = False

    return _HW_CACHE["qsv_encode_works"]


def _detect_cpu_info(report: dict) -> None:
    """Detect CPU information and populate report."""
    try:
        logical_cores = psutil.cpu_count(logical=True)
        physical_cores = psutil.cpu_count(logical=False) or logical_cores
        report["cpu"]["logical_cores"] = logical_cores
        report["cpu"]["physical_cores"] = physical_cores
        report["cpu"]["hyperthreading"] = logical_cores > physical_cores
        report["cpu"]["is_intel"] = is_intel_cpu()
        _detect_heterogeneous_cpu(report)
    except Exception as e:
        report["warnings"].append(f"CPU detection failed: {e}")


def _detect_heterogeneous_cpu(report: dict) -> None:
    """Detect P-cores/E-cores on heterogeneous CPUs."""
    if not IS_LINUX or not Path("/sys/devices/system/cpu").exists():
        return

    freqs = []
    for cpu_dir in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*")):
        max_freq_file = cpu_dir / "cpufreq/cpuinfo_max_freq"
        if max_freq_file.exists():
            freq = int(max_freq_file.read_text().strip())
            cpu_num = int(cpu_dir.name.replace("cpu", ""))
            freqs.append((cpu_num, freq))

    if not freqs:
        return

    freqs.sort(key=lambda x: x[1], reverse=True)
    max_freq = freqs[0][1]
    p_cores = [cpu for cpu, freq in freqs if freq >= max_freq * 0.9]
    e_cores = [cpu for cpu, freq in freqs if freq < max_freq * 0.9]

    if p_cores and e_cores:
        report["cpu"]["heterogeneous"] = True
        report["cpu"]["p_cores"] = p_cores
        report["cpu"]["e_cores"] = e_cores
        report["warnings"].append(
            f"Heterogeneous CPU detected: {len(p_cores)} P-cores, {len(e_cores)} E-cores. "
            "P-cores will be preferred for streaming."
        )
    else:
        report["cpu"]["heterogeneous"] = False


def _detect_gpu_info(report: dict) -> None:
    """Detect GPU information and populate report."""
    report["gpu"]["nvidia"] = has_nvidia()
    report["gpu"]["vaapi_available"] = has_vaapi()

    if HAVE_PYNVML and report["gpu"]["nvidia"]:
        try:
            pynvml.nvmlInit()
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            name = pynvml.nvmlDeviceGetName(handle)
            if isinstance(name, bytes):
                name = name.decode("utf-8")
            report["gpu"]["nvidia_model"] = name
            pynvml.nvmlShutdown()
        except Exception as e:
            report["warnings"].append(f"NVML GPU query failed: {e}")


def _detect_numa_info(report: dict) -> None:
    """Detect NUMA topology and populate report."""
    numa_node = get_numa_node_for_gpu()
    if numa_node is not None:
        report["numa"]["gpu_node"] = numa_node
        report["numa"]["multi_socket"] = True
        report["warnings"].append(
            f"Multi-socket system detected. GPU on NUMA node {numa_node}. "
            "Streaming threads will be pinned to this node for lowest latency."
        )
    else:
        report["numa"]["multi_socket"] = False


def _detect_encoder_info(report: dict) -> None:
    """Detect available encoders and populate report."""
    encoders_to_check = [
        ("h264_nvenc", "NVENC H.264"),
        ("hevc_nvenc", "NVENC H.265"),
        ("h264_qsv", "QSV H.264"),
        ("hevc_qsv", "QSV H.265"),
        ("h264_vaapi", "VAAPI H.264"),
        ("hevc_vaapi", "VAAPI H.265"),
        ("libx264", "CPU H.264"),
        ("libx265", "CPU H.265"),
    ]

    for enc_name, display_name in encoders_to_check:
        available = ffmpeg_has_encoder(enc_name)
        report["encoders"][display_name] = {"available": available}

        if "qsv" in enc_name and available:
            works = test_qsv_encode()
            report["encoders"][display_name]["tested"] = works
            if not works:
                report["warnings"].append(
                    f"{display_name} encoder present but fails test. "
                    "Check: iGPU enabled in BIOS, i915 driver loaded, /dev/dri permissions."
                )


def generate_hardware_report() -> dict[str, any]:
    """Generate comprehensive hardware detection report.

    Returns detailed system information for debugging and optimization.
    Useful for troubleshooting hardware encoder issues and verifying
    latency optimizations are applied correctly.

    Returns:
        Dictionary with keys:
        - platform: OS and architecture info
        - cpu: CPU vendor, cores (logical/physical), P-core detection
        - gpu: GPU vendor, NUMA node, driver info
        - encoders: Available hardware encoders and test results
        - accelerators: FFmpeg hardware accelerators
        - numa: NUMA topology and GPU affinity
        - affinity: Recommended CPU affinity for streaming
        - warnings: List of potential issues or recommendations
    """
    report = {
        "platform": {
            "os": py_platform.system(),
            "arch": py_platform.machine(),
            "is_linux": IS_LINUX,
        },
        "cpu": {},
        "gpu": {},
        "encoders": {},
        "accelerators": set(),
        "numa": {},
        "affinity": [],
        "warnings": [],
    }

    _detect_cpu_info(report)
    _detect_gpu_info(report)
    _detect_numa_info(report)
    report["accelerators"] = ffmpeg_hwaccels()
    _detect_encoder_info(report)
    report["affinity"] = get_optimal_cpu_affinity()

    has_hw_encoder = any(
        e["available"] for name, e in report["encoders"].items() if "NVENC" in name or "QSV" in name or "VAAPI" in name
    )
    if not has_hw_encoder:
        report["warnings"].append(
            "No hardware encoders detected! CPU encoding will cause high CPU usage and latency. "
            "Install NVIDIA drivers (NVENC), enable Intel iGPU (QSV), or configure VAAPI."
        )

    if report["cpu"].get("hyperthreading") and not report["affinity"]:
        report["warnings"].append(
            "Hyperthreading detected but CPU affinity not set. Consider pinning to physical cores for lower latency."
        )

    # Latency optimization recommendations
    if report.get("encoders", {}).get("NVENC H.264", {}).get("available"):
        report["warnings"].append(
            "OPTIMIZATION: NVENC H.264 detected. For lowest latency, use: "
            "--encoder h.264 --hwenc nvenc --tune ull --preset llhp"
        )

    if report["cpu"].get("heterogeneous"):
        p_count = len(report["cpu"].get("p_cores", []))
        report["warnings"].append(
            f"OPTIMIZATION: Heterogeneous CPU detected with {p_count} P-cores. "
            "Streaming threads will be automatically pinned to P-cores for best performance."
        )

    if report["numa"].get("gpu_node") is not None:
        numa_node = report["numa"]["gpu_node"]
        report["warnings"].append(
            f"OPTIMIZATION: Multi-socket system (GPU on NUMA node {numa_node}). "
            "Threads will be automatically pinned to GPU's NUMA node for 2x lower memory latency."
        )

    return report


def get_optimal_cpu_affinity() -> list[int]:
    """Get optimal CPU cores for latency-critical streaming tasks.

    Returns physical cores, avoiding hyperthreading and preferring
    performance cores on heterogeneous CPUs (Intel 12th gen+).

    Uses psutil.cpu_count(logical=False) to get actual physical cores,
    not logical cores (which include hyperthreading). On 8c/16t system,
    returns [0-7] not [0-15].

    For heterogeneous CPUs (P-cores + E-cores), prefers P-cores by
    reading CPU frequencies from /sys/devices/system/cpu/cpuN/cpufreq.
    """
    try:
        # Get physical cores only (no hyperthreading)
        # CRITICAL: logical=False returns physical count, not logical count
        physical_count = psutil.cpu_count(logical=False)
        if not physical_count:
            physical_count = psutil.cpu_count()

        if not physical_count or physical_count <= MIN_CORES_FOR_AFFINITY:
            return []  # Let OS scheduler handle small systems

        # On Linux, check for heterogeneous CPUs (P-cores + E-cores)
        if IS_LINUX and Path("/sys/devices/system/cpu").exists():
            try:
                # P-cores typically have higher max frequency
                # Read CPU frequencies to identify performance cores
                freqs = []
                for cpu_dir in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*")):
                    max_freq_file = cpu_dir / "cpufreq/cpuinfo_max_freq"
                    if max_freq_file.exists():
                        freq = int(max_freq_file.read_text().strip())
                        cpu_num = int(cpu_dir.name.replace("cpu", ""))
                        freqs.append((cpu_num, freq))

                if freqs:
                    # Sort by frequency (descending) and take top cores
                    freqs.sort(key=lambda x: x[1], reverse=True)
                    max_freq = freqs[0][1]
                    # P-cores are typically within 10% of max frequency
                    p_cores = [cpu for cpu, freq in freqs if freq >= max_freq * P_CORE_FREQ_THRESHOLD]
                    if len(p_cores) >= MIN_P_CORES_REQUIRED:
                        logging.debug(f"Detected P-cores: {p_cores[:MAX_P_CORES_FOR_ENCODING]}")
                        return p_cores[:MAX_P_CORES_FOR_ENCODING]  # Use up to 8 P-cores
            except Exception as e:
                logging.debug(f"Heterogeneous CPU detection failed: {e}")

        # Fallback: use first N physical cores
        return list(range(min(physical_count, 8)))
    except Exception as e:
        logging.debug(f"CPU affinity detection failed: {e}")
        return []


def get_numa_node_for_gpu() -> int | None:
    """Get NUMA node closest to primary GPU for optimal latency.

    On multi-socket systems (e.g., dual Xeon), GPU is typically on one
    NUMA node. Pinning threads to the same NUMA node reduces memory
    access latency (cross-node = ~2x slower).

    Returns NUMA node number (0, 1, ...) or None if:
    - Not Linux
    - Single-socket system
    - GPU NUMA node undetectable

    Usage: After detecting node, use:
        psutil.Process().cpu_affinity(cores_on_numa_node)

    Returns NUMA node number or None if detection fails.
    """
    if not IS_LINUX:
        return None

    try:
        # Try to find GPU's NUMA node via sysfs
        gpu_paths = list(Path("/sys/class/drm").glob("card[0-9]"))
        if not gpu_paths:
            return None

        # Use first card (typically primary display)
        gpu_device = gpu_paths[0].resolve()
        numa_node_file = gpu_device / "device/numa_node"

        if numa_node_file.exists():
            node = int(numa_node_file.read_text().strip())
            if node >= 0:  # -1 means no NUMA affinity
                logging.info(
                    f"GPU on NUMA node {node}. For optimal latency on multi-socket systems, "
                    "consider pinning threads to this node."
                )
                return node
            logging.debug("GPU has no specific NUMA affinity (single-socket system)")
        else:
            logging.debug("NUMA node file not found for GPU (likely single-socket)")
    except Exception as e:
        logging.debug(f"NUMA detection failed: {e}")

    return None


class StreamThread(threading.Thread):
    def __init__(self, cmd, name):
        super().__init__(daemon=True)
        self.cmd = cmd
        self.name = name
        self.process = None
        self._running = True

    def _setup_cpu_affinity(self, ps):
        """Configure CPU affinity and priority for the process."""
        ps.nice(-10)
        numa_node = get_numa_node_for_gpu()
        affinity = get_optimal_cpu_affinity()

        if numa_node is not None and affinity and IS_LINUX:
            self._apply_numa_aware_affinity(ps, numa_node, affinity)
        elif affinity:
            ps.cpu_affinity(affinity[:8])
            logging.debug(f"{self.name} pinned to cores {affinity[:4]}... (physical cores, no HT)")
        else:
            logging.debug(f"{self.name} using default CPU affinity (no optimization)")

    def _apply_numa_aware_affinity(self, ps, numa_node, affinity):
        """Apply NUMA-aware CPU affinity for optimal GPU locality."""
        try:
            numa_cores = [cpu for cpu in affinity if Path(f"/sys/devices/system/cpu/cpu{cpu}/node{numa_node}").exists()]
            if numa_cores:
                ps.cpu_affinity(numa_cores[:8])
                logging.info(
                    f"{self.name} pinned to NUMA node {numa_node} cores {numa_cores[:4]}... "
                    f"(GPU affinity for 2x lower memory latency)"
                )
            else:
                ps.cpu_affinity(affinity[:8])
                logging.debug(f"{self.name} pinned to cores {affinity[:4]}... (no NUMA match)")
        except Exception as e:
            logging.debug(f"NUMA-aware affinity failed, using default: {e}")
            if affinity:
                ps.cpu_affinity(affinity[:8])

    def _log_startup_latency(self, start_time):
        """Log encoder startup latency."""
        startup_latency = (time.time() - start_time) * 1000  # ms
        if startup_latency > ENCODER_STARTUP_THRESHOLD_MS:
            logging.warning(
                f"{self.name} startup took {startup_latency:.1f}ms (>{ENCODER_STARTUP_THRESHOLD_MS}ms threshold)"
            )
        else:
            logging.debug(f"{self.name} startup latency: {startup_latency:.1f}ms")

    def run(self):
        start_time = time.time()
        logging.info("Starting %s: %s", self.name, " ".join(self.cmd))
        try:
            self.process = subprocess.Popen(
                self.cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, universal_newlines=True
            )

            self._log_startup_latency(start_time)

            try:
                ps = psutil.Process(self.process.pid)
                self._setup_cpu_affinity(ps)
            except Exception as e:
                logging.debug(f"Affinity/priority set failed: {e}")

        except Exception as e:
            trigger_shutdown(f"{self.name} failed to start: {e}")
            return

        while self._running and not host_state.should_terminate:
            ret = self.process.poll()
            if ret is not None:
                try:
                    _, err = self.process.communicate(timeout=0.5)
                except Exception:
                    err = ""
                if ret != 0 and not host_state.should_terminate and self._running:
                    logging.error("%s exited (%s). stderr:\n%s", self.name, ret, err or "(no output)")
                    trigger_shutdown(f"{self.name} crashed/quit with code {ret}")
                break
            time.sleep(0.2)

    def stop(self):
        """Stop FFmpeg process with proper cleanup to prevent zombies."""
        self._running = False
        if not self.process:
            return

        try:
            if self.process.poll() is None:
                logging.debug(f"Terminating {self.name} (PID {self.process.pid})")
                self.process.terminate()
                try:
                    self.process.wait(timeout=2.0)
                    logging.debug(f"{self.name} terminated gracefully")
                except subprocess.TimeoutExpired:
                    logging.warning(f"{self.name} did not terminate, sending SIGKILL")
                    self.process.kill()
                    try:
                        self.process.wait(timeout=1.0)
                        logging.debug(f"{self.name} killed successfully")
                    except subprocess.TimeoutExpired:
                        logging.error(f"{self.name} zombie process (PID {self.process.pid})")
        except ProcessLookupError:
            logging.debug(f"{self.name} already exited")
        except Exception as e:
            logging.error(f"Error stopping {self.name}: {e}")


def _detect_monitors_linux():
    try:
        out = subprocess.check_output(
            ["xrandr", "--listmonitors"], universal_newlines=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        logging.warning("xrandr failed (%s); using default single monitor.", e)
        return []
    except Exception as e:
        logging.error("Unexpected error in monitor detection: %s", e)
        return []
    mons = []
    for line in out.strip().splitlines()[1:]:
        parts = line.split()
        for part in parts:
            if "x" in part and "+" in part:
                try:
                    res, ox, oy = part.split("+")
                    w, h = res.split("x")
                    w = int(w.split("/")[0])
                    h = int(h.split("/")[0])
                    mons.append((w, h, int(ox), int(oy)))
                    break
                except Exception:
                    continue
    return mons


def detect_monitors():
    return _detect_monitors_linux()


def _input_ll_flags():
    return [
        "-fflags",
        "nobuffer",
        "-avioflags",
        "direct",
        "-use_wallclock_as_timestamps",
        "1",
        "-thread_queue_size",
        "64",
        "-probesize",
        "32",
        "-analyzeduration",
        "0",
    ]


def _output_sync_flags():
    return ["-fps_mode", "passthrough"]


def _mpegts_ll_mux_flags():
    return [
        "-flush_packets",
        "1",
        "-max_interleave_delta",
        "0",
        "-muxdelay",
        "0",
        "-muxpreload",
        "0",
        "-mpegts_flags",
        "resend_headers",
    ]


def _best_ts_pkt_size(mtu_guess: int, ipv6: bool) -> int:
    """Calculate optimal MPEG-TS packet size for given MTU.

    Returns multiple of 188 bytes (MPEG-TS packet size) that fits in MTU.
    Default: 1316 bytes = 7 TS packets for 1500 MTU.
    """
    if mtu_guess <= 0:
        mtu_guess = 1500
    overhead = IPV6_UDP_OVERHEAD if ipv6 else IPV4_UDP_OVERHEAD
    max_payload = max(512, mtu_guess - overhead)
    return max(MPEGTS_PACKET_SIZE, (max_payload // MPEGTS_PACKET_SIZE) * MPEGTS_PACKET_SIZE)


def _parse_bitrate_bits(bstr: str) -> int:
    if not bstr:
        return 0
    s = str(bstr).strip().lower()
    if not s:
        return 0
    try:
        # Check last character for suffix (faster than endswith)
        last_char = s[-1]
        multiplier = {
            "k": BITS_PER_KILOBIT,
            "m": BITS_PER_MEGABIT,
            "g": BITS_PER_GIGABIT,
        }.get(last_char)

        if multiplier:
            return int(float(s[:-1]) * multiplier)
        return int(float(s))
    except (ValueError, IndexError):
        return 0


def _format_bits(bits: int) -> str:
    """Format bitrate for human-readable display."""
    if bits >= BITS_PER_MEGABIT:
        return f"{max(1, bits // BITS_PER_MEGABIT)}M"
    if bits >= BITS_PER_KILOBIT:
        return f"{max(1, bits // BITS_PER_KILOBIT)}k"
    return str(max(1, bits))


def _target_bpp(codec: str, fps: int) -> float:
    """Calculate target bits per pixel based on codec and framerate.

    Returns optimal BPP for quality/bitrate balance:
    - H.264: 0.10 baseline, reduced at high FPS
    - H.265: 0.06 (better compression)
    """
    c = (codec or "h.264").lower()
    base = 0.045 if c in ("h.265", "hevc") else 0.07
    if fps >= HIGH_FPS_THRESHOLD:
        base += 0.02
    return base


def _safe_nvenc_preset(preset: str) -> str:
    preset = (preset or "").strip().lower()
    alias_map = {
        "ultrafast": "p1",
        "superfast": "p2",
        "veryfast": "p3",
        "fast": "p4",
        "medium": "p5",
        "slow": "p6",
        "slower": "p7",
        "veryslow": "p7",
        "ll": "ll",
        "low-latency": "ll",
        "low_latency": "ll",
        "llhq": "llhq",
        "llhp": "llhp",
        "ull": "llhp",
        "ultra-low-latency": "llhp",
        "ultra_low_latency": "llhp",
        "zerolatency": "llhp",
        "realtime": "llhp",
        "hq": "hq",
        "hp": "hp",
        "lossless": "lossless",
        "lossless-highperf": "losslesshp",
        "bd": "bd",
        "high-quality": "hq",
        "high-performance": "hp",
    }

    allowed = {
        "default",
        "fast",
        "medium",
        "slow",
        "hp",
        "hq",
        "bd",
        "ll",
        "llhq",
        "llhp",
        "lossless",
        "losslesshp",
        "p1",
        "p2",
        "p3",
        "p4",
        "p5",
        "p6",
        "p7",
    }

    mapped = alias_map.get(preset, preset)
    return mapped if mapped in allowed else "p4"


def _norm_qp(qp):
    try:
        q = int(qp)
        return str(max(0, min(51, q)))
    except Exception:
        return ""


def _try_nvenc_encoder(codec: str) -> str | None:
    """Try NVENC encoder for given codec."""
    encoder_name = "h264_nvenc" if codec == "h.264" else "hevc_nvenc"
    if has_nvidia() and ffmpeg_has_encoder(encoder_name):
        latency_note = "lowest latency" if codec == "h.264" else "lowest latency, but slightly higher than H.264"
        logging.info(f"Auto-selected NVENC for {codec.upper()} encoding ({latency_note})")
        return "nvenc"
    return None


def _try_qsv_encoder(codec: str, hwaccels: set) -> str | None:
    """Try QSV encoder for given codec."""
    encoder_name = "h264_qsv" if codec == "h.264" else "hevc_qsv"
    if "qsv" in hwaccels and ffmpeg_has_encoder(encoder_name) and test_qsv_encode():
        logging.info(f"Auto-selected QSV for {codec.upper()} encoding (verified working, low latency)")
        return "qsv"
    return None


def _try_vaapi_encoder(codec: str) -> str | None:
    """Try VAAPI encoder for given codec."""
    encoder_name = "h264_vaapi" if codec == "h.264" else "hevc_vaapi"
    if has_vaapi() and ffmpeg_has_encoder(encoder_name):
        logging.info(f"Auto-selected VAAPI for {codec.upper()} encoding (reliable fallback)")
        return "vaapi"
    return None


def _auto_select_hwenc(codec: str) -> str:
    """Auto-detect best hardware encoder. Priority: NVENC > QSV > VAAPI > CPU."""
    hwaccels = ffmpeg_hwaccels()

    # Try hardware encoders in priority order
    if result := _try_nvenc_encoder(codec):
        return result
    if result := _try_qsv_encoder(codec, hwaccels):
        return result
    if result := _try_vaapi_encoder(codec):
        return result

    # Fallback to CPU
    cpu_lib = "libx264" if codec == "h.264" else "libx265"
    intensity = "high" if codec == "h.264" else "very high"
    logging.warning(
        f"No hardware encoder detected, using CPU ({cpu_lib}) - expect {intensity} CPU usage and higher latency"
    )
    return "cpu"


def _build_rate_control_flags(hwenc: str, qp: str, bitrate: str, adaptive: bool) -> list[str]:
    """Build rate control flags based on encoder type."""
    if "vaapi" in hwenc:
        qp_val = qp or "23"
        flags = ["-rc_mode", "CQP", "-qp", qp_val]
        if bitrate and str(bitrate).lower() not in ("0", "auto"):
            flags += ["-b:v", bitrate, "-maxrate", bitrate, "-bufsize", bitrate]
        return flags

    if "nvenc" in hwenc:
        if adaptive:
            return ["-rc", "vbr", "-maxrate", bitrate or "15M", "-cq", qp or "23"]
        return ["-rc", "constqp"] + (["-qp", qp] if qp else [])

    if "qsv" in hwenc:
        return ["-rc_mode", "ICQ", "-icq_quality", qp or "23"]

    return ["-crf", qp or "23"]


def _nvenc_tune_args(tune_l: str) -> list[str]:
    """Get NVENC tune arguments based on tune preset."""
    if tune_l in ("zerolatency", "ull", "ultra-low-latency", "ultra_low_latency", "realtime"):
        return ["-tune", "ull"]
    if tune_l in ("low-latency", "ll", "low_latency"):
        return ["-tune", "ll"]
    if tune_l in ("hq", "film", "quality", "high_quality"):
        return ["-tune", "hq"]
    if tune_l in ("lossless",):
        return ["-tune", "lossless"]
    return ["-tune", "ll"]


def _build_h264_encoder_args(  # noqa: PLR0913
    hwenc: str,
    preset_l: str,
    tune_l: str,
    gop_val: int,
    use_gop: bool,
    dynamic_flags: list[str],
    pix_fmt: str,
    ensure_fn,
) -> tuple[list[str], list[str]]:
    """Build H.264 encoder arguments for specified hardware encoder."""
    extra_filters = []

    if hwenc == "nvenc" and ensure_fn("h264_nvenc"):
        enc = [
            "-c:v",
            "h264_nvenc",
            "-preset",
            _safe_nvenc_preset(preset_l or "llhq"),
            *(["-g", str(gop_val)] if use_gop else []),
            "-bf",
            "0",
            "-rc-lookahead",
            "0",
            "-refs",
            "1",
            "-flags2",
            "+fast",
            *dynamic_flags,
            "-pix_fmt",
            pix_fmt,
            "-bsf:v",
            "h264_mp4toannexb",
            *_nvenc_tune_args(tune_l),
        ]
    elif hwenc == "qsv" and ensure_fn("h264_qsv"):
        enc = ["-c:v", "h264_qsv", *dynamic_flags, "-pix_fmt", pix_fmt, "-bsf:v", "h264_mp4toannexb"]
    elif hwenc == "vaapi" and has_vaapi() and ensure_fn("h264_vaapi"):
        va_fmt = _vaapi_fmt_for_pix_fmt(pix_fmt, "h.264")
        extra_filters += ["-vf", f"format={va_fmt},hwupload", "-vaapi_device", "/dev/dri/renderD128"]
        enc = ["-c:v", "h264_vaapi", "-bf", "0", *dynamic_flags, "-pix_fmt", pix_fmt, "-bsf:v", "h264_mp4toannexb"]
    else:
        enc = [
            "-c:v",
            "libx264",
            "-preset",
            preset_l or "ultrafast",
            "-tune",
            tune_l or "zerolatency",
            *(["-g", str(gop_val)] if use_gop else []),
            *dynamic_flags,
            "-pix_fmt",
            pix_fmt,
            "-bsf:v",
            "h264_mp4toannexb",
        ]
        if tune_l in ("zerolatency", "ultra-low-latency", "ull", "low-latency", "ll"):
            enc += ["-x264-params", "scenecut=0"]

    return extra_filters, enc


def _build_h265_encoder_args(  # noqa: PLR0913
    hwenc: str,
    preset_l: str,
    tune_l: str,
    gop_val: int,
    use_gop: bool,
    dynamic_flags: list[str],
    pix_fmt: str,
    ensure_fn,
) -> tuple[list[str], list[str]]:
    """Build H.265 encoder arguments for specified hardware encoder."""
    extra_filters = []

    if hwenc == "nvenc" and ensure_fn("hevc_nvenc"):
        enc = [
            "-c:v",
            "hevc_nvenc",
            "-preset",
            _safe_nvenc_preset(preset_l or "p5"),
            *(["-g", str(gop_val)] if use_gop else []),
            "-bf",
            "0",
            "-rc-lookahead",
            "0",
            "-refs",
            "1",
            "-flags2",
            "+fast",
            *dynamic_flags,
            "-pix_fmt",
            pix_fmt,
            "-bsf:v",
            "hevc_mp4toannexb",
            *_nvenc_tune_args(tune_l),
        ]
    elif hwenc == "qsv" and ensure_fn("hevc_qsv"):
        enc = ["-c:v", "hevc_qsv", *dynamic_flags, "-pix_fmt", pix_fmt, "-bsf:v", "hevc_mp4toannexb"]
    elif hwenc == "vaapi" and has_vaapi() and ensure_fn("hevc_vaapi"):
        va_fmt = _vaapi_fmt_for_pix_fmt(pix_fmt, "h.265")
        extra_filters += ["-vf", f"format={va_fmt},hwupload", "-vaapi_device", "/dev/dri/renderD128"]
        enc = ["-c:v", "hevc_vaapi", "-bf", "0", *dynamic_flags, "-pix_fmt", pix_fmt, "-bsf:v", "hevc_mp4toannexb"]
    else:
        enc = [
            "-c:v",
            "libx265",
            "-preset",
            preset_l or "ultrafast",
            "-tune",
            tune_l or "zerolatency",
            *(["-g", str(gop_val)] if use_gop else []),
            *dynamic_flags,
            "-pix_fmt",
            pix_fmt,
            "-bsf:v",
            "hevc_mp4toannexb",
        ]
        if tune_l in ("zerolatency", "ultra-low-latency", "ull", "low-latency", "ll"):
            enc += ["-x265-params", "scenecut=0:rc-lookahead=0"]

    return extra_filters, enc


def _pick_encoder_args(codec: str, hwenc: str, preset: str, gop: str, qp: str, tune: str, bitrate: str, pix_fmt: str):  # noqa: PLR0913
    codec = (codec or "h.264").lower()
    hwenc = (hwenc or "auto").lower()
    preset_l = (preset or "").strip().lower()
    tune_l = (tune or "").strip().lower()
    qp = _norm_qp(qp)

    # Warn if H.265 is used with ultra-low-latency tune
    if codec == "h.265" and tune_l in ("zerolatency", "ull", "ultra-low-latency", "ultra_low_latency", "realtime"):
        logging.warning(
            "H.265 codec selected with ultra-low-latency tune. "
            "For lowest latency, consider H.264 codec which typically has 10-20%% faster decode times. "
            "H.265 is better for bandwidth-constrained connections, but H.264 is faster for LAN streaming."
        )

    def ensure(name: str) -> bool:
        ok = ffmpeg_has_encoder(name)
        if not ok:
            logging.warning("Requested encoder '%s' not found; falling back to CPU.", name)
        return ok

    if hwenc == "auto":
        hwenc = _auto_select_hwenc(codec)

    adaptive = getattr(host_args_manager.args, "adaptive", False)
    dynamic_flags = _build_rate_control_flags(hwenc, qp, bitrate, adaptive)

    adaptive = getattr(host_args_manager.args, "adaptive", False)
    dynamic_flags = _build_rate_control_flags(hwenc, qp, bitrate, adaptive)

    try:
        gop_val = int(gop)
        use_gop = gop_val > 0
    except Exception:
        gop_val, use_gop = 0, False

    if codec == "h.264":
        return _build_h264_encoder_args(hwenc, preset_l, tune_l, gop_val, use_gop, dynamic_flags, pix_fmt, ensure)
    if codec == "h.265":
        return _build_h265_encoder_args(hwenc, preset_l, tune_l, gop_val, use_gop, dynamic_flags, pix_fmt, ensure)

    return [], []


def _pick_kms_device():
    for cand in ("card0", "card1", "card2"):
        p = Path(f"/dev/dri/{cand}")
        if p.exists():
            return str(p)
    return "/dev/dri/card0"


def build_video_cmd(args, bitrate, monitor_info, video_port):
    try:
        fps_i = int(str(args.framerate))
    except Exception:
        fps_i = 60

    w, h, ox, oy = monitor_info
    preset = args.preset.strip().lower() if args.preset else ""
    gop, qp, tune, pix_fmt = args.gop, args.qp, args.tune, args.pix_fmt

    codec_name = args.encoder if args.encoder and args.encoder.lower() != "none" else "h.264"
    min_bits = int(w) * int(h) * max(1, fps_i) * _target_bpp(codec_name, fps_i)
    cur_bits = _parse_bitrate_bits(bitrate)
    if cur_bits < min_bits:
        safe_bits = int(min_bits)
        safe_str = _format_bits(safe_bits)
        logging.warning(
            "Bitrate too low for %dx%d@%dfps (%s < %s). Bumping to %s.",
            w,
            h,
            fps_i,
            str(bitrate),
            _format_bits(cur_bits),
            safe_str,
        )
        bitrate = safe_str
        host_state.current_bitrate = safe_str

    ip = getattr(host_state, "client_ip", None)
    if not ip or not isinstance(ip, str) or ip.strip().lower() in ("none", "", "0.0.0.0"):
        logging.error(f"build_video_cmd: invalid client IP ({ip!r}) — refusing to build ffmpeg command.")
        return None

    base_in = [*(_ffmpeg_base_cmd()), *(_input_ll_flags())]
    disp = args.display
    if "." not in disp:
        disp = f"{disp}.0"

    capture_pref = (os.environ.get("LINUXPLAY_CAPTURE", "auto") or "auto").lower()
    kms_available = ffmpeg_has_device("kmsgrab")
    vaapi_available = has_vaapi()

    def _vaapi_possible_for_codec():
        enc = (args.encoder or "h.264").lower()
        return (enc == "h.264" and ffmpeg_has_encoder("h264_vaapi")) or (
            enc == "h.265" and ffmpeg_has_encoder("hevc_vaapi")
        )

    use_kms = False
    if capture_pref == "kmsgrab" or (
        capture_pref == "auto"
        and kms_available
        and (
            (args.hwenc in ("auto", "vaapi") and vaapi_available and _vaapi_possible_for_codec())
            or (args.hwenc == "cpu")
        )
    ):
        use_kms = True

    if use_kms:
        kms_dev = os.environ.get("LINUXPLAY_KMS_DEVICE", _pick_kms_device())
        logging.info("Linux capture: kmsgrab (%s) selected (pref=%s).", kms_dev, capture_pref)
        input_side = [
            *base_in,
            "-f",
            "kmsgrab",
            "-framerate",
            str(fps_i),
            "-device",
            kms_dev,
            "-i",
            "-",
        ]

        extra_filters, encode = _pick_encoder_args(
            codec=args.encoder,
            hwenc=args.hwenc,
            preset=preset,
            gop=gop,
            qp=qp,
            tune=tune,
            bitrate=bitrate,
            pix_fmt=pix_fmt,
        )

        if any(x in encode for x in ("h264_vaapi", "hevc_vaapi")):
            _vaapi_fmt = {"nv12": "nv12", "yuv420p": "nv12", "p010": "p010", "yuv420p10": "p010"}.get(
                (pix_fmt or "nv12").lower(), "nv12"
            )
            extra_filters = [
                "-vf",
                f"hwmap=derive_device=vaapi,scale_vaapi=w={w}:h={h}:format={_vaapi_fmt}",
                "-vaapi_device",
                "/dev/dri/renderD128",
            ]
        elif args.hwenc == "cpu":
            extra_filters = ["-vf", f"hwdownload,format={pix_fmt or 'yuv420p'}"]

    else:
        logging.info("Linux capture: x11grab selected (pref=%s, kms=%s).", capture_pref, kms_available)
        input_arg = f"{disp}+{ox},{oy}"
        input_side = [
            *base_in,
            "-f",
            "x11grab",
            "-draw_mouse",
            "0",
            "-framerate",
            str(fps_i),
            "-video_size",
            f"{w}x{h}",
            "-i",
            input_arg,
        ]
        extra_filters, encode = _pick_encoder_args(
            codec=args.encoder,
            hwenc=args.hwenc,
            preset=preset,
            gop=gop,
            qp=qp,
            tune=tune,
            bitrate=bitrate,
            pix_fmt=pix_fmt,
        )

    output_side = _output_sync_flags()
    mtu_guess = 1500
    ipv6 = ":" in ip
    pkt_size = _best_ts_pkt_size(mtu_guess, ipv6)
    fifo_size = 32768
    buffer_size = 65536
    if getattr(host_state, "net_mode", "lan") == "wifi":
        fifo_size = 131072
        buffer_size = 262144

    out = [
        *(_mpegts_ll_mux_flags()),
        "-flags",
        "+low_delay",
        "-f",
        "mpegts",
        *_marker_opt(),
        (
            f"udp://{ip}:{video_port}"
            f"?pkt_size={pkt_size}"
            f"&buffer_size={buffer_size}"
            f"&fifo_size={fifo_size}"
            f"&overrun_nonfatal=1"
            f"&max_delay=0"
        ),
    ]

    return input_side + output_side + (extra_filters or []) + encode + out


def _detect_pulse_monitor():
    """Detect the best available PulseAudio monitor source."""
    mon = os.environ.get("PULSE_MONITOR", "")
    if mon:
        return mon if mon.endswith(".monitor") else f"{mon}.monitor"

    if not which("pactl"):
        return "default.monitor"

    try:
        out = subprocess.check_output(["pactl", "list", "short", "sources"], text=True, stderr=subprocess.DEVNULL)
        best = None
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= PACTL_OUTPUT_MIN_PARTS:
                name, state = parts[1], parts[4].upper()
                if ".monitor" in name:
                    if state == "RUNNING":
                        return name
                    if state == "IDLE" and not best:
                        best = name
        if best:
            return best
    except Exception as e:
        logging.warning("PulseAudio monitor detection failed: %s", e)

    return "default.monitor"


def _detect_audio_channels(mon):
    """Detect the number of audio channels for the given monitor source."""
    if not which("pactl"):
        return 2

    try:
        probe = subprocess.check_output(
            [
                "bash",
                "-c",
                f"pactl list sources | grep -A2 '{mon}' | grep 'Channels' | head -n1 | awk '{{print $2}}'",
            ],
            text=True,
        ).strip()
        if probe.isdigit():
            channels = int(probe)
            return channels if channels in [1, 2, 6, 8] else 2
    except Exception as e:
        logging.warning("Audio channel detection failed: %s", e)

    return 2


def build_audio_cmd():
    opus_app = os.environ.get("LP_OPUS_APP", "voip")
    opus_fd = os.environ.get("LP_OPUS_FD", "10")

    net_mode = getattr(host_state, "net_mode", "lan")
    aud_buf = "4194304" if net_mode == "wifi" else "512"
    aud_delay = "150000" if net_mode == "wifi" else "0"

    mon = _detect_pulse_monitor()
    logging.info("Using PulseAudio source: %s", mon)

    channels = _detect_audio_channels(mon)
    logging.info("Detected %s channel(s): %s", channels, "Surround" if channels > STEREO_CHANNELS else "Stereo")

    input_side = [
        *(_ffmpeg_base_cmd()),
        *(_input_ll_flags()),
        "-f",
        "pulse",
        "-i",
        mon,
        "-ac",
        str(channels),
    ]

    output_side = _output_sync_flags()

    encode = [
        "-c:a",
        "libopus",
        "-b:a",
        f"{SURROUND_BITRATE_KBPS}k" if channels > STEREO_CHANNELS else f"{STEREO_BITRATE_KBPS}k",
        "-application",
        opus_app,
        "-frame_duration",
        opus_fd,
    ]

    out = [
        *(_mpegts_ll_mux_flags()),
        *_marker_opt(),
        "-f",
        "mpegts",
        f"udp://{host_state.client_ip}:{UDP_AUDIO_PORT}"
        f"?pkt_size=1316&buffer_size={aud_buf}&overrun_nonfatal=1&max_delay={aud_delay}",
    ]

    return input_side + output_side + encode + out


def _inject_mouse_move(x, y):
    if HAVE_PYNPUT:
        try:
            _mouse.position = (int(x), int(y))
        except Exception as e:
            logging.debug(f"pynput move failed: {e}")
    elif IS_LINUX:
        try:
            # Store handle to prevent zombie processes
            proc = subprocess.Popen(
                ["xdotool", "mousemove", str(x), str(y)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            # Non-blocking wait with cleanup
            proc.poll()
        except (OSError, FileNotFoundError) as e:
            logging.debug(f"xdotool mousemove failed: {e}")


def _inject_mouse_down(btn):
    if HAVE_PYNPUT:
        b = {"1": Button.left, "2": Button.middle, "3": Button.right}.get(btn, Button.left)
        try:
            _mouse.press(b)
        except Exception as e:
            logging.debug(f"pynput mousedown failed: {e}")
    elif IS_LINUX:
        try:
            proc = subprocess.Popen(["xdotool", "mousedown", btn], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.poll()
        except (OSError, FileNotFoundError) as e:
            logging.debug(f"xdotool mousedown failed: {e}")


def _inject_mouse_up(btn):
    if HAVE_PYNPUT:
        b = {"1": Button.left, "2": Button.middle, "3": Button.right}.get(btn, Button.left)
        try:
            _mouse.release(b)
        except Exception as e:
            logging.debug(f"pynput mouseup failed: {e}")
    elif IS_LINUX:
        try:
            proc = subprocess.Popen(["xdotool", "mouseup", btn], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.poll()
        except (OSError, FileNotFoundError) as e:
            logging.debug(f"xdotool mouseup failed: {e}")


def _inject_scroll(btn):
    if HAVE_PYNPUT:
        try:
            if btn == "4":
                _mouse.scroll(0, +1)
            elif btn == "5":
                _mouse.scroll(0, -1)
            elif btn == "6":
                _mouse.scroll(-1, 0)
            elif btn == "7":
                _mouse.scroll(+1, 0)
        except Exception as e:
            logging.debug(f"pynput scroll failed: {e}")
    elif IS_LINUX:
        try:
            proc = subprocess.Popen(["xdotool", "click", btn], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.poll()
        except (OSError, FileNotFoundError) as e:
            logging.debug(f"xdotool scroll failed: {e}")


_key_map = {
    "Escape": Key.esc if HAVE_PYNPUT else None,
    "Tab": Key.tab if HAVE_PYNPUT else None,
    "BackSpace": Key.backspace if HAVE_PYNPUT else None,
    "Return": Key.enter if HAVE_PYNPUT else None,
    "Insert": Key.insert if HAVE_PYNPUT else None,
    "Delete": Key.delete if HAVE_PYNPUT else None,
    "Home": Key.home if HAVE_PYNPUT else None,
    "End": Key.end if HAVE_PYNPUT else None,
    "Left": Key.left if HAVE_PYNPUT else None,
    "Up": Key.up if HAVE_PYNPUT else None,
    "Right": Key.right if HAVE_PYNPUT else None,
    "Down": Key.down if HAVE_PYNPUT else None,
    "Page_Up": Key.page_up if HAVE_PYNPUT else None,
    "Page_Down": Key.page_down if HAVE_PYNPUT else None,
    "Shift_L": Key.shift if HAVE_PYNPUT else None,
    "Control_L": Key.ctrl if HAVE_PYNPUT else None,
    "Alt_L": Key.alt if HAVE_PYNPUT else None,
    "Alt_R": (Key.alt_gr if HAVE_PYNPUT and hasattr(Key, "alt_gr") else (Key.alt if HAVE_PYNPUT else None)),
    "Super_L": (Key.cmd if HAVE_PYNPUT else None),
    "Caps_Lock": (Key.caps_lock if HAVE_PYNPUT else None),
    "F1": Key.f1 if HAVE_PYNPUT else None,
    "F2": Key.f2 if HAVE_PYNPUT else None,
    "F3": Key.f3 if HAVE_PYNPUT else None,
    "F4": Key.f4 if HAVE_PYNPUT else None,
    "F5": Key.f5 if HAVE_PYNPUT else None,
    "F6": Key.f6 if HAVE_PYNPUT else None,
    "F7": Key.f7 if HAVE_PYNPUT else None,
    "F8": Key.f8 if HAVE_PYNPUT else None,
    "F9": Key.f9 if HAVE_PYNPUT else None,
    "F10": Key.f10 if HAVE_PYNPUT else None,
    "F11": Key.f11 if HAVE_PYNPUT else None,
    "F12": Key.f12 if HAVE_PYNPUT else None,
    "space": Key.space if HAVE_PYNPUT else None,
}

CHAR_TO_X11 = {
    "-": "minus",
    "=": "equal",
    "[": "bracketleft",
    "]": "bracketright",
    "\\": "backslash",
    ";": "semicolon",
    "'": "apostrophe",
    ",": "comma",
    ".": "period",
    "/": "slash",
    "`": "grave",
    "!": "exclam",
    '"': "quotedbl",
    "#": "numbersign",
    "$": "dollar",
    "%": "percent",
    "&": "ampersand",
    "*": "asterisk",
    "(": "parenleft",
    ")": "parenright",
    "_": "underscore",
    "+": "plus",
    "{": "braceleft",
    "}": "braceright",
    "|": "bar",
    ":": "colon",
    "<": "less",
    ">": "greater",
    "?": "question",
    "£": "sterling",
    "¬": "notsign",
    "¦": "brokenbar",
}

NAME_TO_CHAR = {
    "minus": "-",
    "equal": "=",
    "bracketleft": "[",
    "bracketright": "]",
    "backslash": "\\",
    "semicolon": ";",
    "apostrophe": "'",
    "comma": ",",
    "period": ".",
    "slash": "/",
    "grave": "`",
    "exclam": "!",
    "quotedbl": '"',
    "numbersign": "#",
    "dollar": "$",
    "percent": "%",
    "ampersand": "&",
    "asterisk": "*",
    "parenleft": "(",
    "parenright": ")",
    "underscore": "_",
    "plus": "+",
    "braceleft": "{",
    "braceright": "}",
    "bar": "|",
    "colon": ":",
    "less": "<",
    "greater": ">",
    "question": "?",
    "sterling": "£",
    "notsign": "¬",
    "brokenbar": "¦",
}


def _inject_key(action, name):
    if HAVE_PYNPUT:
        k = _key_map.get(name)
        try:
            if k:
                (_keys.press if action == "down" else _keys.release)(k)
                return

            if isinstance(name, str) and len(name) == 1:
                (_keys.press if action == "down" else _keys.release)(name)
                return

            ch = NAME_TO_CHAR.get(name)
            if ch:
                (_keys.press if action == "down" else _keys.release)(ch)
                return
        except Exception as e:
            logging.debug("pynput key %s failed for %r: %s", action, name, e)
        return

    if IS_LINUX:
        try:
            keyname = name
            if isinstance(name, str) and len(name) == 1:
                keyname = CHAR_TO_X11.get(name, name)
            cmd = ["xdotool", "keydown" if action == "down" else "keyup", keyname]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.poll()  # Non-blocking cleanup
        except Exception as e:
            logging.debug(f"xdotool key {action} failed for {name!r}: {e}")


def _validate_csr_pin(peer_ip: str, parts: list) -> tuple[bool, str | None]:
    """Validate PIN for CSR authentication. Returns (success, error_code)."""
    if len(parts) < CSR_AUTH_MIN_PARTS:
        return False, "NEEDPIN"

    provided_pin = parts[2]
    ok = False
    with host_state.pin_lock:
        if (
            not host_state.session_active
            and provided_pin == str(host_state.pin_code)
            and time.time() < host_state.pin_expiry
        ):
            ok = True

    if not ok:
        _record_failed_auth(peer_ip)
        return False, "FAIL:BADPIN"

    _clear_failed_auth(peer_ip)
    return True, None


def _process_csr_and_issue_cert(conn, peer_ip: str) -> dict | None:
    """Request CSR from client and issue certificate. Returns cert result or None."""
    conn.sendall(b"SENDCSR")
    csr_raw = conn.recv(8192).decode("utf-8", errors="replace").strip()

    if not csr_raw.startswith("CSR:"):
        conn.sendall(b"FAIL:BADCSR")
        return None

    csr_b64 = csr_raw[4:]
    csr_pem = base64.b64decode(csr_b64)

    result = _issue_client_cert(client_name=f"client-{peer_ip}", export_hint_ip=peer_ip, csr_pem=csr_pem)
    if not result:
        conn.sendall(b"FAIL:CERTISSUE")
        return None

    return result


def _activate_csr_session(peer_ip: str) -> str:
    """Activate session after successful CSR auth. Returns monitor info string."""
    with host_state.pin_lock:
        host_state.session_active = True
        host_state.authed_client_ip = peer_ip
        host_state.pin_expiry = 0
        host_state.pin_paused = True
        host_state.last_pong_ts = time.time()

    host_state.client_ip = peer_ip
    monitors_str = (
        ";".join(f"{w}x{h}+{ox}+{oy}" for (w, h, ox, oy) in host_state.monitors) if host_state.monitors else DEFAULT_RES
    )
    set_status(f"Client (new): {host_state.client_ip}")
    return monitors_str


def _handle_csr_auth(conn, peer_ip, parts, encoder_str):
    """Handle CSR-based authentication (secure mode)."""
    logging.info("[AUTH] New secure handshake with CSR from %s", peer_ip)

    # Check rate limiting
    allowed, reason = _check_rate_limit(peer_ip)
    if not allowed:
        logging.warning(f"[AUTH] Rate limit: {peer_ip} - {reason}")
        with contextlib.suppress(Exception):
            conn.sendall(f"FAIL:RATELIMIT:{reason}".encode())
        return False

    # Validate PIN
    ok, error = _validate_csr_pin(peer_ip, parts)
    if not ok:
        with contextlib.suppress(Exception):
            conn.sendall(error.encode())
        return False

    # Process CSR and issue certificate
    try:
        result = _process_csr_and_issue_cert(conn, peer_ip)
        if not result:
            return False

        # Send cert and CA
        cert_b64 = base64.b64encode(result["cert_pem"]).decode()
        ca_b64 = base64.b64encode(result["ca_pem"]).decode()
        conn.sendall(f"CERT:{cert_b64}|{ca_b64}".encode())

        # Activate session
        monitors_str = _activate_csr_session(peer_ip)

        # Send final OK (only once!)
        conn.sendall(f"OK:{encoder_str}:{monitors_str}".encode())
        set_status(f"Client (new): {host_state.client_ip}")
        logging.info("[AUTH] Client %s authenticated via CSR (secure mode)", peer_ip)
        threading.Thread(target=lambda: pin_rotate_if_needed(force=True), daemon=True).start()
        return True
    except Exception as e:
        logging.error("[AUTH] CSR handshake failed: %s", e)
        with contextlib.suppress(Exception):
            conn.sendall(b"FAIL:ERROR")
        return False


def _handle_cert_challenge_auth(conn, peer_ip, parts, encoder_str):
    """Handle challenge-response authentication for existing cert."""
    fp_hex = parts[1][5:].strip().upper()
    logging.info("[AUTH] Challenge-response auth from %s (FP: %s...)", peer_ip, fp_hex[:12])

    if host_state.session_active:
        with contextlib.suppress(Exception):
            conn.sendall(b"BUSY:ACTIVESESSION")
        logging.warning(f"[AUTH] Rejected cert client {peer_ip} — active session")
        return False

    # Verify cert is trusted
    rec = _trust_record_for(fp_hex, _load_trust_db())
    if not rec or rec.get("status") != "trusted":
        with contextlib.suppress(Exception):
            conn.sendall(b"FAIL:UNTRUSTEDCERT")
        logging.warning(f"[AUTH] Rejected {peer_ip} — cert not trusted")
        return False

    challenge = _generate_challenge()
    challenge_b64 = base64.b64encode(challenge).decode()

    try:
        conn.sendall(f"CHALLENGE:{challenge_b64}".encode())
        sig_raw = conn.recv(8192).decode("utf-8", errors="replace").strip()
        if not sig_raw.startswith("SIGNATURE:"):
            conn.sendall(b"FAIL:BADSIG")
            return False

        # Verify signature
        sig_b64 = sig_raw[10:]  # Remove "SIGNATURE:" prefix
        try:
            signature = base64.b64decode(sig_b64)
        except Exception:
            conn.sendall(b"FAIL:BADSIG")
            return False

        # Load certificate PEM from trust database
        cert_pem = rec.get("cert_pem")
        if not cert_pem:
            conn.sendall(b"FAIL:NOCERT")
            logging.error("[AUTH] No cert_pem in trust record for %s", fp_hex[:12])
            return False

        # Verify signature matches challenge
        if not _verify_signature(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem, challenge, signature):
            conn.sendall(b"FAIL:BADSIG")
            logging.warning("[AUTH] Signature verification failed for %s", peer_ip)
            return False

        # Activate session (same as CSR flow)
        with host_state.pin_lock:
            host_state.session_active = True
            host_state.authed_client_ip = peer_ip
            host_state.pin_expiry = 0
            host_state.pin_paused = True
            host_state.last_pong_ts = time.time()

        host_state.client_ip = peer_ip
        monitors_str = (
            ";".join(f"{w}x{h}+{ox}+{oy}" for (w, h, ox, oy) in host_state.monitors)
            if host_state.monitors
            else DEFAULT_RES
        )

        resp = f"OK:{encoder_str}:{monitors_str}"
        try:
            conn.sendall(resp.encode("utf-8"))
            conn.shutdown(socket.SHUT_WR)
            time.sleep(0.05)
        finally:
            pass

        set_status(f"Client (secure): {host_state.client_ip}")
        logging.info("[AUTH] ✓ Client %s authenticated via challenge-response (SECURE)", peer_ip)
        return True
    except Exception as e:
        logging.error("[AUTH] Challenge-response failed: %s", e)
        with contextlib.suppress(Exception):
            conn.sendall(b"FAIL:ERROR")
        return False


def _handle_legacy_certfp_auth(conn, peer_ip, parts, encoder_str):
    """Handle legacy fingerprint-only authentication (DEPRECATED)."""
    fp_hex = parts[1][len("CERTFP:") :].strip().upper()
    logging.warning("[AUTH] LEGACY fingerprint-only auth from %s (DEPRECATED)", peer_ip)

    if host_state.session_active:
        try:
            conn.sendall(b"BUSY:ACTIVESESSION")
            conn.shutdown(socket.SHUT_WR)
            time.sleep(0.05)
        except Exception:
            pass
        logging.warning(f"[AUTH] Rejected CERTFP client {peer_ip} — active session")
        return False

    if fp_hex and _verify_fingerprint_trusted(fp_hex):
        host_state.session_active = True
        host_state.authed_client_ip = peer_ip
        host_state.pin_expiry = 0
        host_state.pin_paused = True
        host_state.last_pong_ts = time.time()
        host_state.client_ip = peer_ip

        monitors_str = (
            ";".join(f"{w}x{h}+{ox}+{oy}" for (w, h, ox, oy) in host_state.monitors)
            if host_state.monitors
            else DEFAULT_RES
        )
        resp = f"OK:{encoder_str}:{monitors_str}"
        try:
            conn.sendall(resp.encode("utf-8"))
            conn.shutdown(socket.SHUT_WR)
            time.sleep(0.05)
        finally:
            pass

        set_status(f"Client (legacy cert): {host_state.client_ip}")
        logging.warning("[AUTH] Client %s authenticated via CERTFP (LEGACY - please upgrade)", peer_ip)
        return True

    try:
        conn.sendall(b"FAIL:UNTRUSTEDCERT")
        conn.shutdown(socket.SHUT_WR)
        time.sleep(0.05)
    except Exception:
        pass
    logging.warning(f"[AUTH] Rejected cert from {peer_ip} — not trusted")
    return False


def _handle_legacy_pin_auth(conn, peer_ip, parts, encoder_str):
    """Handle legacy PIN-only authentication (DEPRECATED)."""
    provided_pin = parts[1] if len(parts) >= HELLO_MIN_PARTS else ""
    logging.warning("[AUTH] LEGACY PIN-only auth from %s (DEPRECATED - insecure)", peer_ip)

    allowed, reason = _check_rate_limit(peer_ip)
    if not allowed:
        logging.warning(f"[AUTH] Rate limit: {peer_ip} - {reason}")
        try:
            conn.sendall(f"FAIL:RATELIMIT:{reason}".encode())
            conn.shutdown(socket.SHUT_WR)
            time.sleep(0.05)
        except Exception:
            pass
        return False

    ok = False
    with host_state.pin_lock:
        if (
            not host_state.session_active
            and provided_pin == str(host_state.pin_code)
            and time.time() < host_state.pin_expiry
        ):
            ok = True

    if ok:
        _clear_failed_auth(peer_ip)
        with host_state.pin_lock:
            host_state.session_active = True
            host_state.authed_client_ip = peer_ip
            host_state.pin_expiry = 0
            host_state.pin_paused = True
            host_state.last_pong_ts = time.time()
            logging.info(f"[AUTH] Client {peer_ip} authenticated (LEGACY) — PIN invalidated")

        _issue_client_cert(client_name="linuxplay-client", export_hint_ip=peer_ip, csr_pem=None)
        threading.Thread(target=lambda: pin_rotate_if_needed(force=True), daemon=True).start()

        host_state.client_ip = peer_ip
        monitors_str = (
            ";".join(f"{w}x{h}+{ox}+{oy}" for (w, h, ox, oy) in host_state.monitors)
            if host_state.monitors
            else DEFAULT_RES
        )

        try:
            conn.sendall(f"OK:{encoder_str}:{monitors_str}".encode())
            conn.shutdown(socket.SHUT_WR)
            time.sleep(0.05)
        finally:
            pass

        set_status(f"Client (legacy PIN): {host_state.client_ip}")
        logging.warning("Client %s handshake complete (LEGACY MODE - please upgrade client)", peer_ip)
        return True

    _record_failed_auth(peer_ip)
    if host_state.session_active:
        logging.warning(f"[AUTH] {peer_ip} attempted reuse of consumed PIN (session active)")
        reply = b"BUSY:ACTIVESESSION"
    else:
        logging.warning(f"[AUTH] Rejected {peer_ip}: invalid or expired PIN")
        reply = b"FAIL:BADPIN"
    try:
        conn.sendall(reply)
        conn.shutdown(socket.SHUT_WR)
        time.sleep(0.05)
    except Exception:
        pass
    return False


def tcp_handshake_server(sock, encoder_str, _args):
    logging.info("TCP handshake server on %d", TCP_HANDSHAKE_PORT)
    set_status("Waiting for client handshake…")

    _ensure_ca()

    while not host_state.should_terminate:
        try:
            conn, addr = sock.accept()
            peer_ip = addr[0]
            logging.info(f"Handshake from {peer_ip}")

            raw = conn.recv(2048).decode("utf-8", errors="replace").strip()
            parts = (raw or "").split()
            cmd = parts[0] if parts else ""

            if host_state.session_active and host_state.authed_client_ip and peer_ip != host_state.authed_client_ip:
                logging.warning(f"Rejected handshake from {peer_ip}: active session with {host_state.authed_client_ip}")
                try:
                    conn.sendall(b"BUSY:ACTIVESESSION")
                    conn.shutdown(socket.SHUT_WR)
                    time.sleep(0.05)
                except Exception:
                    pass
                conn.close()
                continue

            # NEW: Challenge-response with CSR (secure mode)
            if cmd == "AUTH" and len(parts) >= CERT_AUTH_MIN_PARTS and parts[1].startswith("CSR"):
                success = _handle_csr_auth(conn, peer_ip, parts, encoder_str)
                conn.close()
                if success:
                    continue

            # NEW: Challenge-response for existing cert (signature verification)
            if cmd == "AUTH" and len(parts) >= CERT_AUTH_MIN_PARTS and parts[1].startswith("CERT:"):
                _handle_cert_challenge_auth(conn, peer_ip, parts, encoder_str)
                conn.close()
                continue

            # LEGACY: Fingerprint-only (DEPRECATED)
            if cmd == "HELLO" and len(parts) >= HELLO_MIN_PARTS and parts[1].startswith("CERTFP:"):
                _handle_legacy_certfp_auth(conn, peer_ip, parts, encoder_str)
                conn.close()
                continue

            # LEGACY: PIN-only (generates server-side keys - DEPRECATED)
            if cmd == "HELLO":
                _handle_legacy_pin_auth(conn, peer_ip, parts, encoder_str)
                conn.close()
                continue

            # Unknown command
            try:
                conn.sendall(b"FAIL")
                conn.shutdown(socket.SHUT_WR)
                time.sleep(0.05)
            except Exception:
                pass
            conn.close()

        except OSError:
            break
        except Exception as e:
            trigger_shutdown(f"Handshake server error: {e}")
            break


def start_streams_for_current_client(args):
    ip = getattr(host_state, "client_ip", None)
    if not ip:
        logging.warning("start_streams_for_current_client: no valid client IP — waiting for handshake.")
        return

    with host_state.video_thread_lock:
        if host_state.starting_streams:
            logging.debug("start_streams_for_current_client: already starting; skipping duplicate call.")
            return
        if host_state.video_threads:
            logging.debug("start_streams_for_current_client: video threads already active; skipping.")
            return

        if getattr(host_state, "last_disconnect_ts", 0) > 0:
            elapsed = time.time() - host_state.last_disconnect_ts
            if elapsed < RECONNECT_COOLDOWN:
                logging.debug(f"start_streams_for_current_client: cooldown {elapsed:.2f}s — skipping restart.")
                return

        host_state.starting_streams = True

        # Initialize performance metrics for new session
        host_state.perf_metrics["session_start"] = time.time()
        host_state.perf_metrics["frames_encoded"] = 0
        host_state.perf_metrics["bytes_sent"] = 0
        host_state.perf_metrics["encoder_restarts"] += 1 if host_state.video_threads else 0
        host_state.perf_metrics["numa_node"] = get_numa_node_for_gpu()

        try:
            host_state.video_threads = []
            for i, mon in enumerate(host_state.monitors):
                cmd = build_video_cmd(args, host_state.current_bitrate, mon, UDP_VIDEO_PORT + i)
                if not cmd:
                    logging.warning(f"Video {i} skipped — invalid or incomplete ffmpeg command.")
                    continue
                t = StreamThread(cmd, f"Video {i}")
                t.start()
                host_state.video_threads.append(t)

            if args.audio == "enable" and not host_state.audio_thread:
                ac = build_audio_cmd()
                if ac:
                    host_state.audio_thread = StreamThread(ac, "Audio")
                    host_state.audio_thread.start()
        except Exception as e:
            logging.error(f"start_streams_for_current_client: exception while starting — {e}")
        finally:
            host_state.starting_streams = False


def _handle_net_mode_change(tokens):
    """Handle network mode change request."""
    if len(tokens) < HELLO_MIN_PARTS:
        return

    mode = tokens[1].strip().lower()
    if mode not in ("wifi", "lan"):
        return

    old = getattr(host_state, "net_mode", "lan")
    if mode == old:
        return

    logging.info(f"Network mode switch requested: {old} → {mode}")
    host_state.net_mode = mode
    try:
        stop_streams_only()
        if host_args_manager.args:
            start_streams_for_current_client(host_args_manager.args)
    except Exception as e:
        logging.error(f"Restart after NET failed: {e}")


def _handle_goodbye():
    """Handle client disconnect."""
    peer_ip = host_state.authed_client_ip or host_state.client_ip
    logging.info(f"Client at {peer_ip} disconnected cleanly.")
    try:
        stop_streams_only()
        host_state.client_ip = None
        host_state.starting_streams = False
        host_state.session_active = False
        host_state.authed_client_ip = None
        set_status("Client disconnected — waiting for connection…")
        logging.debug("All streams stopped after GOODBYE.")

        pin_rotate_if_needed(force=True)
        logging.info("[AUTH] Client disconnected — PIN rotation resumed.")

        time.sleep(RECONNECT_COOLDOWN)
    except Exception as e:
        logging.error(f"Error handling GOODBYE cleanup: {e}")


def _handle_mouse_packet(tokens):
    """Handle mouse movement and button events."""
    if len(tokens) != MOUSE_PKT_PARTS:
        return

    try:
        pkt_type = int(tokens[1])
        bmask = int(tokens[2])
        x = int(tokens[3])
        y = int(tokens[4])
    except ValueError:
        return

    _inject_mouse_move(x, y)

    if pkt_type == MOUSE_PKT_TYPE_DOWN:
        if bmask & 1:
            _inject_mouse_down("1")
        if bmask & 2:
            _inject_mouse_down("2")
        if bmask & 4:
            _inject_mouse_down("3")
    elif pkt_type == MOUSE_PKT_TYPE_UP:
        if bmask & 1:
            _inject_mouse_up("1")
        if bmask & 2:
            _inject_mouse_up("2")
        if bmask & 4:
            _inject_mouse_up("3")


def _validate_control_packet(peer_ip):
    """Validate if control packet should be processed. Returns True if valid."""
    if not host_state.session_active:
        logging.debug(f"Ignoring control packet from {peer_ip} (no active session)")
        return False

    if host_state.authed_client_ip:
        if peer_ip != host_state.authed_client_ip:
            logging.warning(f"Rejected control packet from {peer_ip} — active client: {host_state.authed_client_ip}")
            return False
    else:
        logging.debug(f"Ignoring early control packet from {peer_ip} (auth IP not yet set)")
        return False

    return True


def _process_control_command(tokens):
    """Process a control command from client."""
    if not tokens:
        return

    cmd = tokens[0].upper()

    if cmd == "NET":
        _handle_net_mode_change(tokens)
    elif cmd == "GOODBYE":
        _handle_goodbye()
    elif cmd == "MOUSE_PKT":
        _handle_mouse_packet(tokens)
    elif cmd == "MOUSE_SCROLL" and len(tokens) == PROTOCOL_CMD_AND_ARG:
        _inject_scroll(tokens[1])
    elif cmd == "KEY_PRESS" and len(tokens) == PROTOCOL_CMD_AND_ARG:
        _inject_key("down", tokens[1])
    elif cmd == "KEY_RELEASE" and len(tokens) == PROTOCOL_CMD_AND_ARG:
        _inject_key("up", tokens[1])


def control_listener(sock):
    # Optimize socket for low-latency control input
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
        if IS_LINUX:
            # SO_BUSY_POLL for ultra-low latency (requires root or CAP_NET_ADMIN)
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, 46, UDP_BUSY_POLL_USEC)  # SO_BUSY_POLL=46
    except OSError as e:
        logging.debug(f"Control socket optimization failed (non-critical): {e}")

    logging.info("Control listener UDP %d", UDP_CONTROL_PORT)
    while not host_state.should_terminate:
        try:
            data, addr = sock.recvfrom(2048)
            peer_ip = addr[0]

            if not _validate_control_packet(peer_ip):
                continue

            msg = data.decode("utf-8", errors="ignore").strip()
            if not msg:
                continue

            tokens = msg.split()
            _process_control_command(tokens)

        except OSError:
            break
        except Exception as e:
            trigger_shutdown(f"Control listener error: {e}")
            break


def clipboard_monitor_host():
    if not HAVE_PYPERCLIP:
        logging.info("pyperclip not available; host clipboard sync disabled.")
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_clipboard_addr = None  # Track client's ephemeral port

    while not host_state.should_terminate:
        current = ""
        with contextlib.suppress(Exception):
            current = (pyperclip.paste() or "").strip()
        with host_state.clipboard_lock:
            if (
                not host_state.ignore_clipboard_update
                and current
                and current != host_state.last_clipboard_content
                and host_state.client_ip
            ):
                host_state.last_clipboard_content = current
                msg = f"CLIPBOARD_UPDATE HOST {current}".encode()
                try:
                    # Send to client's ephemeral port if known, otherwise to well-known port
                    if client_clipboard_addr:
                        sock.sendto(msg, client_clipboard_addr)
                    else:
                        sock.sendto(msg, (host_state.client_ip, UDP_CLIPBOARD_PORT))
                except Exception as e:
                    trigger_shutdown(f"Clipboard send error: {e}")
                    break

        # Check if we should update client address from listener
        if hasattr(host_state, "client_clipboard_addr"):
            client_clipboard_addr = host_state.client_clipboard_addr

        time.sleep(1)
    sock.close()


def clipboard_listener_host(sock):
    if not HAVE_PYPERCLIP:
        return

    # Optimize socket for clipboard data
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
    except OSError as e:
        logging.debug(f"Clipboard socket optimization failed (non-critical): {e}")

    while not host_state.should_terminate:
        try:
            data, addr = sock.recvfrom(65535)
            msg = data.decode("utf-8", errors="ignore")

            # Handle keepalive messages from client (used to establish connection)
            if msg.strip() == "CLIPBOARD_KEEPALIVE":
                if addr[0] == host_state.client_ip or not host_state.client_ip:
                    host_state.client_clipboard_addr = addr
                    logging.debug(f"Client clipboard address registered from keepalive: {addr}")
                continue

            tokens = msg.split(maxsplit=2)
            if len(tokens) >= CLIPBOARD_UPDATE_MIN_PARTS and tokens[0] == "CLIPBOARD_UPDATE" and tokens[1] == "CLIENT":
                # Remember client's ephemeral port for responses
                if addr[0] == host_state.client_ip:
                    host_state.client_clipboard_addr = addr
                    logging.debug(f"Client clipboard address updated to {addr}")

                new_content = tokens[2]
                with host_state.clipboard_lock:
                    host_state.ignore_clipboard_update = True
                    try:
                        if (pyperclip.paste() or "") != new_content:
                            pyperclip.copy(new_content)
                    except Exception as e:
                        trigger_shutdown(f"Clipboard apply error: {e}")
                        break
                    finally:
                        host_state.ignore_clipboard_update = False
        except OSError:
            break
        except Exception as e:
            trigger_shutdown(f"Clipboard listener error: {e}")
            break


def recvall(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def file_upload_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host_state.file_upload_sock = s
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host_args_manager.args.bind_address, FILE_UPLOAD_PORT))
        s.listen(5)
        logging.info("File upload listener TCP %d", FILE_UPLOAD_PORT)
    except Exception as e:
        trigger_shutdown(f"File upload listener bind/listen failed: {e}")
        try:
            s.close()
        finally:
            host_state.file_upload_sock = None
        return

    while not host_state.should_terminate:
        try:
            conn, addr = s.accept()
            peer_ip = addr[0]

            # SECURITY: Verify client is authenticated before accepting uploads
            if not host_state.session_active or peer_ip != host_state.authed_client_ip:
                logging.warning(f"[SECURITY] Rejected file upload from unauthenticated client {peer_ip}")
                conn.close()
                continue

            header = recvall(conn, 4)
            if not header:
                conn.close()
                continue
            filename_length = int.from_bytes(header, "big")
            filename = recvall(conn, filename_length).decode("utf-8")
            file_size = int.from_bytes(recvall(conn, 8), "big")

            dest_dir = Path.home() / "LinuxPlayDrop"
            dest_dir.mkdir(parents=True, exist_ok=True)

            # SECURITY: Sanitize filename to prevent path traversal
            # Remove any path components, use only the basename
            safe_filename = Path(filename).name
            if not safe_filename or safe_filename.startswith("."):
                logging.warning(f"[SECURITY] Rejected invalid filename: {filename}")
                conn.close()
                continue

            dest_path = (dest_dir / safe_filename).resolve()

            # SECURITY: Verify resolved path is within dest_dir
            if not dest_path.is_relative_to(dest_dir.resolve()):
                logging.warning(f"[SECURITY] Path traversal attempt blocked: {filename} -> {dest_path}")
                conn.close()
                continue

            with dest_path.open("wb") as f:
                remaining = file_size
                while remaining > 0:
                    chunk = conn.recv(min(4096, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
            conn.close()
            logging.info("Received file %s (%d bytes) from %s", dest_path, file_size, peer_ip)
        except OSError:
            break
        except Exception as e:
            trigger_shutdown(f"File upload error: {e}")
            break
    try:
        s.close()
    finally:
        host_state.file_upload_sock = None


def _handle_heartbeat_timeout(now):
    """Handle heartbeat timeout with exponential backoff."""
    timeout_count = host_state.perf_metrics.get("heartbeat_timeouts", 0)
    cooldown = min(
        RECONNECT_COOLDOWN * (2 ** min(timeout_count, HEARTBEAT_BACKOFF_EXPONENT_MAX)),
        HEARTBEAT_MAX_BACKOFF_SECS,
    )

    logging.warning(
        "Heartbeat timeout from %s (timeout #%d) — no PONG or GOODBYE for %.1fs, stopping streams. Cooldown: %.1fs",
        host_state.client_ip,
        timeout_count + 1,
        now - host_state.last_pong_ts,
        cooldown,
    )

    host_state.perf_metrics["heartbeat_timeouts"] += 1

    try:
        stop_streams_only()
    except Exception as e:
        logging.error("Error stopping streams after timeout: %s", e)

    host_state.last_disconnect_ts = now
    host_state.client_ip = None
    host_state.starting_streams = False
    set_status("Client disconnected — waiting for connection…")
    host_state.session_active = False
    host_state.authed_client_ip = None
    pin_rotate_if_needed(force=True)

    time.sleep(cooldown)


def _send_heartbeat_ping(sock, client_heartbeat_addr, last_ping, now):
    """Send PING to client and return updated last_ping timestamp."""
    if now - last_ping < HEARTBEAT_INTERVAL:
        return last_ping

    try:
        if client_heartbeat_addr:
            sock.sendto(b"PING", client_heartbeat_addr)
        else:
            sock.sendto(b"PING", (host_state.client_ip, UDP_HEARTBEAT_PORT))
        return now
    except Exception as e:
        logging.warning("Heartbeat send error: %s", e)
        return last_ping


def _receive_heartbeat_pong(sock, client_heartbeat_addr, now):
    """Receive PONG from client and return updated client_heartbeat_addr."""
    sock.settimeout(0.5)
    try:
        data, addr = sock.recvfrom(1024)
        msg = data.decode("utf-8", errors="ignore").strip()
        if msg.startswith("PONG") and addr[0] == host_state.client_ip:
            host_state.last_pong_ts = now
            if not client_heartbeat_addr or client_heartbeat_addr != addr:
                client_heartbeat_addr = addr
                logging.debug(f"Client heartbeat address updated to {addr}")
    except TimeoutError:
        pass
    except Exception as e:
        logging.debug("Heartbeat recv error: %s", e)

    return client_heartbeat_addr


def _check_heartbeat_timeout(now, client_heartbeat_addr):
    """Check for heartbeat timeout and handle if necessary. Returns updated client_heartbeat_addr."""
    if (now - host_state.last_pong_ts) > HEARTBEAT_TIMEOUT and (
        now - host_state.last_disconnect_ts
    ) > HEARTBEAT_RECONNECT_GRACE_SECS:
        if host_state.client_ip:
            _handle_heartbeat_timeout(now)
            client_heartbeat_addr = None
        host_state.last_pong_ts = now
    elif host_state.client_ip and (now - host_state.last_pong_ts) < HEARTBEAT_INTERVAL * 2:
        if host_state.perf_metrics.get("heartbeat_timeouts", 0) > 0:
            logging.debug("Heartbeat recovered, resetting timeout counter")

    return client_heartbeat_addr


def heartbeat_manager(_args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        _optimize_udp_socket(s, send_buf=True, recv_buf=True)
        s.bind((_args.bind_address, UDP_HEARTBEAT_PORT))
        host_state.heartbeat_sock = s
        logging.info("Heartbeat manager running on UDP %d (responds to client's source port)", UDP_HEARTBEAT_PORT)
    except Exception as e:
        trigger_shutdown(f"Heartbeat socket error: {e}")
        return

    last_ping = 0.0
    host_state.last_pong_ts = time.time()
    client_heartbeat_addr = None

    while not host_state.should_terminate:
        now = time.time()

        try:
            log_performance_metrics()
        except Exception as e:
            logging.debug(f"Performance metrics logging failed: {e}")

        if host_state.client_ip:
            last_ping = _send_heartbeat_ping(s, client_heartbeat_addr, last_ping, now)
            client_heartbeat_addr = _receive_heartbeat_pong(s, client_heartbeat_addr, now)
            client_heartbeat_addr = _check_heartbeat_timeout(now, client_heartbeat_addr)
        else:
            client_heartbeat_addr = None
            time.sleep(0.5)


def resource_monitor():
    p = psutil.Process(os.getpid())

    def get_host_memory_mb():
        total = 0
        try:
            total += p.memory_info().rss
            children = list(p.children(recursive=True))
        except Exception:
            return total / (1024 * 1024)

        for child in children:
            with contextlib.suppress(Exception):
                cname = child.name().lower()
                if "ffmpeg" in cname:
                    total += child.memory_info().rss
        return total / (1024 * 1024)

    def read_gpu_usage():
        if not HAVE_PYNVML:
            return None
        try:
            pynvml.nvmlInit()
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            return f"GPU: {util.gpu}% VRAM: {util.memory}% (NVENC)"
        except Exception:
            pass

        try:
            for card in Path("/sys/class/drm").iterdir():
                busy_path = card / "device" / "gpu_busy_percent"
                if busy_path.exists():
                    with busy_path.open() as f:
                        val = f.read().strip()
                        return f"GPU: {val}% (VAAPI)"
        except Exception:
            pass

        try:
            cmd = ["timeout", "0.5", "intel_gpu_top", "-J"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            if '"Busy"' in out:
                j = json.loads(out)
                busy = j["engines"]["Render/3D/0"]["busy"]
                return f"GPU: {busy}% (iGPU)"
        except Exception:
            pass

        return ""

    while not host_state.should_terminate:
        cpu = p.cpu_percent(interval=1)
        mem = get_host_memory_mb()
        gpu_info = read_gpu_usage()
        logging.info(f"[MONITOR] CPU: {cpu:.1f}% | RAM: {mem:.1f} MB" + (f" | {gpu_info}" if gpu_info else ""))
        time.sleep(5)


def stats_broadcast():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    p = psutil.Process(os.getpid())

    def get_host_memory_mb():
        total = 0
        try:
            total += p.memory_info().rss
            children = list(p.children(recursive=True))
        except Exception:
            return total / (1024 * 1024)

        for child in children:
            with contextlib.suppress(Exception):
                cname = child.name().lower()
                if "ffmpeg" in cname:
                    total += child.memory_info().rss
        return total / (1024 * 1024)

    while not host_state.should_terminate:
        if host_state.client_ip:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = get_host_memory_mb()

                gpu = 0.0
                if not HAVE_PYNVML:
                    gpu = 0.0
                else:
                    try:
                        pynvml.nvmlInit()
                        h = pynvml.nvmlDeviceGetHandleByIndex(0)
                        gpu = float(pynvml.nvmlDeviceGetUtilizationRates(h).gpu)
                    except Exception:
                        try:
                            for card in Path("/sys/class/drm").iterdir():
                                busy_path = card / "device" / "gpu_busy_percent"
                                if busy_path.exists():
                                    with busy_path.open() as f:
                                        gpu = float(f.read().strip())
                                    break
                        except Exception:
                            gpu = 0.0

                fps = getattr(host_state, "current_fps", 0)
                msg = f"STATS {cpu:.1f} {gpu:.1f} {mem:.1f} {fps:.1f}"
                sock.sendto(msg.encode("utf-8"), (host_state.client_ip, UDP_HEARTBEAT_PORT))
            except Exception:
                pass
        time.sleep(1)


class GamepadServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._running = True
        self.sock = None
        self.ui = None
        self._dpad = {"left": False, "right": False, "up": False, "down": False}
        self._hatx = 0
        self._haty = 0

    def _open_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Use larger receive buffer for gamepad events
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVLOWAT, 1)
        if IS_LINUX:
            # SO_BUSY_POLL for gamepad input responsiveness
            with contextlib.suppress(OSError):
                s.setsockopt(socket.SOL_SOCKET, 46, UDP_BUSY_POLL_USEC)  # SO_BUSY_POLL=46
        s.bind((host_args_manager.args.bind_address, UDP_GAMEPAD_PORT))
        s.setblocking(False)
        return s

    def _open_uinput(self):
        if not (IS_LINUX and HAVE_UINPUT):
            return None
        caps = {
            ecodes.EV_KEY: [
                ecodes.BTN_SOUTH,
                ecodes.BTN_EAST,
                ecodes.BTN_NORTH,
                ecodes.BTN_WEST,
                ecodes.BTN_TL,
                ecodes.BTN_TR,
                ecodes.BTN_TL2,
                ecodes.BTN_TR2,
                ecodes.BTN_SELECT,
                ecodes.BTN_START,
                ecodes.BTN_THUMBL,
                ecodes.BTN_THUMBR,
                getattr(ecodes, "BTN_MODE", 0x13C),
            ],
            ecodes.EV_ABS: [
                (ecodes.ABS_X, AbsInfo(0, -32768, 32767, 16, 0, 0)),
                (ecodes.ABS_Y, AbsInfo(0, -32768, 32767, 16, 0, 0)),
                (ecodes.ABS_RX, AbsInfo(0, -32768, 32767, 16, 0, 0)),
                (ecodes.ABS_RY, AbsInfo(0, -32768, 32767, 16, 0, 0)),
                (ecodes.ABS_Z, AbsInfo(0, 0, 255, 0, 0, 0)),
                (ecodes.ABS_RZ, AbsInfo(0, 0, 255, 0, 0, 0)),
                (ecodes.ABS_HAT0X, AbsInfo(0, -1, 1, 0, 0, 0)),
                (ecodes.ABS_HAT0Y, AbsInfo(0, -1, 1, 0, 0, 0)),
            ],
        }
        ui = UInput(
            caps,
            name="LinuxPlay Virtual Gamepad",
            bustype=0x03,
            vendor=0x045E,
            product=0x028E,
            version=0x0110,
        )
        ui.write(ecodes.EV_ABS, ecodes.ABS_Z, 0)
        ui.write(ecodes.EV_ABS, ecodes.ABS_RZ, 0)
        ui.syn()
        return ui

    def _process_dpad_event(self, c, v, pending):
        """Process D-pad key event and update HAT axes."""
        if c == ecodes.KEY_LEFT:
            self._dpad["left"] = v != 0
        elif c == ecodes.KEY_RIGHT:
            self._dpad["right"] = v != 0
        elif c == ecodes.KEY_UP:
            self._dpad["up"] = v != 0
        elif c == ecodes.KEY_DOWN:
            self._dpad["down"] = v != 0

        new_hatx = (
            -1
            if self._dpad["left"] and not self._dpad["right"]
            else (1 if self._dpad["right"] and not self._dpad["left"] else 0)
        )
        new_haty = (
            -1
            if self._dpad["up"] and not self._dpad["down"]
            else (1 if self._dpad["down"] and not self._dpad["up"] else 0)
        )

        if new_hatx != self._hatx:
            self._hatx = new_hatx
            pending.append((ecodes.EV_ABS, ecodes.ABS_HAT0X, self._hatx))
        if new_haty != self._haty:
            self._haty = new_haty
            pending.append((ecodes.EV_ABS, ecodes.ABS_HAT0Y, self._haty))

    def _process_gamepad_events(self, buf, n, pending):
        """Process gamepad events from buffer."""
        unpack_event = struct.Struct("!Bhh").unpack_from

        for i in range(0, n - 4, 5):
            try:
                t, c, v = unpack_event(buf, i)
            except Exception:
                continue
            if not self.ui:
                continue

            if t == ecodes.EV_KEY and c in (ecodes.KEY_LEFT, ecodes.KEY_RIGHT, ecodes.KEY_UP, ecodes.KEY_DOWN):
                self._process_dpad_event(c, v, pending)
            else:
                pending.append((t, c, v))

    def _receive_and_process_events(self, buf, pending):
        """Receive and process gamepad events. Returns True to continue, False to break."""
        try:
            n, _ = self.sock.recvfrom_into(buf)
        except BlockingIOError:
            time.sleep(0.0005)
            return True
        except OSError:
            return False

        if n < GAMEPAD_MIN_PACKET_SIZE:
            return True

        try:
            self._process_gamepad_events(buf, n, pending)

            if pending:
                for et, ec, ev in pending:
                    self.ui.write(et, ec, ev)
                self.ui.syn()
                pending.clear()

        except Exception as e:
            logging.debug("Gamepad parse/write error: %s", e)

        return True

    def run(self):
        with contextlib.suppress(Exception):
            psutil.Process(os.getpid()).nice(-10)

        try:
            self.sock = self._open_socket()
            self.ui = self._open_uinput()
            if not self.ui:
                logging.info("Gamepad server active (pass-through), but uinput unavailable.")
            else:
                logging.info("Gamepad server active on UDP %d with virtual device.", UDP_GAMEPAD_PORT)
        except Exception as e:
            logging.error("Gamepad server init failed: %s", e)
            return

        buf = bytearray(64)
        pending = []

        while self._running and not host_state.should_terminate:
            if not self._receive_and_process_events(buf, pending):
                break

        try:
            if self.ui:
                self.ui.close()
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    def stop(self):
        self._running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass


def session_manager(args):
    while not host_state.should_terminate:
        if time.time() - host_state.last_disconnect_ts < RECONNECT_COOLDOWN:
            time.sleep(0.5)
            continue

        if host_state.client_ip and not host_state.video_threads:
            set_status(f"Client: {host_state.client_ip}")
            start_streams_for_current_client(args)
        time.sleep(0.5)


def _signal_handler(signum, _frame):
    logging.info("Signal %s received, shutting down…", signum)
    trigger_shutdown(f"Signal {signum}")
    stop_all()
    with contextlib.suppress(SystemExit):
        sys.exit(0)


def _initialize_sockets(bind_address):
    """Initialize all server sockets. Returns True on success, False on error."""
    try:
        host_state.handshake_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_state.handshake_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        host_state.handshake_sock.bind((bind_address, TCP_HANDSHAKE_PORT))
        host_state.handshake_sock.listen(5)
    except Exception as e:
        trigger_shutdown(f"Handshake socket error: {e}")
        return False

    try:
        host_state.control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host_state.control_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        host_state.control_sock.bind((bind_address, UDP_CONTROL_PORT))
    except Exception as e:
        trigger_shutdown(f"Control socket error: {e}")
        return False

    try:
        host_state.clipboard_listener_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host_state.clipboard_listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        host_state.clipboard_listener_sock.bind((bind_address, UDP_CLIPBOARD_PORT))
    except Exception as e:
        trigger_shutdown(f"Clipboard socket error: {e}")
        return False

    return True


def _start_server_threads(args):
    """Start all server threads."""
    threading.Thread(
        target=tcp_handshake_server, args=(host_state.handshake_sock, args.encoder, args), daemon=True
    ).start()
    threading.Thread(target=clipboard_monitor_host, daemon=True).start()
    threading.Thread(target=clipboard_listener_host, args=(host_state.clipboard_listener_sock,), daemon=True).start()
    threading.Thread(target=file_upload_listener, daemon=True).start()
    threading.Thread(target=heartbeat_manager, args=(args,), daemon=True).start()
    threading.Thread(target=session_manager, args=(args,), daemon=True).start()
    threading.Thread(target=control_listener, args=(host_state.control_sock,), daemon=True).start()
    threading.Thread(target=resource_monitor, daemon=True).start()
    threading.Thread(target=stats_broadcast, daemon=True).start()
    threading.Thread(target=pin_manager_thread, daemon=True).start()

    if IS_LINUX:
        try:
            host_state.gamepad_thread = GamepadServer()
            host_state.gamepad_thread.start()
        except Exception as e:
            logging.error("Failed to start gamepad server: %s", e)


def core_main(args, use_signals=True) -> int:
    if use_signals:
        try:
            for _sig in (signal.SIGINT, signal.SIGTERM):
                signal.signal(_sig, _signal_handler)
        except Exception:
            pass

    logging.debug("FFmpeg marker in use: %s", _marker_value())

    host_state.current_bitrate = args.bitrate
    host_state.monitors = detect_monitors() or [(1920, 1080, 0, 0)]
    host_args_manager.args = args

    if not _initialize_sockets(args.bind_address):
        stop_all()
        return 1

    _start_server_threads(args)

    pin_rotate_if_needed(force=True)
    logging.info("Waiting for client handshake…")
    logging.info("Host running. Close window or Ctrl+C to quit.")
    exit_code = 0
    try:
        while not host_state.should_terminate:
            time.sleep(0.2)
    except KeyboardInterrupt:
        trigger_shutdown("KeyboardInterrupt")
    finally:
        reason = host_state.shutdown_reason
        stop_all()
        if reason:
            logging.critical("Stopped due to error: %s", reason)
            exit_code = 1
        else:
            logging.info("Shutdown complete.")
    return exit_code


class LogEmitter:
    """Thread-safe event emitter for log messages and status updates."""

    def __init__(self):
        self.log_callbacks = []
        self.status_callbacks = []

    def connect_log(self, callback):
        self.log_callbacks.append(callback)

    def connect_status(self, callback):
        self.status_callbacks.append(callback)

    def emit_log(self, msg: str):
        for callback in self.log_callbacks:
            callback(msg)

    def emit_status(self, msg: str):
        for callback in self.status_callbacks:
            callback(msg)


log_emitter = LogEmitter()


def set_status(text: str):
    with contextlib.suppress(Exception):
        log_emitter.emit_status(text)


class TkLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()

    def emit(self, record):
        try:
            msg = self.format(record)
        except Exception:
            msg = record.getMessage()
        with contextlib.suppress(Exception):
            log_emitter.emit_log(msg)


def _apply_dark_theme(root: tk.Tk):
    """Apply dark theme to tkinter window."""
    bg_dark = "#353535"
    fg_light = "#ffffff"

    root.configure(bg=bg_dark)

    # Configure ttk styles
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TLabel", background=bg_dark, foreground=fg_light)
    style.configure("TButton", background=bg_dark, foreground=fg_light)
    style.configure("TFrame", background=bg_dark)


class HostWindow:
    def __init__(self, root: tk.Tk, args):
        self.root = root
        self.args = args
        self.core_thread = None
        self.core_rc = None
        self.stop_enabled = False

        self.root.title("LinuxPlay Host")
        self.root.geometry("840x520")

        # Status label
        self.status_label = ttk.Label(root, text="Idle", font=("sans-serif", 10))
        self.status_label.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        # Log view (scrolled text)
        self.log_view = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            font=("monospace", 9),
            bg="#232323",
            fg="#ffffff",
            insertbackground="#ffffff",
            state=tk.DISABLED,
        )
        self.log_view.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Button frame
        button_frame = tk.Frame(root, bg="#353535")
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

        self.stop_btn = ttk.Button(button_frame, text="Stop", command=self._on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.RIGHT, padx=5)

        # Setup logging
        self._log_handler = TkLogHandler()
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
        self._log_handler.setFormatter(fmt)
        logging.getLogger().addHandler(self._log_handler)

        log_emitter.connect_log(self.append_log)
        log_emitter.connect_status(self.set_status_text)

        # Enable stop button after delay
        self.root.after(1200, self._enable_stop_button)

        # Start core
        self._start_core()

        # Poll for core completion
        self._poll_core_done()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _enable_stop_button(self):
        self.stop_enabled = True
        self.stop_btn.config(state=tk.NORMAL)

    def _start_core(self):
        self.set_status_text("Starting…")
        self.append_log("Launching host core…")
        self.core_rc = None

        def _run():
            rc = core_main(self.args, use_signals=False)
            self.core_rc = rc
            self.root.after(0, lambda: self.root.quit())

        self.core_thread = threading.Thread(target=_run, name="HostCore", daemon=True)
        self.core_thread.start()

    def _poll_core_done(self):
        """Poll for core termination and disable stop button if terminated."""
        if host_state.should_terminate:
            self.stop_btn.config(state=tk.DISABLED)
        else:
            self.root.after(300, self._poll_core_done)

    def _on_stop(self):
        if not self.stop_enabled:
            return
        self.stop_btn.config(state=tk.DISABLED)
        self.stop_enabled = False
        self.append_log("Stop requested by user.")
        trigger_shutdown("User pressed Stop")

    def append_log(self, text: str):
        """Thread-safe log append."""

        def _append():
            self.log_view.config(state=tk.NORMAL)
            self.log_view.insert(tk.END, text + "\n")
            self.log_view.see(tk.END)
            self.log_view.config(state=tk.DISABLED)

        # Ensure we're on main thread
        if threading.current_thread() is threading.main_thread():
            _append()
        else:
            self.root.after(0, _append)

    def set_status_text(self, text: str):
        """Thread-safe status update."""

        def _update():
            self.status_label.config(text=text)

        if threading.current_thread() is threading.main_thread():
            _update()
        else:
            self.root.after(0, _update)

    def _on_close(self):
        if not host_state.should_terminate:
            trigger_shutdown("Window closed")
        self.root.destroy()


def parse_args():
    p = argparse.ArgumentParser(description="LinuxPlay Host (Linux only)")
    p.add_argument("--gui", action="store_true", help="Show host GUI window.")
    p.add_argument(
        "--hardware-report",
        action="store_true",
        help="Display comprehensive hardware detection report and exit. "
        "Shows CPU topology, GPU capabilities, available encoders, NUMA configuration, "
        "and optimization recommendations for low-latency streaming.",
    )
    p.add_argument(
        "--bind-address",
        default="127.0.0.1",
        help="IP address to bind server sockets to. Default: 127.0.0.1 (localhost only). "
        "For LAN access, use your interface IP (e.g., 192.168.1.100). "
        "For WAN, use WireGuard tunnel IP. NEVER use 0.0.0.0 on untrusted networks.",
    )
    p.add_argument("--encoder", choices=["none", "h.264", "h.265"], default="none")
    p.add_argument(
        "--hwenc",
        choices=["auto", "cpu", "nvenc", "qsv", "vaapi"],
        default="auto",
        help="Manual encoder backend selection (auto=heuristic).",
    )
    p.add_argument("--framerate", default=DEFAULT_FPS)
    p.add_argument("--bitrate", default=LEGACY_BITRATE)
    p.add_argument("--audio", choices=["enable", "disable"], default="disable")
    p.add_argument("--adaptive", action="store_true")
    p.add_argument("--display", default=":0")
    p.add_argument("--preset", default="")
    p.add_argument("--gop", default="30")
    p.add_argument("--qp", default="")
    p.add_argument("--tune", default="")
    p.add_argument("--pix_fmt", default="yuv420p")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def _print_hardware_section(title, data, format_func):
    """Print a section of the hardware report."""
    if not data:
        return
    print(f"[{title}]")
    format_func(data)
    print()


def _format_platform_info(report):
    """Format platform information."""
    print(f"  OS: {report['platform']['os']}")
    print(f"  Architecture: {report['platform']['arch']}")
    print(f"  Linux: {report['platform']['is_linux']}")


def _format_cpu_info(cpu):
    """Format CPU information."""
    print(f"  Logical cores: {cpu.get('logical_cores', 'N/A')}")
    print(f"  Physical cores: {cpu.get('physical_cores', 'N/A')}")
    print(f"  Hyperthreading: {cpu.get('hyperthreading', 'N/A')}")
    print(f"  Intel CPU: {cpu.get('is_intel', 'N/A')}")
    if cpu.get("heterogeneous"):
        print("  Heterogeneous: Yes (P-cores + E-cores)")
        print(f"  P-cores: {cpu.get('p_cores', [])}")
        print(f"  E-cores: {cpu.get('e_cores', [])}")
    else:
        print("  Heterogeneous: No")


def _format_gpu_info(gpu):
    """Format GPU information."""
    print(f"  NVIDIA: {gpu.get('nvidia', False)}")
    if gpu.get("nvidia_model"):
        print(f"  NVIDIA Model: {gpu['nvidia_model']}")
    print(f"  VAAPI available: {gpu.get('vaapi_available', False)}")


def _format_numa_info(numa):
    """Format NUMA information."""
    print(f"  Multi-socket system: {numa.get('multi_socket', False)}")
    if numa.get("gpu_node") is not None:
        print(f"  GPU NUMA node: {numa['gpu_node']}")


def _format_accelerators_info(accelerators):
    """Format hardware accelerators information."""
    print(f"  FFmpeg hwaccels: {', '.join(sorted(accelerators)) or 'none'}")


def _format_encoders_info(encoders):
    """Format encoders information."""
    for name, info in sorted(encoders.items()):
        status = "✓ Available" if info["available"] else "✗ Not available"
        if "tested" in info:
            status += f" (tested: {'✓ works' if info['tested'] else '✗ failed'})"
        print(f"  {name:20s}: {status}")


def _format_affinity_info(affinity):
    """Format CPU affinity information."""
    print(f"  Recommended cores: {affinity}")
    print("  (Physical cores for lowest latency streaming)")


def _format_warnings_info(warnings):
    """Format warnings and recommendations."""
    import textwrap

    for i, warning in enumerate(warnings, 1):
        wrapped = textwrap.fill(warning, width=66, subsequent_indent="    ")
        print(f"  {i}. {wrapped}")


def _print_hardware_report(report):
    """Print the complete hardware report."""
    print("\n" + "=" * 70)
    print("LinuxPlay Hardware Detection Report")
    print("=" * 70 + "\n")

    _print_hardware_section("Platform", report, _format_platform_info)
    _print_hardware_section("CPU", report.get("cpu"), _format_cpu_info)
    _print_hardware_section("GPU", report.get("gpu"), _format_gpu_info)
    _print_hardware_section("NUMA", report.get("numa"), _format_numa_info)
    _print_hardware_section("Hardware Accelerators", report.get("accelerators"), _format_accelerators_info)
    _print_hardware_section("Encoders", report.get("encoders"), _format_encoders_info)
    _print_hardware_section("CPU Affinity", report.get("affinity"), _format_affinity_info)
    _print_hardware_section("Warnings & Recommendations", report.get("warnings"), _format_warnings_info)

    print("=" * 70 + "\n")


def main():
    args = parse_args()

    logging.basicConfig(
        level=(logging.DEBUG if args.debug else logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if not IS_LINUX:
        logging.critical("Hosting is Linux-only. Run this on a Linux machine.")
        return 2

    if args.hardware_report:
        report = generate_hardware_report()
        _print_hardware_report(report)
        return 0

    if args.gui:
        root = tk.Tk()
        _apply_dark_theme(root)
        window = HostWindow(root, args)
        root.mainloop()
        rc = window.core_rc if window.core_rc is not None else 0
        sys.exit(rc)
    else:
        rc = core_main(args, use_signals=True)
        sys.exit(rc)


if __name__ == "__main__":
    main()
