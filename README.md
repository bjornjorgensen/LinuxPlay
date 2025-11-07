# LinuxPlay

> The open source, ultra low latency remote desktop and game streaming stack for Linux. Built with FFmpeg, UDP and Qt.

![License: GPLv2](https://img.shields.io/badge/License-GPLv2-blue.svg)
![Platform: Linux Host](https://img.shields.io/badge/Host-Linux-green.svg)
![Platform: Windows Client](https://img.shields.io/badge/Client-Windows%20%7C%20Linux-blue.svg)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)
![FFmpeg](https://img.shields.io/badge/FFmpeg-Required-critical)

---

## Features

- **Codecs**: H.264 and H.265 (HEVC) with hardware acceleration via NVENC, QSV, VAAPI, AMF, or CPU fallback.
- **Transport**: Ultra low latency design. Video over MPEG-TS on UDP. Audio over UDP. Input for mouse, keyboard and gamepad over UDP. Clipboard on UDP. Handshake and file upload on TCP. Automatic socket buffer optimization (2MB send, 512KB receive) and optional `SO_BUSY_POLL` support for sub-100μs network latency.
- **Secure Handshake**
  - Modern challenge-response authentication with RSA 4096-bit keys
  - Client generates own keypair (private key never transmitted)
  - Certificate Signing Request (CSR) flow for secure first-time authentication
  - CA fingerprint pinning (Trust On First Use) prevents MITM attacks
  - Rotating 6-digit PIN for initial device pairing (refreshes every 30 seconds)
  - Session lock rejects new clients while another is connected (BUSY protection)
  - Legacy PIN-only authentication deprecated (migration required)
- **PIN to Certificate Upgrade**
  - On first connection, client generates RSA 4096-bit keypair locally
  - Client sends Certificate Signing Request (CSR) with PIN to host
  - Host validates PIN and signs CSR, returns certificate (private key never leaves client)
  - Certificates automatically stored in `~/.linuxplay/` directory
  - Subsequent connections use challenge-response authentication (no PIN needed)
  - GUI automatically detects certificates and disables PIN field
- **Controller Support**: Full gamepad forwarding over UDP using a virtual uinput device on the host. Works with Xbox, DualSense, 8BitDo and other HID controllers.
- **Multi Monitor**: Stream one or more displays. Resolution and offsets are detected per display.
- **Clipboard and File Transfer**: Bi directional clipboard sync and client to host file uploads on TCP.
- **Link Aware Streaming**: Buffers adapt for LAN and Wi Fi to reduce jitter and stalls.
- **Resilience**: Heartbeat with ping and pong. The host stops streams and returns to the waiting state on timeout or disconnect.
- **Stats Overlay (Client)**: Real time FPS, CPU, RAM and GPU metrics via OpenGL with triple buffered PBO uploads.
- **Firewall Friendly**: Windows clients no longer require firewall configuration. Uses outbound-only connections with ephemeral ports that work through NAT and firewalls automatically.
- **Cross Platform**: Host runs on Linux. Clients support both Linux and Windows 10/11.

---

## Why LinuxPlay

LinuxPlay is for people who want speed, control and transparency.  
No accounts. No hidden daemons. No black boxes.  
You pick the codec, bitrate, buffers and behavior. Every knob is exposed and does something you can measure.

---

## Architecture

**Network Design:**  
LinuxPlay uses a firewall-friendly architecture where the client initiates all connections using ephemeral ports. This allows Windows clients to work without firewall configuration, as Windows automatically permits responses to outbound connections.

```
Client                        Network           Host
------                        -------           ----
TCP handshake (7001)   <-------------------->  Handshake
UDP control (7000)      -------------------->  Input (mouse/keyboard)
UDP clipboard (7002)   <-------------------->  Clipboard sync (client initiates)
UDP heartbeat (7004)   <-------------------->  Keepalive (client sends PONG first)
UDP gamepad (7005)      -------------------->  Virtual gamepad (uinput)
UDP video (5000+idx)   <--------------------   FFmpeg capture + encode
UDP audio (6001)       <--------------------   FFmpeg Opus audio
TCP upload (7003)      --------------------->  File upload handler
```

**Key Design:**
- Client uses ephemeral (random high) ports for heartbeat and clipboard
- Host learns and responds to client's actual source port
- No client-side firewall rules needed on Windows
- Works through NAT/routers automatically

---

## Installation

### System Requirements

**Host (Linux):**
- Ubuntu 22.04+ (or equivalent)
- Python 3.11 or higher
- FFmpeg with hardware encoding support
- X11 or Wayland display server

**Client (Linux or Windows):**
- Python 3.11 or higher
- FFmpeg for audio playback
- OpenGL 3.0+ support
- PyQt5 for GUI (optional, CLI available)

### Ubuntu 24.04 packages

```bash
sudo apt update
sudo apt install -y ffmpeg xdotool xclip pulseaudio-utils libcap2-bin \
    wireguard-tools qrencode python3 python3-venv python3-pip libgl1 libegl1 \
    python3-evdev libxcb-xinerama0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 \
    libxcb-keysyms1 libxcb-randr0 libxcb-render-util0
```

If `pip install av` fails, install FFmpeg development headers:

```bash
sudo apt install -y pkg-config python3-dev libavdevice-dev libavfilter-dev libavformat-dev libavcodec-dev libswscale-dev libswresample-dev libavutil-dev
```

### Modern Setup with uv (Recommended)

[uv](https://github.com/astral-sh/uv) is a fast Python package manager written in Rust. It's significantly faster than pip and provides better dependency resolution.

#### Install uv

```bash
# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or with pip
pip install uv
```

#### Setup project with uv

```bash
# Clone the repository
git clone https://github.com/Techlm77/LinuxPlay.git
cd LinuxPlay

# Create virtual environment and install dependencies (uv does this automatically)
uv venv
uv pip install -e ".[dev]"

# Or use the Makefile
make install-dev
```

### Traditional Setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Linux or macOS
# .venv\Scripts\activate    # Windows PowerShell

python3 -m pip install -U pip wheel setuptools
python3 -m pip install PyQt5 PyOpenGL PyOpenGL_accelerate av numpy pynput pyperclip psutil evdev nvidia-ml-py cryptography
```

`evdev` is required on Linux clients for controller capture.  
`nvidia-ml-py` is optional but recommended for NVIDIA GPU monitoring.  
Hosting already requires Linux. Controller forwarding currently supports Linux to Linux.

---

## Usage

### Quick Start with Makefile

```bash
# Install dependencies
make install-dev

# Run the GUI launcher
make run-gui

# Or directly
make run-host    # Start host
make run-client  # Show client help
```

### GUI launcher

```bash
python3 src/linuxplay/start.py
# Or with uv
uv run python src/linuxplay/start.py
```
- Host tab. Pick a preset and select Start Host.
- Client tab. Enter the host LAN IP or WireGuard tunnel IP and select Start Client.
- The client GUI detects the certificate bundle if present and disables the PIN field automatically.

### Command line

```bash
# Host (with GUI - requires desktop session)
uv run python src/linuxplay/host.py --gui --encoder h.264 --hwenc auto --framerate 60 --bitrate 8M --audio enable --gop 15 --pix_fmt yuv420p

# Host (headless/SSH - no GUI)
uv run python src/linuxplay/host.py --encoder h.264 --hwenc auto --framerate 60 --bitrate 8M --audio enable --gop 15 --pix_fmt yuv420p

# Client (Linux or Windows)
uv run python src/linuxplay/client.py --host_ip SERVER_IP --decoder h.264 --hwaccel auto --audio enable --monitor 0 --gamepad enable --debug

# Or with traditional python3 (if not using uv)
python3 src/linuxplay/host.py --encoder h.264 --hwenc auto --framerate 60 --bitrate 8M --audio enable
python3 src/linuxplay/client.py --host_ip SERVER_IP --decoder h.264 --hwaccel auto --audio enable
```

---

## Network Modes

- The client auto detects whether the link is Wi Fi or Ethernet and announces NET WIFI or NET LAN.
- The host adjusts buffers for the detected link.
- Manual override is available with `client.py --net wifi` or `client.py --net lan`. Default is auto.

---

## Heartbeat and Reconnects

- The host sends PING every second and expects PONG within ten seconds.
- On timeout or client exit the host stops streams, clears state and returns to Waiting for connection.
- Reconnecting starts video and audio again without manual intervention.

---

## Ports on Host

The host listens on these ports. **The client does not need any firewall rules** as it uses outbound-only connections with ephemeral (randomly assigned) ports.

| Purpose                  | Protocol | Port            | Client Port        |
|--------------------------|----------|-----------------|-------------------|
| Handshake                | TCP      | 7001            | Ephemeral         |
| Video per monitor        | UDP      | 5000 plus index | Ephemeral         |
| Audio                    | UDP      | 6001            | Ephemeral         |
| Control mouse keyboard   | UDP      | 7000            | Ephemeral         |
| Clipboard                | UDP      | 7002            | Ephemeral         |
| File upload              | TCP      | 7003            | Ephemeral         |
| Heartbeat ping pong      | UDP      | 7004            | Ephemeral         |
| Gamepad controller       | UDP      | 7005            | Ephemeral         |

**Windows Client**: No firewall configuration needed. The client initiates all UDP connections, and Windows automatically allows responses on the same connection.

---

## Linux Capture Notes

- **kmsgrab** gives the lowest overhead and does not draw the cursor. Grant capability:
  ```bash
  sudo setcap cap_sys_admin+ep "$(command -v ffmpeg)"
  ```
- **x11grab** is the fallback when kmsgrab is not viable or you need cursor capture.
- **VAAPI** encode needs access to `/dev/dri/renderD128`. Add your user to the `video` group if needed.

---

## Ultra-Low Latency Mode (SO_BUSY_POLL)

LinuxPlay automatically optimizes all UDP sockets with larger buffers (2MB send, 512KB receive) to reduce packet loss and improve throughput.

For **absolute minimum latency** (sub-100 microsecond network stack latency), Linux kernels 3.11+ support `SO_BUSY_POLL` - a feature that keeps CPU cores actively polling the network interface instead of waiting for interrupts.

### When to Enable

- **Gaming/competitive scenarios** where every millisecond counts
- **LAN connections** (gigabit Ethernet) with stable, low-latency links
- Systems where **latency matters more than power consumption**

### How to Enable

Grant the `CAP_NET_ADMIN` capability to Python:

```bash
# Find your Python executable
which python3

# Grant capability (survives reboots)
sudo setcap cap_net_admin+ep /usr/bin/python3

# Verify
getcap /usr/bin/python3
# Should show: /usr/bin/python3 cap_net_admin=ep
```

**That's it!** LinuxPlay will automatically enable `SO_BUSY_POLL` on all latency-critical sockets (control, heartbeat, gamepad, clipboard) when the capability is available.

### Performance Impact

| Scenario | Without SO_BUSY_POLL | With SO_BUSY_POLL | Improvement |
|----------|---------------------|-------------------|-------------|
| Network stack latency | ~100-500μs | ~50-150μs | **50-70% lower** |
| Input responsiveness | Good | Excellent | Noticeable in FPS games |
| Packet loss (LAN) | <1% | <0.1% | **10x reduction** |
| CPU usage (idle) | Minimal | +1-3% per core | Small trade-off |

### Verification

Check logs for confirmation:

```bash
# Host
python src/linuxplay/host.py ...
# Look for: "Control listener UDP 7000" (no errors about socket optimization)

# Client  
python src/linuxplay/client.py ...
# Look for: "Heartbeat responder active" (no socket optimization warnings)
```

If you see `"socket optimization failed (non-critical)"` in debug logs, the capability isn't set - the application still works normally but without the extra latency reduction.

### Removing the Capability

```bash
sudo setcap -r /usr/bin/python3
```

### Alternative: Run as Root (Not Recommended)

```bash
# Works but security risk - only for testing
sudo python3 src/linuxplay/host.py ...
```

**Important**: SO_BUSY_POLL is completely optional. LinuxPlay works perfectly without it - you just won't get the absolute lowest possible latency (still much better than VNC/RDP/Parsec).

---

## Recommended Presets

- **Lowest Latency**. H.264 at 60 to 120 fps. GOP 8 to 15. Low latency tune.
- **Balanced**. H.264 at 45 to 75 fps. 4 to 10 Mbit per second. GOP 15.
- **High Quality**. H.265 at 30 to 60 fps. 12 to 20 Mbit per second. `yuv444p` if supported by your pipeline.

---

## Security

### Network Binding

**IMPORTANT**: By default, the host binds to `127.0.0.1` (localhost only). To allow connections:

- **Local testing**: Use default `127.0.0.1` (client runs on same machine)
- **LAN streaming**: Use `--bind-address <your-interface-ip>` (e.g., `192.168.1.100`)
- **WAN/remote**: Use WireGuard tunnel and bind to tunnel IP (e.g., `10.0.0.1`)
- **NEVER** use `--bind-address 0.0.0.0` on untrusted networks (exposes all interfaces)

Example for LAN access:
```bash
linuxplay-host --bind-address 192.168.1.100 --encoder h.264 --hwenc nvenc
```

### Authentication & Sessions

**Modern Secure Authentication (Recommended)**:
- Client generates own RSA 4096-bit keypair on first connection
- Certificate Signing Request (CSR) sent to host with PIN
- Host signs CSR and returns certificate (private key never leaves client)
- Subsequent connections use challenge-response authentication
- CA fingerprint pinning (Trust On First Use) prevents MITM attacks
- Certificates stored in `~/.linuxplay/` directory

**Legacy Authentication (DEPRECATED)**:
- ⚠️ **WARNING**: Legacy PIN-only and fingerprint-only authentication modes are deprecated
- Server-generated client keys (legacy mode) will be removed in a future release
- Existing legacy certificates still work but log deprecation warnings
- Migrate to secure mode: delete old certificates and reconnect with PIN to generate new keypair

**Session Management**:
- Use WireGuard for WAN use. Point the client to the tunnel IP.
- One active client at a time. Additional clients receive BUSY until the session ends.
- Revoke a client by removing the entry in `trusted_clients.json` on the host.

**Certificate Locations**:
- Client: `~/.linuxplay/client_key.pem` (private key, 0600 permissions)
- Client: `~/.linuxplay/client_cert.pem` (signed certificate)
- Client: `~/.linuxplay/host_ca.pem` (host CA certificate)
- Client: `~/.linuxplay/pinned_hosts.json` (pinned CA fingerprints for TOFU)
## Changelog (recent)

- **Added `nvidia-ml-py` dependency**: Official NVIDIA GPU monitoring library now properly declared in `pyproject.toml` (replaces deprecated `pynvml`)
- **Firewall-free Windows clients**: Redesigned network architecture to use outbound-only connections with ephemeral ports. Windows clients no longer require firewall configuration.
- **Enhanced Security**: Complete authentication redesign with RSA 4096-bit client keypairs, CSR flow, and challenge-response protocol
- **CA Fingerprint Pinning**: Trust On First Use (TOFU) prevents MITM attacks on subsequent connections
- **Automatic Certificate Storage**: Certificates now stored in `~/.linuxplay/` (no manual file copying required)
- **Deprecated Legacy Auth**: PIN-only and fingerprint-only modes marked for removal (migration recommended)
- Added certificate based authentication with automatic PIN to certificate upgrade flow.
- Added session lock. New handshakes are rejected with BUSY while a client is active.
- Client GUI now auto detects certificate bundle and disables the PIN field live.
- Improved heartbeat handling and reconnect behavior.
- Expanded controller support and stability.

---

## Performance Optimization

LinuxPlay includes automatic UDP socket optimizations (2MB send buffers, 512KB receive buffers) for all connections. For even lower latency, see the **[Ultra-Low Latency Mode (SO_BUSY_POLL)](#ultra-low-latency-mode-so_busy_poll)** section above.

For detailed performance tuning, system configuration, and advanced optimization techniques, see **[PERFORMANCE.md](PERFORMANCE.md)**.

Key topics covered:
- System configuration (kernel parameters, CPU governor, power management)
- Network optimization (MTU, ring buffers, UDP tuning, SO_BUSY_POLL)
- Encoding optimization (codec selection, GOP tuning, bitrate guidelines)
- CPU core affinity (P-core/E-core, NUMA awareness)
- GPU optimization (NVENC, QSV, VAAPI tuning)
- Monitoring and profiling tools
- Recommended configurations for gaming, productivity, and remote access

---

## Troubleshooting

### Host Issues

#### PyQt5 module not found

```bash
# Install all dependencies
uv pip install -e ".[dev]"
# Or with traditional pip
pip3 install PyQt5
```

#### Qt platform plugin "xcb" error

Install required X11 libraries:

```bash
sudo apt install -y libxcb-xinerama0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 \
    libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 \
    libxcb-xfixes0 libxcb-xkb1 libxkbcommon-x11-0
```

If running over SSH, either:
- Run on the actual desktop session (recommended)
- Use SSH with X11 forwarding: `ssh -X user@host`
- Set display: `export DISPLAY=:0`

#### VAAPI error: "No VA display found for device /dev/dri/renderD128"

Add your user to the video and render groups:

```bash
sudo usermod -a -G video,render $USER
# Log out and log back in for changes to take effect
```

Create persistent udev rule:

```bash
echo 'KERNEL=="renderD*", GROUP="render", MODE="0660"' | sudo tee /etc/udev/rules.d/70-render.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Verify access:

```bash
ls -l /dev/dri/renderD128
# Should show: crw-rw---- 1 root render ...
groups
# Should include: video render
```

Alternatively, use CPU encoding:

```bash
python src/linuxplay/host.py --hwenc cpu --encoder h.264
```

#### Gamepad error: "/dev/uinput" cannot be opened

```bash
sudo chmod 666 /dev/uinput
# Or add to input group:
sudo usermod -a -G input $USER
```

### Windows Client Issues

#### Windows Firewall blocking UDP packets (Legacy Issue - Fixed)

**As of the latest version, Windows clients no longer need firewall configuration!**

The client now uses outbound-only connections with ephemeral ports. Windows Firewall automatically allows responses to outbound connections, so no manual firewall rules are needed.

If you previously added firewall rules for LinuxPlay, you can safely remove them - they're no longer necessary.

**How it works:**
- Client initiates connections using random high ports (ephemeral)
- Host learns the client's actual port and responds there
- Windows sees these as responses to outbound connections and allows them
- Works through NAT and home routers automatically

#### ffplay not found (Audio error)

Download and install FFmpeg for Windows:
1. Download from [FFmpeg Builds](https://github.com/BtbN/FFmpeg-Builds/releases)
2. Extract and add to PATH
3. Or disable audio: `--audio disable`

#### Windows Firewall blocking UDP packets

Add firewall rule for Python:

```powershell
# Run PowerShell as Administrator
New-NetFirewallRule -DisplayName "LinuxPlay Client" -Direction Inbound `
    -Program "C:\Path\To\python.exe" -Action Allow -Profile Private
```

Or through GUI:
1. Windows Security → Firewall & network protection
2. Advanced settings → Inbound Rules → New Rule
3. Program → Browse to your Python executable
4. Allow the connection → Private networks
5. Name: "LinuxPlay Client"

#### OpenGL GLError on Windows

Use ANGLE backend for better Windows compatibility:

```powershell
$env:QT_OPENGL="angle"
$env:QT_ANGLE_PLATFORM="d3d11"
python src/linuxplay/client.py --host_ip YOUR_HOST_IP --decoder h.264 --hwaccel auto
```

### General Issues

#### PIN rotation or connection timeouts

- Ensure UDP ports 5000-7005 are accessible on the **host** (no client firewall config needed)
- Check firewall rules on the **host** machine
- Verify network connectivity: `ping YOUR_HOST_IP`
- For WAN connections, use WireGuard VPN
#### Certificate authentication not working

**Modern Authentication (v0.2.0+)**:
Certificates are automatically stored in `~/.linuxplay/` after first successful PIN authentication.
If you need to reset authentication:

```bash
# Delete old certificates to force re-authentication
rm -rf ~/.linuxplay/
```

**Legacy Mode (DEPRECATED)**:
If you have certificates in `src/linuxplay/` from older versions, migrate to secure mode:

```bash
# Remove old certificates
rm src/linuxplay/client_cert.pem src/linuxplay/client_key.pem src/linuxplay/host_ca.pem

# Reconnect with PIN - new certificates will be generated automatically
# New certs stored in ~/.linuxplay/ with secure permissions
```

Legacy server-generated keys are deprecated and will be removed in a future release.
- `host_ca.pem`

They should be next to `client.py` and `start.py` in `src/linuxplay/`.

#### Poor streaming quality or stuttering

- Check network bandwidth: `iperf3` between client and host
- Lower bitrate: `--bitrate 4M` or `--bitrate 6M`
- Reduce framerate: `--framerate 30`
- On WiFi, ensure good signal strength (> -60 dBm)
- Try `--net wifi` mode for WiFi connections

---

## Development

### Code Quality Tools

LinuxPlay uses modern Python tooling for development:

- **[uv](https://github.com/astral-sh/uv)**: Fast Python package manager (pip replacement)
- **[ruff](https://github.com/astral-sh/ruff)**: Extremely fast Python linter and formatter
- **[pytest](https://pytest.org)**: Comprehensive testing framework

### Running Tests

LinuxPlay includes a comprehensive test suite with 150+ tests covering utilities, authentication, and network protocols.

```bash
# Install test dependencies
make install-test

# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests only
make test-integration

# Run tests with coverage
make test-cov

# Quick interactive test runner
./run_tests.sh
```

See [tests/README.md](tests/README.md) for detailed testing documentation.

### Using ruff

```bash
# Format code
make format
# Or directly
uv run ruff format .

# Check for issues
make lint
# Or
uv run ruff check .

# Auto-fix issues
make fix
# Or
uv run ruff check . --fix
```

### Available Make Commands

```bash
make help          # Show all available commands
make install       # Install project dependencies
make install-dev   # Install with dev dependencies
make lint          # Run ruff linter
make format        # Format code with ruff
make check         # Check without making changes
make fix           # Auto-fix linting issues
make run-host      # Run the host application
make run-client    # Run the client application
make run-gui       # Run the GUI launcher
make clean         # Clean cache and build artifacts
```

---

## Support LinuxPlay

LinuxPlay is a fully open-source project built from scratch and originally maintained by a single developer in spare time.  
It has since grown into a collaborative, community-driven project thanks to contributors who share a passion for performance, networking, and open-source streaming technology.

If you enjoy LinuxPlay or use it in your workflow, you can help sustain and expand development through GitHub Sponsors:

[![Sponsor @Techlm77](https://img.shields.io/badge/Sponsor-Techlm77-pink.svg?logo=github-sponsors)](https://github.com/sponsors/Techlm77)

Your support helps cover hardware testing, development time, and ongoing improvements to performance, security, and cross-platform compatibility across many different Linux distros, while encouraging future contributors to join and help LinuxPlay continue to evolve.

---

## License

LinuxPlay is licensed under GNU GPL v2.0 only. See `LICENSE`.  
External tools such as FFmpeg, xdotool, xclip and ffplay are executed as separate processes and retain their own licenses.

---

Developed and maintained by [Techlm77](https://github.com/Techlm77) :)
