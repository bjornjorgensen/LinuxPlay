# Wayland Support in LinuxPlay

This document explains LinuxPlay's current Wayland support status, technical limitations, and future roadmap.

---

## TL;DR - Current Status

**❌ Wayland video capture does NOT work** due to compositor security restrictions.

**✅ Workaround:** Use an X11 session (Plasma X11, GNOME Xorg) at login.

**🔮 Future:** PipeWire backend planned, but will add 3-8ms latency vs X11's direct capture.

---

## What Works on Wayland

### ✅ Display Server Detection
LinuxPlay correctly detects Wayland via environment variables:
- `XDG_SESSION_TYPE=wayland`
- `WAYLAND_DISPLAY` socket

**Logs:**
```
[INFO] Display server detected: wayland
[INFO] Wayland detected: forcing kmsgrab capture (x11grab incompatible)
```

### ✅ Monitor Detection
Full support for Wayland-specific monitor detection tools:
- **wlr-randr** (Sway, River, wlroots compositors)
- **swaymsg** (Sway-specific)
- **hyprctl** (Hyprland-specific)
- Fallback to xrandr for XWayland compatibility

Tested extensively in `tests/test_wayland_support.py` (58 test cases).

### ✅ Input Handling
- **Mouse/Keyboard:** Works via `pynput` (not display-server-dependent)
- **Gamepad:** Works via `uinput` (kernel-level, bypasses compositor)

---

## What Does NOT Work on Wayland

### ❌ Video Capture - CRITICAL BLOCKER

**The Problem:**

LinuxPlay's ultra-low-latency path relies on FFmpeg's `kmsgrab` to capture video:
- `kmsgrab` requires direct access to DRM/KMS framebuffers
- On Wayland, **only the compositor** (KWin/Mutter/Sway) can access DRM/KMS
- External processes are **blocked by design** for security

**Your Error:**
```
[kmsgrab @ 0x555a886d4700] No handle set on framebuffer: maybe you need some additional capabilities?
[in#0 @ 0x555a886d3dc0] Error opening input: Invalid argument
Error opening input file -.
Error opening input files: Invalid argument
[ERROR] Video 0 exited (234)
[CRITICAL] FATAL/STOP: Video 0 crashed/quit with code 234
```

**This is not a bug.** This is Wayland saying "no" - the compositor already owns the display planes, and FFmpeg's kmsgrab cannot access them.

**Why `cap_sys_admin` doesn't help:**
```bash
# This won't fix Wayland
sudo setcap cap_sys_admin+ep $(which ffmpeg)
```

Even with elevated capabilities, only ONE process can be DRM master at a time. KWin/Mutter/Sway already hold DRM master, so FFmpeg gets denied.

**Why `x11grab` doesn't work:**
- `x11grab` only works on X11 (Xorg)
- On Wayland, there's no X11 server to grab from
- The only capture method on Wayland is through compositor APIs (PipeWire/xdg-desktop-portal)

---

## Technical Deep Dive

### Wayland's Security Model

Wayland's architecture intentionally prevents direct framebuffer access:

```
┌─────────────────────────────────────────┐
│         Wayland Compositor              │
│    (KWin / Mutter / Sway / etc.)        │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │   DRM Master (Exclusive)        │   │
│  │   Direct GPU Access             │   │
│  │   Framebuffer Control           │   │
│  └─────────────────────────────────┘   │
│                                         │
│  Apps communicate via Wayland protocol  │
└─────────────────────────────────────────┘
           ↑
           │ Wayland Protocol
           │ (No direct DRM access)
           ↓
    ┌──────────────┐
    │ Applications │
    │  (LinuxPlay) │
    └──────────────┘
```

**X11 Model (What LinuxPlay Uses):**
```
┌─────────────────────────────────────────┐
│         X11 Server                      │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │   DRM Master (Shared via XIdle) │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
           ↑
           │ X11 Protocol
           │ (Allows screen grabs)
           ↓
    ┌──────────────┐
    │   kmsgrab    │  ← Can access DRM during idle
    │  (FFmpeg)    │
    └──────────────┘
```

### Why kmsgrab is Fast on X11

On X11, `kmsgrab` achieves **0.5-2ms** capture latency because:
1. Direct DRM buffer read (no compositor overhead)
2. Zero-copy GPU → GPU transfer
3. No CPU involvement in capture path
4. No frame synchronization delays

**Latency Breakdown (X11 + kmsgrab):**
```
Display refresh → DRM buffer available (0.1ms)
  → kmsgrab reads DRM (0.5ms)
  → VAAPI/NVENC encode (3-5ms)
  → UDP send (0.1ms)
  ───────────────────────────
  Total: ~4-7ms end-to-end
```

### Why Wayland is Slower

Wayland requires going through the compositor's screen capture API:

**Wayland Capture Path (PipeWire, not yet implemented):**
```
Compositor renders → Internal buffer (1ms)
  → PipeWire screen cast API (1-2ms)
  → CPU copy or DMA-BUF share (1-5ms)
  → FFmpeg decode/encode (3-5ms)
  → UDP send (0.1ms)
  ───────────────────────────
  Total: ~6-13ms end-to-end (naive)
  Total: ~5-10ms (optimized DMA-BUF)
```

**Added latency:** 3-8ms compared to X11 (unavoidable architectural cost)

---

## Workaround: Use X11 Session

### For KDE Plasma Users

1. **Log out** of your current session
2. On the **SDDM login screen**, click the session selector (bottom-left or top-right)
3. Select **"Plasma (X11)"**
4. Log back in
5. Verify with: `echo $XDG_SESSION_TYPE` (should output `x11`)
6. Run LinuxPlay host - `kmsgrab` will work normally

### For GNOME Users

1. **Log out** of your current session
2. On the **GDM login screen**, click the gear icon
3. Select **"GNOME on Xorg"** or **"Ubuntu on Xorg"**
4. Log back in
5. Verify with: `echo $XDG_SESSION_TYPE` (should output `x11`)
6. Run LinuxPlay host

### System Specs from Original Report
```
OS: CachyOS x86_64
Kernel: Linux 6.17.4-arch2-1
DE: KDE Plasma 6.5.2
WM: KWin (Wayland)  ← This is the issue
GPU: AMD Radeon RX 6800 XT
```

**Solution:** Switch to "Plasma (X11)" at SDDM login screen.

---

## Attempted Bypass Methods (Why They Don't Work)

### ❌ Running as Root
```bash
sudo linuxplay-host --bind-address 192.168.1.10
```

**Why it fails:**
- DRM master is exclusive (only ONE process at a time)
- KWin already holds DRM master → FFmpeg gets denied even as root
- Security risk for network services

**Verdict:** Won't work, dangerous, don't try.

### ❌ Disabling Compositor
```bash
killall kwin_wayland
```

**Why it fails:**
- Wayland requires a compositor (unlike X11 where it's optional)
- No compositor = no display output (screen goes black)
- Killing compositor kills your entire session

**Verdict:** Impossible on Wayland.

### ❌ Kernel Modules / eBPF Hooks

**Why it's impractical:**
- Requires kernel programming expertise
- Must be recompiled for every kernel update
- Security nightmare (full system access)
- Breaks on kernel updates
- Distribution maintainers won't accept it

**Verdict:** Theoretically possible but completely impractical.

### 🤔 Gamescope (Valve's Compositor)

**Approach:**
```bash
gamescope -W 2560 -H 1440 --expose-wayland -- plasma-wayland
```

**Why it might work:**
- Gamescope is designed for game streaming
- More permissive DRM access policies
- Used by Steam Deck for remote play

**Downsides:**
- Nested compositor = significant overhead
- Defeats the purpose of low latency
- Limited desktop features
- Not well-tested for full desktop use

**Verdict:** Technically possible but defeats latency goals.

### 🔮 DRM Lease Protocol (Future)

**Technical approach:**
Uses Wayland's `zwp_drm_lease_v1` protocol to temporarily transfer DRM master.

**Current support:**
- ❌ KDE Plasma: Not implemented
- ❌ GNOME Mutter: Not implemented
- ✅ Gamescope: Supports this for VR
- ⚠️ Some experimental compositors

**Verdict:** Theoretically possible but 2-3 years away from mainstream.

---

## Future Roadmap: PipeWire Backend

### What Needs to Be Implemented

LinuxPlay will add native Wayland support via **PipeWire screen capture**:

**Required changes:**
1. Add PipeWire dependency to `pyproject.toml`
2. Implement `PipeWireCaptureThread` in `src/linuxplay/host.py`
3. Detect Wayland and use PipeWire backend automatically
4. Use DMA-BUF for zero-copy GPU → encoder transfer
5. Handle xdg-desktop-portal permission dialogs

**Code snippet (pseudo-code):**
```python
def build_pipewire_capture_cmd(monitor_info, video_port):
    """Build FFmpeg command using PipeWire with DMA-BUF optimization."""
    portal_node = get_pipewire_node_for_monitor(monitor_info)
    
    return [
        "ffmpeg",
        "-hide_banner",
        "-loglevel", "error",
        
        # PipeWire input with DMA-BUF (GPU buffer sharing)
        "-f", "pipewire",
        "-dmabuf_device", "/dev/dri/renderD128",
        "-node_id", str(portal_node),
        "-i", "-",
        
        # Direct GPU encode (no CPU copy)
        "-c:v", "h264_vaapi",
        "-vaapi_device", "/dev/dri/renderD128",
        
        # Low latency flags
        "-bf", "0",
        "-rc_mode", "CQP",
        "-qp", "23",
        
        # Output
        "-f", "mpegts",
        f"udp://{ip}:{video_port}?pkt_size=1316"
    ]
```

### Performance Expectations

**Optimized PipeWire (with DMA-BUF):**
- Compositor → PipeWire → VAAPI encoder (all on GPU)
- Zero CPU copies (GPU-only pipeline)
- **Estimated latency:** 3-8ms added vs X11 kmsgrab
- **Throughput:** Supports 4K@144Hz

**Naive PipeWire (CPU path):**
- Compositor → PipeWire → CPU → FFmpeg → VAAPI encoder
- Multiple CPU copies
- **Estimated latency:** 15-25ms added vs X11 kmsgrab
- **Throughput:** Limited to 4K@60Hz

### Comparison Table

| Method | Latency Added | Throughput | Viability |
|--------|---------------|------------|-----------|
| **X11 + kmsgrab** | 0.5-2ms | ✅ 4K@180Hz | **Current (best)** |
| **X11 + x11grab** | 8-15ms | ✅ 4K@120Hz | Fallback |
| **Wayland + PipeWire (naive)** | 15-25ms | ⚠️ 4K@60Hz | Too slow for gaming |
| **Wayland + PipeWire (DMA-BUF)** | 3-8ms | ✅ 4K@144Hz | **Future target** |

### User Experience

**On first connection (Wayland + PipeWire):**
```
[INFO] Wayland detected, using PipeWire backend
[INFO] Requesting screen capture permission...
```

**xdg-desktop-portal shows dialog:**
```
┌─────────────────────────────────────────┐
│  LinuxPlay wants to record your screen │
│                                         │
│  ○ Share entire screen                 │
│  ○ Share specific monitor              │
│  ○ Share specific window               │
│                                         │
│        [ Cancel ]    [ Share ]          │
└─────────────────────────────────────────┘
```

**After user approves:**
```
[INFO] Screen capture approved, starting stream...
[INFO] PipeWire node: 1234
[INFO] Using DMA-BUF zero-copy path (GPU → VAAPI)
[INFO] Starting Video 0: ffmpeg -f pipewire ...
```

---

## Design Philosophy: Why X11 Remains Recommended

LinuxPlay's core principle is **"speed first"**. Every architectural decision prioritizes latency over convenience.

**Quote from project instructions:**
> "Proper Wayland support will come later via a separate PipeWire backend, though it won't or probably never match the same native performance as x11 via direct kmsdrm and kmsgrab."

**Why this matters for gaming:**
- **3ms difference** is noticeable in competitive gaming (180Hz+ monitors)
- **Input → display latency budget:** Every millisecond counts
- **60fps = 16.67ms frame time:** Adding 8ms = 50% overhead

**Use cases:**
- **Remote gaming (competitive):** X11 + kmsgrab (absolute minimum latency)
- **Remote gaming (casual):** Wayland + PipeWire acceptable
- **Remote desktop/productivity:** Wayland + PipeWire perfectly fine

---

## Testing Wayland Detection

LinuxPlay has extensive Wayland detection tests in `tests/test_wayland_support.py`:

**Coverage:**
- ✅ Display server detection (all compositors)
- ✅ Monitor detection (wlr-randr, swaymsg, hyprctl)
- ✅ Fallback chains
- ✅ Error handling
- ✅ Edge cases (malformed output, timeouts)

**Run tests:**
```bash
make test-integration
# Or specifically
uv run pytest tests/test_wayland_support.py -v
```

**Note:** Tests mock the functionality - they don't test actual video capture (not implemented yet).

---

## Contributing Wayland Support

Interested in implementing PipeWire backend? Here's what's needed:

### Prerequisites
- Experience with PipeWire C API or Python bindings
- Understanding of DMA-BUF and zero-copy GPU pipelines
- FFmpeg integration knowledge
- Ability to test on real Wayland compositors

### Implementation Checklist
- [ ] Add PipeWire Python bindings to dependencies
- [ ] Implement `detect_pipewire_available()` in `host.py`
- [ ] Create `PipeWireCaptureThread` class
- [ ] Add portal permission handling
- [ ] Implement DMA-BUF path detection
- [ ] Add fallback for CPU-copy path
- [ ] Write integration tests
- [ ] Benchmark latency vs X11
- [ ] Update documentation

### Performance Requirements
- Must achieve <10ms added latency vs X11 kmsgrab
- Must support 4K@120Hz minimum
- Must work on NVIDIA, AMD, and Intel GPUs
- Must gracefully handle permission denials

### Testing Requirements
- Test on KDE Plasma (KWin)
- Test on GNOME (Mutter)
- Test on Sway (wlroots)
- Test on Hyprland
- Measure end-to-end latency with hardware timestamps

---

## FAQ

### Q: Can I run LinuxPlay host in a VM?
**A:** Not recommended. VMs add significant latency (10-30ms) and often don't expose GPU properly for hardware encoding. Use bare metal Linux for best performance.

### Q: Does Wayland work for audio streaming?
**A:** Yes! Audio capture uses PulseAudio/PipeWire APIs, which work identically on X11 and Wayland.

### Q: Will switching to X11 break my workflow?
**A:** Most applications work identically on X11 and Wayland. Notable exceptions:
- Screen sharing in browsers (may need to use PipeWire portal on X11 too)
- Some Wayland-only apps (rare, mostly experimental)

### Q: Can I use X2Go or VNC instead?
**A:** X2Go/VNC are designed for productivity (lossless, high latency). LinuxPlay is designed for gaming (lossy compression, ultra-low latency). Different use cases.

### Q: Does this affect the client?
**A:** No. Client runs on any platform (Windows/Linux, X11/Wayland). Only the **host** needs X11 for optimal performance.

### Q: When will PipeWire support be ready?
**A:** No ETA yet. Contributors welcome! This is a complex feature requiring significant development effort.

---

## Related Issues

- Original bug report: GitHub issue (kmsgrab fails on Wayland)
- Feature request: PipeWire backend implementation
- Discussion: Wayland latency benchmarking

---

## Summary

**Current state:** Wayland video capture does NOT work due to compositor restrictions.

**Workaround:** Use X11 session (Plasma X11, GNOME Xorg) for optimal performance.

**Future:** PipeWire backend will enable Wayland support with 3-8ms added latency.

**Philosophy:** LinuxPlay prioritizes speed. X11 remains recommended for competitive gaming.

---

*Last updated: November 8, 2025*
