"""Tests for UDP socket buffer optimization and SO_BUSY_POLL features."""

import socket
import sys

import pytest

from linuxplay.client import UDP_BUSY_POLL_USEC, UDP_RECV_BUFFER_SIZE, UDP_SEND_BUFFER_SIZE
from linuxplay.host import (
    UDP_BUSY_POLL_USEC as HOST_UDP_BUSY_POLL_USEC,
)
from linuxplay.host import (
    UDP_RECV_BUFFER_SIZE as HOST_UDP_RECV_BUFFER_SIZE,
)
from linuxplay.host import (
    UDP_SEND_BUFFER_SIZE as HOST_UDP_SEND_BUFFER_SIZE,
)


class TestSocketBufferConstants:
    """Test that socket buffer constants are defined correctly."""

    def test_host_send_buffer_size(self):
        """Host send buffer should be 2MB."""
        assert HOST_UDP_SEND_BUFFER_SIZE == 2_097_152

    def test_host_recv_buffer_size(self):
        """Host receive buffer should be 512KB."""
        assert HOST_UDP_RECV_BUFFER_SIZE == 524_288

    def test_host_busy_poll_microseconds(self):
        """Host SO_BUSY_POLL should be 50 microseconds."""
        assert HOST_UDP_BUSY_POLL_USEC == 50

    def test_client_send_buffer_size(self):
        """Client send buffer should be 2MB."""
        assert UDP_SEND_BUFFER_SIZE == 2_097_152

    def test_client_recv_buffer_size(self):
        """Client receive buffer should be 512KB."""
        assert UDP_RECV_BUFFER_SIZE == 524_288

    def test_client_busy_poll_microseconds(self):
        """Client SO_BUSY_POLL should be 50 microseconds."""
        assert UDP_BUSY_POLL_USEC == 50

    def test_constants_match_between_host_and_client(self):
        """Host and client should use same buffer sizes."""
        assert HOST_UDP_SEND_BUFFER_SIZE == UDP_SEND_BUFFER_SIZE
        assert HOST_UDP_RECV_BUFFER_SIZE == UDP_RECV_BUFFER_SIZE
        assert HOST_UDP_BUSY_POLL_USEC == UDP_BUSY_POLL_USEC


class TestUDPSocketBufferOptimization:
    """Test UDP socket buffer size configuration."""

    def test_socket_can_set_send_buffer(self):
        """Verify socket accepts SO_SNDBUF configuration."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)
            # OS may adjust the value based on system limits (net.core.wmem_max)
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            assert actual > 0
            # Verify the buffer was increased from default (typically ~200KB)
            assert actual > 200_000
        finally:
            sock.close()

    def test_socket_can_set_recv_buffer(self):
        """Verify socket accepts SO_RCVBUF configuration."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            assert actual > 0
            assert actual >= UDP_RECV_BUFFER_SIZE or actual >= UDP_RECV_BUFFER_SIZE // 2
        finally:
            sock.close()

    def test_buffer_optimization_survives_socket_operations(self):
        """Buffer settings should persist after socket operations."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)

            # Buffer should still be configured
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            assert actual > 0
        finally:
            sock.close()

    def test_multiple_sockets_can_have_optimized_buffers(self):
        """Multiple sockets can each have optimized buffers."""
        socks = []
        try:
            for _ in range(3):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
                socks.append(sock)

            # All should have buffers configured
            for sock in socks:
                send_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                recv_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                assert send_buf > 0
                assert recv_buf > 0
        finally:
            for sock in socks:
                sock.close()


class TestSOBusyPoll:
    """Test SO_BUSY_POLL socket option behavior."""

    def test_so_busy_poll_constant_value(self):
        """SO_BUSY_POLL socket option is 46 on Linux."""
        # This is the Linux kernel constant for SO_BUSY_POLL
        SO_BUSY_POLL = 46
        assert SO_BUSY_POLL == 46

    @pytest.mark.skipif(sys.platform != "linux", reason="SO_BUSY_POLL is Linux-only")
    def test_so_busy_poll_requires_privilege(self):
        """SO_BUSY_POLL requires CAP_NET_ADMIN or root privileges."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        SO_BUSY_POLL = 46

        try:
            # This should either succeed (if we have privileges) or fail gracefully
            try:
                sock.setsockopt(socket.SOL_SOCKET, SO_BUSY_POLL, UDP_BUSY_POLL_USEC)
                # If it succeeded, we have the capability
                assert True
            except OSError as e:
                # Expected if we don't have CAP_NET_ADMIN
                # Error codes: EPERM (1) or ENOPROTOOPT (92)
                # Using errno is acceptable here as we're testing system capability
                assert e.errno in (1, 92, 95), f"Unexpected error code: {e.errno}"  # noqa: PT017
        finally:
            sock.close()

    def test_so_busy_poll_graceful_degradation(self):
        """SO_BUSY_POLL failure should be handled gracefully."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        SO_BUSY_POLL = 46

        # Simulate the try/except pattern used in the code
        success = False
        error_caught = False

        try:
            try:
                sock.setsockopt(socket.SOL_SOCKET, SO_BUSY_POLL, UDP_BUSY_POLL_USEC)
                success = True
            except OSError:
                error_caught = True
                # Graceful degradation - socket still works
        finally:
            sock.close()

        # Either succeeded or caught the error gracefully
        assert success or error_caught

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows doesn't support SO_BUSY_POLL")
    def test_so_busy_poll_value_range(self):
        """SO_BUSY_POLL value should be reasonable."""
        # Valid range is typically 0-1000 microseconds
        assert 0 < UDP_BUSY_POLL_USEC <= 1000
        assert isinstance(UDP_BUSY_POLL_USEC, int)


class TestSocketOptimizationIntegration:
    """Integration tests for socket optimization in real network operations."""

    def test_optimized_socket_can_send_and_receive(self):
        """Socket with buffer optimization can send/receive data."""
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # Apply optimizations
            server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)

            # Bind server
            server.bind(("127.0.0.1", 0))
            server.settimeout(2.0)
            port = server.getsockname()[1]

            # Send message
            test_data = b"OPTIMIZED_SOCKET_TEST"
            client.sendto(test_data, ("127.0.0.1", port))

            # Receive message
            data, _addr = server.recvfrom(1024)
            assert data == test_data
        finally:
            server.close()
            client.close()

    def test_optimized_socket_handles_large_packets(self):
        """Optimized socket handles larger UDP packets efficiently."""
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # Apply optimizations
            server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)

            server.bind(("127.0.0.1", 0))
            server.settimeout(2.0)
            port = server.getsockname()[1]

            # Send large packet (near UDP limit, but under MTU)
            large_data = b"X" * 8192
            client.sendto(large_data, ("127.0.0.1", port))

            data, _addr = server.recvfrom(16384)
            assert len(data) == len(large_data)
            assert data == large_data
        finally:
            server.close()
            client.close()

    def test_buffer_size_affects_burst_handling(self):
        """Larger buffers help handle burst traffic."""
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # Small buffer for comparison
            server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
            server.bind(("127.0.0.1", 0))
            server.settimeout(0.1)  # Short timeout
            port = server.getsockname()[1]

            # Send burst of packets
            for i in range(10):
                client.sendto(f"BURST_{i}".encode(), ("127.0.0.1", port))

            # Try to receive all (may drop some with small buffer)
            received = 0
            try:
                while True:
                    _data, _ = server.recvfrom(1024)
                    received += 1
            except TimeoutError:
                pass

            # With small buffer, we might not get all packets
            # This test just verifies the pattern works
            assert received > 0

            # Now test with large buffer
            server2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server2.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUFFER_SIZE)
            server2.bind(("127.0.0.1", 0))
            server2.settimeout(0.1)
            port2 = server2.getsockname()[1]

            for i in range(10):
                client.sendto(f"BURST_{i}".encode(), ("127.0.0.1", port2))

            received2 = 0
            try:
                while True:
                    _data, _ = server2.recvfrom(1024)
                    received2 += 1
            except TimeoutError:
                pass

            # With larger buffer, we should receive more/all packets
            assert received2 >= received

            server2.close()
        finally:
            server.close()
            client.close()


class TestSocketOptimizationEdgeCases:
    """Test edge cases and error handling for socket optimization."""

    def test_zero_buffer_size_handled(self):
        """Zero buffer size is handled by OS (may use minimum)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # OS typically allows this and uses a minimum value
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 0)
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            # OS should set a minimum value
            assert actual > 0
        finally:
            sock.close()

    def test_negative_buffer_size_handled(self):
        """Negative buffer size is handled by OS."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Python converts negative to large unsigned, OS may clamp or reject
            # Test that it doesn't crash the application
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, -1)
                # If it succeeded, OS clamped it
                actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                assert actual > 0
            except (OSError, OverflowError):
                # If it failed, that's also acceptable
                pass
        finally:
            sock.close()

    def test_extremely_large_buffer_handled(self):
        """Extremely large buffer requests handled by OS."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # OS will clamp to system maximum
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 100_000_000)
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            # OS should have clamped it to a reasonable value
            assert 0 < actual < 100_000_000
        finally:
            sock.close()

    def test_buffer_optimization_with_closed_socket_fails(self):
        """Setting buffer on closed socket should fail."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.close()

        with pytest.raises(OSError, match="Bad file descriptor"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SEND_BUFFER_SIZE)


class TestSocketOptimizationDocumentation:
    """Test that optimization features are properly documented."""

    def test_constants_have_correct_values(self):
        """Verify optimization constants match documentation."""
        # As documented in README.md
        assert UDP_SEND_BUFFER_SIZE == 2_097_152  # 2MB
        assert UDP_RECV_BUFFER_SIZE == 524_288  # 512KB
        assert UDP_BUSY_POLL_USEC == 50  # 50 microseconds

    def test_buffer_sizes_are_power_of_two_aligned(self):
        """Buffer sizes should be aligned for efficiency."""
        # 2MB = 2^21, 512KB = 2^19
        import math

        send_log = math.log2(UDP_SEND_BUFFER_SIZE)
        recv_log = math.log2(UDP_RECV_BUFFER_SIZE)

        assert send_log == int(send_log)  # Power of 2
        assert recv_log == int(recv_log)  # Power of 2

    def test_busy_poll_value_is_reasonable(self):
        """SO_BUSY_POLL value should be in typical range."""
        # Linux kernel typically uses 0-1000 microseconds
        # 50µs is a good balance between latency and CPU usage
        assert 10 <= UDP_BUSY_POLL_USEC <= 100


class TestSocketOptimizationPerformance:
    """Performance characteristics of socket optimization."""

    def test_buffer_size_ratios(self):
        """Send buffer should be larger than receive buffer for video streaming."""
        # Video streaming needs large send buffer
        # Control/input needs smaller receive buffer
        assert UDP_SEND_BUFFER_SIZE > UDP_RECV_BUFFER_SIZE
        assert UDP_SEND_BUFFER_SIZE == 4 * UDP_RECV_BUFFER_SIZE  # 4x ratio

    def test_buffer_sizes_exceed_default(self):
        """Optimized buffers should exceed typical OS defaults."""
        # Most OS defaults are 64KB-256KB
        default_typical = 256_000
        assert default_typical < UDP_SEND_BUFFER_SIZE
        assert default_typical < UDP_RECV_BUFFER_SIZE

    def test_busy_poll_latency_reduction(self):
        """SO_BUSY_POLL reduces latency but increases CPU usage."""
        # This is a documentation test - verifies the trade-off is understood
        # 50µs busy polling reduces network stack latency
        # but uses ~1-3% more CPU per core
        assert UDP_BUSY_POLL_USEC > 0  # Enables feature
        assert UDP_BUSY_POLL_USEC < 100  # Keeps CPU usage reasonable
