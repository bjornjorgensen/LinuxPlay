"""
Integration tests for the new challenge-response authentication protocol.
Tests Phase B implementation: CSR flow and signature verification.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch


class TestClientKeypairGeneration:
    """Test client-side keypair generation."""

    def test_ensure_client_keypair_creates_new(self):
        """Client should generate new keypair if none exists."""
        from linuxplay.client import _ensure_client_keypair

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.pem"
            assert not key_path.exists()

            result = _ensure_client_keypair(key_path)

            assert result is True  # Newly generated
            assert key_path.exists()
            assert key_path.stat().st_mode & 0o777 == 0o600  # Secure permissions

    def test_ensure_client_keypair_skips_existing(self):
        """Client should not regenerate existing keypair."""
        from linuxplay.client import _ensure_client_keypair

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.pem"

            # Create first time
            _ensure_client_keypair(key_path)
            first_content = key_path.read_bytes()

            # Call again
            result = _ensure_client_keypair(key_path)

            assert result is False  # Already exists
            assert key_path.read_bytes() == first_content  # Not regenerated

    def test_keypair_is_valid_rsa_4096(self):
        """Generated keypair should be valid RSA 4096-bit."""
        from cryptography.hazmat.primitives import serialization

        from linuxplay.client import _ensure_client_keypair

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.pem"
            _ensure_client_keypair(key_path)

            # Load and verify
            key_pem = key_path.read_bytes()
            private_key = serialization.load_pem_private_key(key_pem, password=None)

            assert private_key.key_size == 4096


class TestCSRGeneration:
    """Test Certificate Signing Request generation."""

    def test_generate_csr_from_keypair(self):
        """CSR generation should create valid request."""
        from cryptography import x509

        from linuxplay.client import _ensure_client_keypair, _generate_csr

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.pem"
            _ensure_client_keypair(key_path)

            csr_pem = _generate_csr(key_path, "test-client")

            assert csr_pem
            assert b"BEGIN CERTIFICATE REQUEST" in csr_pem

            # Verify CSR is valid
            csr = x509.load_pem_x509_csr(csr_pem)
            assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "test-client"

    def test_generate_csr_fails_without_key(self):
        """CSR generation should fail if no keypair exists."""
        from linuxplay.client import _generate_csr

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "nonexistent.pem"

            csr_pem = _generate_csr(key_path, "test-client")

            assert csr_pem == b""  # Failed


class TestChallengeResponse:
    """Test challenge signing and verification."""

    def test_sign_challenge_creates_valid_signature(self):
        """Client should sign challenge with private key."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from linuxplay.client import _ensure_client_keypair, _sign_challenge

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.pem"
            _ensure_client_keypair(key_path)

            challenge = b"test_challenge_32_bytes_long!!!!"
            signature = _sign_challenge(key_path, challenge)

            assert signature
            assert len(signature) > 0

            # Verify signature is valid
            from cryptography.hazmat.primitives import serialization

            key_pem = key_path.read_bytes()
            private_key = serialization.load_pem_private_key(key_pem, password=None)
            public_key = private_key.public_key()

            # Should not raise exception
            public_key.verify(
                signature,
                challenge,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )

    def test_host_verify_signature(self):
        """Host should verify client signature correctly."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization

        from linuxplay.client import _ensure_client_keypair, _generate_csr, _sign_challenge
        from linuxplay.host import _verify_signature

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.pem"
            _ensure_client_keypair(key_path)

            # Generate CSR and extract public key
            csr_pem = _generate_csr(key_path, "test-client")
            csr = x509.load_pem_x509_csr(csr_pem)

            # Create mock certificate with public key
            import datetime

            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID

            # Create self-signed cert for testing
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-client")])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
                .sign(ca_key, hashes.SHA256())
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            # Sign challenge with client key
            challenge = b"test_challenge_32_bytes_long!!!!"
            signature = _sign_challenge(key_path, challenge)

            # Host verifies signature
            result = _verify_signature(cert_pem, challenge, signature)

            assert result is True

    def test_host_reject_invalid_signature(self):
        """Host should reject invalid signatures."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from linuxplay.host import _verify_signature

        # Create test cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        challenge = b"test_challenge"
        invalid_signature = b"invalid_signature_bytes"

        result = _verify_signature(cert_pem, challenge, invalid_signature)

        assert result is False


class TestCAFingerprinting:
    """Test Trust On First Use (TOFU) CA fingerprint pinning."""

    def test_pin_ca_on_first_use(self):
        """First connection should pin CA fingerprint."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from linuxplay.client import _validate_host_ca_fingerprint

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test CA cert
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                .sign(key, hashes.SHA256())
            )
            ca_pem = cert.public_bytes(serialization.Encoding.PEM)

            # Mock home directory
            pinned_file = Path(tmpdir) / ".linuxplay" / "pinned_hosts.json"

            with patch("linuxplay.client.Path.home", return_value=Path(tmpdir)):
                result = _validate_host_ca_fingerprint(ca_pem, "192.168.1.100")

                assert result is True
                assert pinned_file.exists()

                # Check fingerprint was saved
                with pinned_file.open() as f:
                    pinned = json.load(f)
                assert "192.168.1.100" in pinned

    def test_detect_mitm_fingerprint_mismatch(self):
        """Should detect MITM attack when CA fingerprint changes."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from linuxplay.client import _validate_host_ca_fingerprint

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create first CA
            key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca-1")])
            cert1 = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key1.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                .sign(key1, hashes.SHA256())
            )
            ca1_pem = cert1.public_bytes(serialization.Encoding.PEM)

            # Create second CA (MITM attacker)
            key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject2 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca-2")])
            cert2 = (
                x509.CertificateBuilder()
                .subject_name(subject2)
                .issuer_name(subject2)
                .public_key(key2.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                .sign(key2, hashes.SHA256())
            )
            ca2_pem = cert2.public_bytes(serialization.Encoding.PEM)

            with patch("linuxplay.client.Path.home", return_value=Path(tmpdir)):
                # Pin first CA
                result1 = _validate_host_ca_fingerprint(ca1_pem, "192.168.1.100")
                assert result1 is True

                # Try second CA (MITM)
                result2 = _validate_host_ca_fingerprint(ca2_pem, "192.168.1.100")
                assert result2 is False  # Detected attack!

    def test_accept_same_ca_on_reconnect(self):
        """Should accept same CA fingerprint on subsequent connections."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from linuxplay.client import _validate_host_ca_fingerprint

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create CA
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                .sign(key, hashes.SHA256())
            )
            ca_pem = cert.public_bytes(serialization.Encoding.PEM)

            with patch("linuxplay.client.Path.home", return_value=Path(tmpdir)):
                # First connection
                result1 = _validate_host_ca_fingerprint(ca_pem, "192.168.1.100")
                assert result1 is True

                # Second connection (should verify against pinned)
                result2 = _validate_host_ca_fingerprint(ca_pem, "192.168.1.100")
                assert result2 is True


class TestHostCSRSigning:
    """Test host CSR signing (new secure mode)."""

    def test_host_signs_csr_correctly(self):
        """Host should sign client CSR without generating keys."""
        from cryptography import x509

        from linuxplay.client import _ensure_client_keypair, _generate_csr
        from linuxplay.host import _ensure_ca, _issue_client_cert

        with tempfile.TemporaryDirectory() as tmpdir:
            # Setup
            key_path = Path(tmpdir) / "client_key.pem"
            _ensure_client_keypair(key_path)
            csr_pem = _generate_csr(key_path, "test-client")

            # Mock host CA location
            with (
                patch("linuxplay.host.CA_KEY", str(Path(tmpdir) / "host_ca_key.pem")),
                patch("linuxplay.host.CA_CERT", str(Path(tmpdir) / "host_ca_cert.pem")),
            ):
                _ensure_ca()

                # Issue cert with CSR
                result = _issue_client_cert(client_name="test-client", export_hint_ip="192.168.1.100", csr_pem=csr_pem)

                assert result is not None
                assert "cert_pem" in result
                assert "ca_pem" in result
                assert "fingerprint" in result

                # Verify cert was signed, not generated with key
                cert = x509.load_pem_x509_certificate(result["cert_pem"])
                assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "test-client"

    def test_legacy_mode_still_works(self):
        """Legacy mode (server-generated keys) should still work for backward compat."""
        from linuxplay.host import _ensure_ca, _issue_client_cert

        with tempfile.TemporaryDirectory() as tmpdir:
            ca_key_path = Path(tmpdir) / "host_ca_key.pem"
            ca_cert_path = Path(tmpdir) / "host_ca_cert.pem"

            with patch("linuxplay.host.CA_KEY", str(ca_key_path)), patch("linuxplay.host.CA_CERT", str(ca_cert_path)):
                _ensure_ca()

                # Issue cert WITHOUT CSR (legacy mode)
                result = _issue_client_cert(client_name="legacy-client", export_hint_ip="192.168.1.100", csr_pem=None)

                assert result is not None
                assert "cert_pem" in result
                # Note: Legacy mode generates keys, so export_dir would have client_key.pem


class TestChallengeGeneration:
    """Test host challenge generation."""

    def test_generate_challenge_is_32_bytes(self):
        """Challenge should be 32 bytes."""
        from linuxplay.host import _generate_challenge

        challenge = _generate_challenge()

        assert len(challenge) == 32

    def test_generate_challenge_is_random(self):
        """Challenges should be unique."""
        from linuxplay.host import _generate_challenge

        challenges = [_generate_challenge() for _ in range(10)]

        # All should be unique
        assert len(set(challenges)) == 10
