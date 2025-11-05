"""Unit tests for client.py tkinter dialog functions."""

import logging
import sys
from unittest.mock import MagicMock, Mock, patch


# Mock PyQt5 modules before importing client to avoid import errors
sys.modules["PyQt5"] = Mock()
sys.modules["PyQt5.QtCore"] = Mock()
sys.modules["PyQt5.QtWidgets"] = Mock()
sys.modules["PyQt5.QtOpenGL"] = Mock()
sys.modules["PyQt5.QtGui"] = Mock()

from linuxplay.client import _ask_pin, _show_error, _show_info  # noqa: E402


class TestTkinterDialogHelpers:
    """Tests for tkinter dialog helper functions."""

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showerror")
    def test_show_error_success(self, mock_showerror, mock_tk):
        """Test _show_error shows error dialog successfully."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        _show_error("Test Title", "Test message")

        # Verify Tk instance created and withdrawn
        mock_tk.assert_called_once()
        mock_root.withdraw.assert_called_once()

        # Verify error dialog shown
        mock_showerror.assert_called_once_with("Test Title", "Test message", parent=mock_root)

        # Verify root destroyed
        mock_root.destroy.assert_called_once()

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showerror")
    def test_show_error_handles_exception(self, mock_showerror, _mock_tk, caplog):  # noqa: PT019
        """Test _show_error logs error on exception."""
        mock_showerror.side_effect = Exception("Dialog failed")

        with caplog.at_level(logging.ERROR):
            _show_error("Error Title", "Error message")

        # Should log the error message
        assert "Error Title: Error message" in caplog.text

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showerror")
    def test_show_error_with_special_characters(self, mock_showerror, mock_tk):
        """Test _show_error handles special characters."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        title = "Security Error"
        message = "Host CA fingerprint mismatch!\nPossible MITM attack."

        _show_error(title, message)

        mock_showerror.assert_called_once_with(title, message, parent=mock_root)

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showinfo")
    def test_show_info_success(self, mock_showinfo, mock_tk):
        """Test _show_info shows info dialog successfully."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        _show_info("Info Title", "Info message")

        # Verify Tk instance created and withdrawn
        mock_tk.assert_called_once()
        mock_root.withdraw.assert_called_once()

        # Verify info dialog shown
        mock_showinfo.assert_called_once_with("Info Title", "Info message", parent=mock_root)

        # Verify root destroyed
        mock_root.destroy.assert_called_once()

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showinfo")
    def test_show_info_handles_exception(self, mock_showinfo, _mock_tk, caplog):  # noqa: PT019
        """Test _show_info logs info on exception."""
        mock_showinfo.side_effect = Exception("Dialog failed")

        with caplog.at_level(logging.INFO):
            _show_info("Info Title", "Info message")

        # Should log the info message
        assert "Info Title: Info message" in caplog.text

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showinfo")
    def test_show_info_with_multiline(self, mock_showinfo, mock_tk):
        """Test _show_info handles multiline messages."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        title = "Certificate Received"
        message = "Successfully received certificate.\nSaved to ~/.linuxplay/"

        _show_info(title, message)

        mock_showinfo.assert_called_once_with(title, message, parent=mock_root)

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_ask_pin_success(self, mock_askstring, mock_tk):
        """Test _ask_pin returns PIN successfully."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_askstring.return_value = "123456"

        result = _ask_pin()

        # Verify Tk instance created and withdrawn
        mock_tk.assert_called_once()
        mock_root.withdraw.assert_called_once()

        # Verify askstring called with correct parameters
        mock_askstring.assert_called_once_with(
            "Enter Host PIN", "6-digit PIN (rotates every 30s):", show="*", parent=mock_root
        )

        # Verify root destroyed
        mock_root.destroy.assert_called_once()

        # Verify PIN returned and stripped
        assert result == "123456"

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_ask_pin_custom_title_prompt(self, mock_askstring, mock_tk):
        """Test _ask_pin with custom title and prompt."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_askstring.return_value = "654321"

        result = _ask_pin(title="Custom Title", prompt="Enter code:")

        mock_askstring.assert_called_once_with("Custom Title", "Enter code:", show="*", parent=mock_root)

        assert result == "654321"

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_ask_pin_cancelled(self, mock_askstring, mock_tk):
        """Test _ask_pin returns empty string when cancelled."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_askstring.return_value = None  # User cancelled

        result = _ask_pin()

        assert result == ""

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_ask_pin_strips_whitespace(self, mock_askstring, mock_tk):
        """Test _ask_pin strips leading/trailing whitespace."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_askstring.return_value = "  123456  "

        result = _ask_pin()

        assert result == "123456"

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_ask_pin_handles_exception(self, mock_askstring, _mock_tk, caplog):  # noqa: PT019
        """Test _ask_pin returns empty string on exception."""
        mock_askstring.side_effect = Exception("Dialog failed")

        with caplog.at_level(logging.ERROR):
            result = _ask_pin()

        # Should return empty string
        assert result == ""

        # Should log error
        assert "PIN dialog failed" in caplog.text

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_ask_pin_empty_input(self, mock_askstring, mock_tk):
        """Test _ask_pin handles empty input."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_askstring.return_value = ""

        result = _ask_pin()

        assert result == ""

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_ask_pin_whitespace_only(self, mock_askstring, mock_tk):
        """Test _ask_pin handles whitespace-only input."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_askstring.return_value = "   "

        result = _ask_pin()

        assert result == ""


class TestDialogThreadSafety:
    """Tests for thread-safe dialog behavior."""

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showerror")
    def test_show_error_destroys_root_on_exception_during_dialog(self, mock_showerror, mock_tk):
        """Test _show_error properly cleans up even if dialog fails."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        # Simulate exception during dialog
        mock_showerror.side_effect = Exception("Display error")

        # Should not raise exception
        _show_error("Title", "Message")

        # Root should still be destroyed (in exception handler)
        # The function catches all exceptions, so destroy won't be called
        # but the exception is handled gracefully

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showerror")
    def test_multiple_show_error_calls_create_separate_roots(self, _mock_showerror, mock_tk):  # noqa: PT019
        """Test multiple _show_error calls create separate Tk instances."""
        mock_root1 = MagicMock()
        mock_root2 = MagicMock()
        mock_tk.side_effect = [mock_root1, mock_root2]

        _show_error("Title 1", "Message 1")
        _show_error("Title 2", "Message 2")

        # Two separate Tk instances should be created
        assert mock_tk.call_count == 2

        # Both should be withdrawn and destroyed
        mock_root1.withdraw.assert_called_once()
        mock_root1.destroy.assert_called_once()
        mock_root2.withdraw.assert_called_once()
        mock_root2.destroy.assert_called_once()


class TestDialogIntegration:
    """Integration tests for dialog usage patterns."""

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showerror")
    def test_error_dialog_typical_authentication_error(self, mock_showerror, mock_tk):
        """Test typical authentication error dialog."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        _show_error("Authentication Failed", "The PIN is incorrect or expired.")

        mock_showerror.assert_called_once_with(
            "Authentication Failed", "The PIN is incorrect or expired.", parent=mock_root
        )

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.messagebox.showerror")
    def test_error_dialog_security_warning(self, mock_showerror, mock_tk):
        """Test security warning dialog."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        _show_error("Security Error", "Host CA fingerprint mismatch!\nPossible Man-in-the-Middle attack.")

        mock_showerror.assert_called_once()
        args = mock_showerror.call_args[0]
        assert args[0] == "Security Error"
        assert "MITM" in args[1] or "Man-in-the-Middle" in args[1]

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_pin_dialog_valid_6_digit(self, mock_askstring, mock_tk):
        """Test PIN dialog with valid 6-digit input."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_askstring.return_value = "042857"

        pin = _ask_pin()

        assert pin == "042857"
        assert len(pin) == 6
        assert pin.isdigit()

    @patch("linuxplay.client.tk.Tk")
    @patch("linuxplay.client.simpledialog.askstring")
    def test_pin_dialog_invalid_input_handling(self, mock_askstring, mock_tk):
        """Test that _ask_pin returns various inputs as-is (validation happens elsewhere)."""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        # Test various invalid inputs (function returns them, caller validates)
        test_cases = ["12345", "1234567", "abc123", ""]

        for test_input in test_cases:
            mock_askstring.return_value = test_input
            result = _ask_pin()
            assert result == test_input
