"""Pytest configuration and shared fixtures."""

import platform
import subprocess
import sys
from unittest.mock import Mock

import pytest


# Mock PyQt5 and OpenGL before any test collection to avoid import errors
# This must happen before importing any LinuxPlay modules
mock_pyqt5 = Mock()
mock_qtcore = Mock()
mock_qthread = Mock()
mock_qtcore.QThread = mock_qthread
mock_qtcore.QTimer = Mock()
mock_qtcore.pyqtSignal = Mock()
mock_qtcore.Qt = Mock()
mock_qtwidgets = Mock()
mock_qtwidgets.QApplication = Mock()
mock_qtwidgets.QOpenGLWidget = Mock()
mock_qtopengl = Mock()
mock_qtgui = Mock()
mock_qtgui.QSurfaceFormat = Mock()

sys.modules["PyQt5"] = mock_pyqt5
sys.modules["PyQt5.QtCore"] = mock_qtcore
sys.modules["PyQt5.QtWidgets"] = mock_qtwidgets
sys.modules["PyQt5.QtOpenGL"] = mock_qtopengl
sys.modules["PyQt5.QtGui"] = mock_qtgui
sys.modules["OpenGL"] = Mock()
sys.modules["OpenGL.GL"] = Mock()

# Inject PyQt5 classes into builtins for client.py's unimported usage
# (client.py uses QThread and pyqtSignal without importing them - legacy issue)
import builtins  # noqa: E402  (must import after mocking sys.modules)


builtins.QThread = mock_qthread
builtins.pyqtSignal = mock_qtcore.pyqtSignal
builtins.QOpenGLWidget = mock_qtwidgets.QOpenGLWidget
builtins.QApplication = mock_qtwidgets.QApplication
builtins.QTimer = mock_qtcore.QTimer
builtins.QMainWindow = mock_qtwidgets.QMainWindow = Mock()
builtins.QWidget = mock_qtwidgets.QWidget = Mock()
builtins.QLabel = mock_qtwidgets.QLabel = Mock()
builtins.QPushButton = mock_qtwidgets.QPushButton = Mock()
builtins.QVBoxLayout = mock_qtwidgets.QVBoxLayout = Mock()
builtins.QHBoxLayout = mock_qtwidgets.QHBoxLayout = Mock()


@pytest.fixture
def mock_ffmpeg_available(monkeypatch):
    """Mock FFmpeg as available."""

    def mock_check_output(*_args, **_kwargs):
        return b"ffmpeg version 6.0"

    monkeypatch.setattr(subprocess, "check_output", mock_check_output)


@pytest.fixture
def mock_linux_platform(monkeypatch):
    """Mock platform as Linux."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")


@pytest.fixture
def mock_windows_platform(monkeypatch):
    """Mock platform as Windows."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
