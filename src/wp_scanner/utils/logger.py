"""
Sophisticated logging module with colored output and formatting.
"""

import sys
from datetime import datetime
from typing import Optional
from enum import Enum


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"

    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


class LogLevel(Enum):
    """Log levels with associated styling."""
    DEBUG = ("DEBUG", Colors.DIM + Colors.WHITE, "[.]")
    INFO = ("INFO", Colors.CYAN, "[*]")
    SUCCESS = ("SUCCESS", Colors.BRIGHT_GREEN, "[+]")
    WARNING = ("WARNING", Colors.BRIGHT_YELLOW, "[!]")
    ERROR = ("ERROR", Colors.RED, "[-]")
    CRITICAL = ("CRITICAL", Colors.BOLD + Colors.BRIGHT_RED, "[!!!]")
    VULN = ("VULN", Colors.BOLD + Colors.MAGENTA, "[VULN]")
    SCAN = ("SCAN", Colors.BRIGHT_BLUE, "[SCAN]")


class Logger:
    """Sophisticated logger with colored output."""

    def __init__(self, name: str = "WPScanner", use_colors: bool = True,
                 verbose: bool = False, log_file: Optional[str] = None):
        self.name = name
        self.use_colors = use_colors and sys.stdout.isatty()
        self.verbose = verbose
        self.log_file = log_file
        self._file_handle = None

        if log_file:
            self._file_handle = open(log_file, 'a')

    def __del__(self):
        if self._file_handle:
            self._file_handle.close()

    def _colorize(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if self.use_colors:
            return f"{color}{text}{Colors.RESET}"
        return text

    def _format_message(self, level: LogLevel, message: str,
                        show_time: bool = False) -> str:
        """Format a log message with level indicator and optional timestamp."""
        _, color, symbol = level.value

        parts = []

        if show_time:
            timestamp = datetime.now().strftime("%H:%M:%S")
            parts.append(self._colorize(f"[{timestamp}]", Colors.DIM))

        parts.append(self._colorize(symbol, color))
        parts.append(message)

        return " ".join(parts)

    def _log(self, level: LogLevel, message: str, show_time: bool = False):
        """Internal logging method."""
        formatted = self._format_message(level, message, show_time)
        print(formatted)

        # Also write to file if configured
        if self._file_handle:
            # Strip colors for file output
            plain_msg = f"[{datetime.now().isoformat()}] [{level.value[0]}] {message}\n"
            self._file_handle.write(plain_msg)
            self._file_handle.flush()

    def debug(self, message: str):
        """Log debug message (only in verbose mode)."""
        if self.verbose:
            self._log(LogLevel.DEBUG, message)

    def info(self, message: str):
        """Log informational message."""
        self._log(LogLevel.INFO, message)

    def success(self, message: str):
        """Log success message."""
        self._log(LogLevel.SUCCESS, message)

    def warning(self, message: str):
        """Log warning message."""
        self._log(LogLevel.WARNING, message)

    def error(self, message: str):
        """Log error message."""
        self._log(LogLevel.ERROR, message)

    def critical(self, message: str):
        """Log critical message."""
        self._log(LogLevel.CRITICAL, message)

    def vuln(self, message: str):
        """Log vulnerability finding."""
        self._log(LogLevel.VULN, message)

    def scan(self, message: str):
        """Log scan activity."""
        self._log(LogLevel.SCAN, message)

    def banner(self, text: str, char: str = "=", width: int = 70):
        """Print a banner/separator."""
        line = char * width
        if self.use_colors:
            line = self._colorize(line, Colors.BRIGHT_BLUE)
        print(f"\n{line}")
        print(self._colorize(text.center(width), Colors.BOLD + Colors.WHITE))
        print(f"{line}\n")

    def section(self, title: str, char: str = "-", width: int = 50):
        """Print a section header."""
        line = char * width
        if self.use_colors:
            print(self._colorize(f"\n{title}", Colors.BOLD + Colors.CYAN))
            print(self._colorize(line, Colors.DIM))
        else:
            print(f"\n{title}")
            print(line)

    def table_row(self, columns: list, widths: list, colors: list = None):
        """Print a formatted table row."""
        parts = []
        for i, (col, width) in enumerate(zip(columns, widths)):
            text = str(col)[:width].ljust(width)
            if colors and i < len(colors) and colors[i]:
                text = self._colorize(text, colors[i])
            parts.append(text)
        print(" ".join(parts))

    def progress(self, current: int, total: int, prefix: str = "Progress",
                 width: int = 40):
        """Print a progress bar."""
        percent = current / total if total > 0 else 0
        filled = int(width * percent)
        bar = "█" * filled + "░" * (width - filled)

        if self.use_colors:
            bar = self._colorize(bar, Colors.BRIGHT_GREEN if percent == 1 else Colors.CYAN)

        sys.stdout.write(f"\r{prefix}: [{bar}] {current}/{total} ({percent*100:.1f}%)")
        sys.stdout.flush()

        if current == total:
            print()  # New line when complete

    def severity_color(self, severity: str) -> str:
        """Get color for a severity level."""
        severity_colors = {
            'CRITICAL': Colors.BOLD + Colors.BRIGHT_RED,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'INFO': Colors.CYAN,
        }
        return severity_colors.get(severity.upper(), Colors.WHITE)


def setup_logger(name: str = "WPScanner", verbose: bool = False,
                 log_file: Optional[str] = None) -> Logger:
    """Factory function to create a configured logger."""
    return Logger(name=name, verbose=verbose, log_file=log_file)
