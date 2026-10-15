"""Stdout notifier: prints the Markdown of each notification."""

import sys
from typing import TextIO

from icp_threat_intel.core.models import Notification


class StdoutNotifier:
    name = "stdout"

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream

    def notify(self, message: Notification) -> None:
        stream = self._stream or sys.stdout
        stream.write(message.markdown)
        if not message.markdown.endswith("\n"):
            stream.write("\n")
        stream.flush()
