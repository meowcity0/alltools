import subprocess
import time
from rich.console import Console
from .models import CommandRecord, EnumSession


class Runner:
    def __init__(self, console: Console, session: EnumSession):
        self.console = console
        self.session = session

    def _full_cmd(self, cmd: list[str]) -> list[str]:
        return (["proxychains4", "-q"] + cmd) if self.session.use_proxy else cmd

    def run(self, cmd: list[str], label: str = "") -> CommandRecord:
        full_cmd = self._full_cmd(cmd)
        cmd_str = " ".join(full_cmd)
        self.console.print(f"[dim #8b949e]  ❯ {cmd_str}[/dim #8b949e]")

        start = time.time()
        result = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        duration = time.time() - start

        record = CommandRecord(
            command=cmd_str,
            output=result.stdout or "",
            return_code=result.returncode,
            duration=duration,
            label=label,
        )
        self.session.command_history.append(record)
        return record

    def start(self, cmd: list[str], label: str = "") -> tuple["subprocess.Popen[str]", str, float]:
        """Start a command non-blocking. Returns (proc, cmd_str, start_time)."""
        full_cmd = self._full_cmd(cmd)
        cmd_str = " ".join(full_cmd)
        self.console.print(f"[dim #8b949e]  ❯ {cmd_str}[/dim #8b949e]")
        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return proc, cmd_str, time.time()

    def collect(
        self,
        proc: "subprocess.Popen[str]",
        cmd_str: str,
        label: str,
        start_time: float,
    ) -> CommandRecord:
        """Wait for a Popen process and record its output."""
        stdout, _ = proc.communicate()
        duration = time.time() - start_time
        record = CommandRecord(
            command=cmd_str,
            output=stdout or "",
            return_code=proc.returncode,
            duration=duration,
            label=label,
        )
        self.session.command_history.append(record)
        return record
