from datetime import datetime
from rich.console import Console


class HeartBeat:
    def __init__(self, console: Console):
        self.console = console
        self._start = datetime.now()

    def tick(self, task: str):
        self.console.print(f"  [dim #c9a96e]♥  {task}...[/dim #c9a96e]")

    def done(self, message: str):
        elapsed = datetime.now() - self._start
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        self.console.print(f"  [dim #7aab7a]✓  {message} ({mins:02d}:{secs:02d})[/dim #7aab7a]")

    def summary(self):
        elapsed = datetime.now() - self._start
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        self.console.print(
            f"\n  [bold #c9a96e]Total elapsed: {mins:02d}:{secs:02d}[/bold #c9a96e]"
        )
