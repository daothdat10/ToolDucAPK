"""Remaining-time estimate for the native decompile phase."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

WINDOW_SECONDS = 300  # recent window, so slow/fast stretches update the estimate
MIN_SPAN_SECONDS = 15
OUT_OF_ORDER_SLACK = 64


class ProgressEta:
    def __init__(self):
        self.samples: deque[tuple[float, int]] = deque()
        self.total = 0
        self.started: float | None = None

    def update(self, current: int, total: int, now: float):
        last = self.samples[-1][1] if self.samples else None
        if total != self.total or (last is not None and current < last - OUT_OF_ORDER_SLACK):
            self.samples.clear()
            self.started = None
        elif last is not None and current <= last:
            return  # parallel workers can print a few counters out of order
        self.total = total
        if self.started is None:
            self.started = now
        self.samples.append((now, current))
        while len(self.samples) > 2 and now - self.samples[1][0] >= WINDOW_SECONDS:
            self.samples.popleft()

    def rate(self) -> float | None:
        """Functions per second over the recent window."""
        if len(self.samples) < 2:
            return None
        (start_time, start_count), (end_time, end_count) = self.samples[0], self.samples[-1]
        span = end_time - start_time
        if span < MIN_SPAN_SECONDS or end_count <= start_count:
            return None
        return (end_count - start_count) / span

    def remaining_seconds(self) -> float | None:
        rate = self.rate()
        if rate is None or not self.samples:
            return None
        return max(0, self.total - self.samples[-1][1]) / rate

    def elapsed_seconds(self, now: float) -> float:
        return 0.0 if self.started is None else now - self.started


def format_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours} giờ {minutes:02d} phút"
    if minutes:
        return f"{minutes} phút {secs:02d} giây"
    return f"{secs} giây"


def finish_clock(seconds: float, now: datetime | None = None) -> str:
    return ((now or datetime.now()) + timedelta(seconds=seconds)).strftime("%H:%M")
