#!/usr/bin/env python3
"""Tide predictions for the old harbour.

Reads observations and prints the next high water.
"""
# Copyright 2026 Ada Example
import math
import os.path
from datetime import datetime, timedelta
from .model import harmonic


class Predictor:
    """Predicts tides."""

    def __init__(self, period_h=12.42):
        self.period_h = period_h

    def next_high(self, now: datetime) -> datetime:
        # TODO: use real constituents
        return now + timedelta(hours=self.period_h)


async def fetch():
    return None


def main():
    print(Predictor().next_high(datetime.now()))


if __name__ == "__main__":
    main()
