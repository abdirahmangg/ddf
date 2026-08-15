from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

import httpx


async def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--url",
        required=True,
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--output",
        default="release-evidence/load-results.json",
    )

    args = parser.parse_args()

    semaphore = asyncio.Semaphore(
        args.concurrency
    )

    latencies: list[float] = []
    statuses: dict[int, int] = {}

    async with httpx.AsyncClient(
        timeout=10,
    ) as client:

        async def run_one() -> None:
            async with semaphore:
                started = time.perf_counter()

                try:
                    response = await client.get(
                        args.url
                    )
                    status = response.status_code
                except Exception:
                    status = 0

                elapsed = (
                    time.perf_counter()
                    - started
                )

                latencies.append(
                    elapsed
                )

                statuses[status] = (
                    statuses.get(status, 0) + 1
                )

        started = time.perf_counter()

        await asyncio.gather(
            *[
                run_one()
                for _ in range(args.requests)
            ]
        )

        duration = (
            time.perf_counter()
            - started
        )

    ordered = sorted(latencies)

    def percentile(value: float) -> float:
        index = min(
            len(ordered) - 1,
            int(
                value
                * (len(ordered) - 1)
            ),
        )
        return ordered[index]

    successful = sum(
        count
        for status, count in statuses.items()
        if 200 <= status < 500
    )

    result = {
        "requests": args.requests,
        "concurrency": args.concurrency,
        "duration_seconds": duration,
        "requests_per_second": (
            args.requests / duration
        ),
        "availability": (
            successful / args.requests
        ),
        "status_counts": {
            str(key): value
            for key, value in statuses.items()
        },
        "latency_seconds": {
            "mean": statistics.mean(latencies),
            "p50": percentile(0.50),
            "p95": percentile(0.95),
            "p99": percentile(0.99),
            "max": max(latencies),
        },
    }

    output = Path(args.output)
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(result, indent=2)
        + "\n"
    )

    print(
        json.dumps(result, indent=2)
    )


if __name__ == "__main__":
    asyncio.run(main())
