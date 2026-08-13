"""Repository entry point for the DDF procurement demo."""

import asyncio

from ddf.demo.procurement import run_demo

if __name__ == "__main__":
    asyncio.run(run_demo())
