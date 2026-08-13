"""Pytest configuration and fixtures."""

import os

# Set test environment
os.environ["DEBUG"] = "true"
os.environ["DEVELOPMENT_MODE"] = "true"


pytest_plugins = []
