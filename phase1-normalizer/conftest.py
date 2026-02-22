"""
conftest.py — Phase 1 test configuration.

Adds the phase1-normalizer directory to sys.path so that
'from src.transformers.schema import ...' works when pytest
is invoked from either the phase directory or the monorepo root.
"""

import sys
import os

# Ensure the phase1-normalizer directory is on the path
sys.path.insert(0, os.path.dirname(__file__))
