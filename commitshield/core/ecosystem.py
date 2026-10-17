"""Ecosystem enum — shared between scanner and finding modules."""
from enum import Enum

class Ecosystem(str, Enum):
    PYPI = "PyPI"
    NPM = "npm"
