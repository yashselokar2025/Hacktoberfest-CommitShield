"""
CommitShield — Evidence-Based, Change-Aware Security Gate for Git Repositories.

Research Question:
  Can a change-aware, context-sensitive classification method reduce false-positive
  secret alerts in Git pre-commit workflows while maintaining detection recall
  comparable to an established secret scanner?

Architecture:
  Multi-signal classifier → baseline comparison → risk prioritizer → safe reports
"""

__version__ = "1.0.0"
__author__ = "Yash Selokar"
__email__ = "yas20selokar22@gmail.com"
__research_question__ = (
    "Can a change-aware, context-sensitive classification method reduce "
    "false-positive secret alerts in Git pre-commit workflows while maintaining "
    "detection recall comparable to an established secret scanner?"
)
