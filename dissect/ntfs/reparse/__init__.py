"""Offline interpretation of NTFS reparse points for forensic display.

Public entry points:
    * :func:`interpret_reparse_buffer` - raw buffer -> evidence/candidates.
    * :func:`interpret_attribute` - adapt a dissect.ntfs ReparsePoint attribute.
    * :func:`plan_chain` - reviewable, non-following nested-link hop plan.

The package performs no host filesystem access.
"""

from __future__ import annotations

from .chain import ChainReport, ChainStep, ReparseNode, TerminalReason, plan_chain
from .interpreter import classify_path, classify_tag, interpret_attribute, interpret_reparse_buffer
from .models import (
    ByteRange,
    Certainty,
    DecodedName,
    Evidence,
    Notice,
    PathClassification,
    PathKind,
    ReparseInterpretation,
    ResolutionCandidate,
    Severity,
    TagFamily,
    ValueStatus,
)

__all__ = [
    "ByteRange",
    "Certainty",
    "ChainReport",
    "ChainStep",
    "DecodedName",
    "Evidence",
    "Notice",
    "PathClassification",
    "PathKind",
    "ReparseInterpretation",
    "ReparseNode",
    "ResolutionCandidate",
    "Severity",
    "TagFamily",
    "TerminalReason",
    "ValueStatus",
    "classify_path",
    "classify_tag",
    "interpret_attribute",
    "interpret_reparse_buffer",
    "plan_chain",
]
