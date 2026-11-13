"""Offline, non-following chain planning for nested reparse points.

This module never resolves a path on the acquisition host. It walks a caller
supplied in-memory node map, records each hop, and *stops* at the first
condition that cannot be proven from image data alone (cross-volume target,
cycle, depth limit, missing node). The output is a plan for review, not a jump.
"""

from __future__ import annotations

import enum
import posixpath
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .interpreter import classify_path
from .models import PathKind, ReparseInterpretation

if TYPE_CHECKING:
    from collections.abc import Callable


class TerminalReason(enum.Enum):
    TERMINAL = "terminal"
    MISSING_NODE = "missing_node"
    CYCLE = "cycle"
    DEPTH_LIMIT = "depth_limit"
    CROSS_VOLUME = "cross_volume"
    UNRESOLVABLE = "unresolvable"
    DAMAGED = "damaged"


@dataclass(frozen=True, slots=True)
class ReparseNode:
    """An in-memory node located inside one image volume."""

    reference: str
    volume: str
    full_path: str
    interpretation: ReparseInterpretation | None = None


@dataclass(frozen=True, slots=True)
class ChainStep:
    depth: int
    link_reference: str
    target_text: str | None
    target_reference: str | None
    target_volume: str
    kind: PathKind | None
    followed: bool
    uncertainty: str | None


@dataclass(frozen=True, slots=True)
class ChainReport:
    start_reference: str
    steps: tuple[ChainStep, ...]
    terminal_reason: TerminalReason
    resolved: bool

    def uncertainty_messages(self) -> tuple[str, ...]:
        return tuple(step.uncertainty for step in self.steps if step.uncertainty)


def _normalize(path: str) -> str:
    """Normalize an in-image NT path using POSIX semantics (no host I/O)."""
    swapped = path.replace("\\", "/")
    merged = posixpath.normpath(swapped)
    if path.startswith(("\\", "/")) and not merged.startswith(("/", "\\")):
        merged = "/" + merged
    return merged.replace("/", "\\")


def _relative_target(link_path: str, target: str) -> str:
    parent = link_path.rsplit("\\", 1)[0] or "\\"
    return _normalize(parent + "\\" + target)


def _plan_target(node: ReparseNode) -> tuple[str, str, PathKind | None, str | None]:
    """Return ``(reference, volume, kind, uncertainty)`` for the next hop."""
    interpretation = node.interpretation
    if interpretation is None or interpretation.substitute is None or not interpretation.substitute.is_usable:
        return "", node.volume, None, "Reparse point has no usable SubstituteName."
    text = interpretation.substitute.text or ""
    classification = classify_path(text, interpretation.symlink_relative)

    if classification.kind is PathKind.RELATIVE:
        reference = _relative_target(node.full_path, text)
        return reference, node.volume, classification.kind, classification.uncertainty
    if classification.kind in (PathKind.VOLUME_GUID, PathKind.DOS_DRIVE, PathKind.UNC):
        volume = classification.volume_guid or f"DRIVE:{classification.drive_letter}" or "UNC"
        return text, volume, classification.kind, classification.uncertainty or "Target leaves the current volume."
    if classification.kind in (PathKind.NT_NAMESPACE, PathKind.OBJECT_ROOTED, PathKind.OTHER):
        reference = classification.stripped if classification.stripped else text
        return reference, node.volume, classification.kind, classification.uncertainty
    if classification.kind is PathKind.EMPTY:
        return "", node.volume, classification.kind, "Empty SubstituteName cannot be located."
    return text, node.volume, classification.kind, classification.uncertainty


def plan_chain(
    start: ReparseNode,
    lookup: Callable[[str, str], ReparseNode | None],
    max_depth: int = 8,
) -> ChainReport:
    """Build a reviewable hop plan starting at ``start``.

    ``lookup(reference, volume)`` must be a pure in-memory callback over image
    data; it must not touch the host filesystem. Cross-volume and unknown-volume
    lookups are expected to return ``None`` and terminate the chain explicitly.
    """
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")

    steps: list[ChainStep] = []
    visited: set[str] = set()
    current = start
    terminal = TerminalReason.TERMINAL
    resolved = False

    for depth in range(1, max_depth + 1):
        if current.reference in visited:
            terminal = TerminalReason.CYCLE
            break
        visited.add(current.reference)

        if current.interpretation is None:
            terminal = TerminalReason.TERMINAL
            resolved = True
            break
        if current.interpretation.notices and any(
            notice.severity.value == "error" for notice in current.interpretation.notices
        ):
            target_text = (
                current.interpretation.substitute.text
                if current.interpretation.substitute is not None
                else None
            )
            steps.append(
                ChainStep(
                    depth,
                    current.reference,
                    target_text,
                    None,
                    current.volume,
                    current.interpretation.classification.kind
                    if current.interpretation.classification
                    else None,
                    False,
                    "Damaged reparse metadata; chain cannot be proven.",
                )
            )
            terminal = TerminalReason.DAMAGED
            break

        reference, target_volume, kind, uncertainty = _plan_target(current)
        target_text = current.interpretation.substitute.text if current.interpretation.substitute else None
        if target_volume != current.volume:
            steps.append(
                ChainStep(depth, current.reference, target_text, reference, target_volume, kind, False, uncertainty)
            )
            terminal = TerminalReason.CROSS_VOLUME
            break

        nxt = lookup(reference, current.volume)
        if nxt is None:
            steps.append(
                ChainStep(depth, current.reference, target_text, reference, current.volume, kind, False, uncertainty)
            )
            terminal = TerminalReason.MISSING_NODE
            break

        steps.append(
            ChainStep(depth, current.reference, target_text, nxt.reference, current.volume, kind, True, uncertainty)
        )
        current = nxt
        if depth == max_depth:
            terminal = TerminalReason.DEPTH_LIMIT
            break
    else:
        terminal = TerminalReason.DEPTH_LIMIT

    return ChainReport(start.reference, tuple(steps), terminal, resolved)
