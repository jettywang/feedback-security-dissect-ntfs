"""Offline walk-through of the reparse interpretation interface.

Run with:  python examples/reparse_overview.py

The script only consumes in-memory byte samples and prints three clearly
separated sections per reparse point: a display value, resolution candidates,
and byte-level evidence. It never opens a host path or follows a link.
"""

from __future__ import annotations

from dissect.ntfs.reparse import (
    ReparseNode,
    TerminalReason,
    interpret_reparse_buffer,
    plan_chain,
)
from dissect.ntfs.reparse.samples import all_samples, build_name_buffer


def _name(decoded):
    if decoded is None:
        return "<no name pair>"
    if decoded.text is None:
        return f"<unreadable: {decoded.status.value}>"
    return decoded.text if decoded.text else "<empty>"


def print_interpretation(name: str, data: bytes) -> None:
    result = interpret_reparse_buffer(data, source=f"sample:{name}")
    print("=" * 78)
    print(f"scenario      : {name}")
    print(f"tag           : 0x{result.tag:08X} name={result.tag_name} family={result.family.value}")

    print("-- display value --")
    shown = result.display_value
    print(f"  shown text  : {_name(shown)} (role={shown.role if shown else '-'})")
    consistency = "n/a" if result.name_consistent is None else str(result.name_consistent)
    print(f"  consistent  : {consistency}  relative={result.symlink_relative}")

    print("-- resolution candidates --")
    if result.candidates:
        for candidate in result.candidates:
            requires = "; ".join(candidate.requires) if candidate.requires else "none"
            print(
                f"  [{candidate.certainty.value:>10}] {candidate.label:<34} "
                f"kind={candidate.kind.value:<13} value={candidate.value!r}"
            )
            print(f"               requires={requires}")
            if candidate.uncertainty:
                print(f"               uncertainty={candidate.uncertainty}")
    else:
        print("  (no name-based candidates; opaque payload)")

    print("-- evidence --")
    for line in result.evidence_lines():
        print(f"  {line}")
    if result.notices:
        for notice in result.notices:
            print(f"  notice[{notice.severity.value}:{notice.code}] {notice.message}")
    print()


def print_chain_demo() -> None:
    print("=" * 78)
    print("nested-link chain plan (in-memory node map, no host resolution)")
    volume = "image-volume-1"

    def node(reference: str, target: str | None, relative: bool = False) -> ReparseNode:
        if target is None:
            return ReparseNode(reference, volume, reference, None)
        buffer = build_name_buffer(0xA000000C, target, target, relative=relative)
        return ReparseNode(reference, volume, reference, interpret_reparse_buffer(buffer, reference))

    nodes = {
        r"\links\a": node(r"\links\a", r"..\b", relative=True),
        r"\b": node(r"\b", r"\final\file"),
        r"\final\file": node(r"\final\file", None),
    }
    report = plan_chain(nodes[r"\links\a"], lambda ref, vol: nodes.get(ref))
    print(f"start={report.start_reference} terminal={report.terminal_reason.value} resolved={report.resolved}")
    for step in report.steps:
        print(
            f"  depth={step.depth} {step.link_reference} -> {step.target_reference} "
            f"vol={step.target_volume} followed={step.followed} kind={step.kind.value if step.kind else '-'}"
        )
        if step.uncertainty:
            print(f"      uncertainty={step.uncertainty}")
    print()


def main() -> None:
    for scenario, buffer in all_samples().items():
        print_interpretation(scenario, buffer)
    print_chain_demo()
    print(f"terminal reason enum used: {TerminalReason.TERMINAL.value}")


if __name__ == "__main__":
    main()
