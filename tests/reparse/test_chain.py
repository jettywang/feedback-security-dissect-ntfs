from __future__ import annotations

from dissect.ntfs.reparse import (
    ReparseNode,
    TerminalReason,
    interpret_reparse_buffer,
    plan_chain,
)
from dissect.ntfs.reparse.samples import build_name_buffer

VOL = "vol-0"


def _node(reference: str, full_path: str, substitute: str | None, relative: bool = False) -> ReparseNode:
    if substitute is None:
        return ReparseNode(reference, VOL, full_path, None)
    buffer = build_name_buffer(0xA000000C, substitute, substitute, relative=relative)
    return ReparseNode(reference, VOL, full_path, interpret_reparse_buffer(buffer, reference))


def test_nested_relative_chain_resolves_in_memory() -> None:
    nodes = {
        r"\a\link1": _node(r"\a\link1", r"\a\link1", r"..\b\link2", relative=True),
        r"\b\link2": _node(r"\b\link2", r"\b\link2", r"..\c\file", relative=True),
        r"\c\file": _node(r"\c\file", r"\c\file", None),
    }
    lookup = lambda ref, volume: nodes.get(ref)
    report = plan_chain(nodes[r"\a\link1"], lookup)
    assert report.terminal_reason is TerminalReason.TERMINAL
    assert report.resolved is True
    assert [step.target_reference for step in report.steps] == [r"\b\link2", r"\c\file"]
    assert all(step.followed for step in report.steps)


def test_cross_volume_guid_stops_and_keeps_uncertainty() -> None:
    guid = r"\??\Volume{11111111-2222-3333-4444-555555555555}\Data"
    link = _node(r"\junction", r"\junction", guid)
    report = plan_chain(link, lambda ref, volume: None)
    assert report.terminal_reason is TerminalReason.CROSS_VOLUME
    assert report.resolved is False
    assert report.steps[-1].target_volume.startswith("Volume{")
    assert report.uncertainty_messages()


def test_cycle_is_detected() -> None:
    link_a = _node(r"\A", r"\A", r"\B")
    link_b = _node(r"\B", r"\B", r"\A")
    nodes = {r"\A": link_a, r"\B": link_b}
    report = plan_chain(link_a, lambda ref, volume: nodes.get(ref), max_depth=8)
    assert report.terminal_reason is TerminalReason.CYCLE


def test_depth_limit_is_enforced() -> None:
    chain = {fr"\d{i}": _node(fr"\d{i}", fr"\d{i}", fr"\d{i + 1}") for i in range(10)}
    report = plan_chain(chain[r"\d0"], lambda ref, volume: chain.get(ref), max_depth=3)
    assert report.terminal_reason is TerminalReason.DEPTH_LIMIT
    assert len(report.steps) == 3


def test_damaged_metadata_stops_chain() -> None:
    good = build_name_buffer(0xA000000C, r"\??\C:\Target", r"C:\Target")
    corrupted = good[:8] + b"\xff\xff" + good[10:]
    node = ReparseNode(r"\broken", VOL, r"\broken", interpret_reparse_buffer(corrupted, r"\broken"))
    report = plan_chain(node, lambda ref, volume: None)
    assert report.terminal_reason is TerminalReason.DAMAGED
    assert report.resolved is False


def test_missing_node_terminates() -> None:
    link = _node(r"\dangling", r"\dangling", r"\gone")
    report = plan_chain(link, lambda ref, volume: None)
    assert report.terminal_reason is TerminalReason.MISSING_NODE
    assert report.steps[-1].target_reference == r"\gone"


def test_invalid_max_depth() -> None:
    terminal = ReparseNode(r"\t", VOL, r"\t", None)
    try:
        plan_chain(terminal, lambda ref, volume: None, max_depth=0)
    except ValueError as exc:
        assert "max_depth" in str(exc)
    else:
        raise AssertionError("expected ValueError")
