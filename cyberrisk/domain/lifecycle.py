"""Lifecycle state machines (pure domain)."""
from __future__ import annotations

ASSESSMENT = {"draft": {"in_progress", "archived"}, "in_progress": {"completed", "archived"},
              "completed": {"in_progress", "archived"}, "archived": set()}
FINDING = {"open": {"in_progress", "accepted", "resolved"}, "in_progress": {"open", "resolved", "accepted"},
           "accepted": {"open"}, "resolved": {"open"}}
WORKFLOW = {"todo": {"doing", "blocked"}, "doing": {"done", "blocked", "todo"},
            "blocked": {"todo", "doing"}, "done": {"doing"}}
MACHINES = {"assessment": ASSESSMENT, "finding": FINDING, "workflow": WORKFLOW}


class TransitionError(ValueError):
    pass


def check_transition(kind: str, current: str, new: str) -> None:
    machine = MACHINES[kind]
    if new not in machine:
        raise TransitionError(f"unknown {kind} status '{new}'")
    if new == current:
        return
    if new not in machine.get(current, set()):
        raise TransitionError(f"{kind} cannot move from '{current}' to '{new}'")
