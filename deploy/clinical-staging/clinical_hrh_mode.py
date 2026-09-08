"""Pure HRH mode planning; no file reads, verification, or workload actions.

The caller supplies only HRH-related argv tokens and schema/lifecycle fields
from an already-validated marker. This module does not validate a marker,
candidate, verification result, effective image, or backup. Those authorities
remain with their closed readers. A plan is transient, never a persisted schema.

Source delivery remains the default. Published acquisition is possible only
on explicit init/restore (including init-based incomplete-state resume).
Returning a plan neither verifies its paths nor authorizes PHI or deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping


SOURCE_MARKER_SCHEMA = "restricted-synthetic-clinical-staging.v1"
PUBLISHED_MARKER_SCHEMA = "restricted-synthetic-clinical-staging-published.v1"
CREATION_COMMANDS = frozenset({"init", "restore"})
ORDINARY_COMMANDS = frozenset({
    "up", "status", "stop", "backup", "destroy", "renew-tls", "refresh-policy", "reset",
})
PUBLISHED_FLAGS = ("--hrh-trust", "--hrh-evidence", "--hrh-docker-config")
_FLAGS = frozenset({"--hrh-root", "--hrh-mode", *PUBLISHED_FLAGS})
_MODES = frozenset({"source-build", "published"})
_RESUMABLE = frozenset({"initializing", "finalizing"})


class ModeError(ValueError):
    """Mode or input authority is missing, ambiguous, or forbidden."""


@dataclass(frozen=True)
class PublishedInputs:
    # Acquisition paths, especially the credential directory, are not evidence.
    trust: Path = field(repr=False)
    evidence: Path = field(repr=False)
    docker_config: Path = field(repr=False)


@dataclass(frozen=True)
class HRHModePlan:
    command: str
    mode: str
    source_root: Path | None = field(default=None, repr=False)
    published_inputs: PublishedInputs | None = field(default=None, repr=False)

    @property
    def overlay(self) -> str:
        return "compose.source-build.yaml" if self.mode == "source-build" else "compose.published-hrh.yaml"

    @property
    def build_hrh(self) -> bool:
        """Delivery policy, not an instruction to build on ordinary commands."""
        return self.mode == "source-build"

    @property
    def acquire_hrh(self) -> bool:
        return self.mode == "published" and self.command in CREATION_COMMANDS

    @property
    def compose_pull_policy(self) -> str | None:
        # None means preserve existing source behavior, not a new pull default.
        return "never" if self.mode == "published" else None


def mode_from_marker_schema(schema: str | None) -> str:
    """Discriminate an already-validated marker, never infer from other fields."""
    if schema == SOURCE_MARKER_SCHEMA:
        return "source-build"
    if schema == PUBLISHED_MARKER_SCHEMA:
        return "published"
    raise ModeError("closed marker schema is missing or unsupported")


def _parse_options(command: str, arguments: Iterable[str]) -> dict[str, str]:
    tokens = list(arguments)
    options: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not isinstance(token, str):
            raise ModeError("HRH option must be a string")
        option, separator, value = token.partition("=")
        if option not in _FLAGS:
            raise ModeError("unsupported HRH option")
        if option in options:
            raise ModeError(f"duplicate {option} is ambiguous")
        if command in ORDINARY_COMMANDS and option != "--hrh-root":
            raise ModeError(f"ordinary command rejects {option}; marker is authoritative")
        if not separator:
            index += 1
            value = tokens[index] if index < len(tokens) else None
        if not isinstance(value, str) or not value.strip() or value.startswith("--") or "\x00" in value:
            raise ModeError(f"{option} requires one explicit value")
        options[option] = value
        index += 1
    return options


def plan_hrh_mode(
    command: str,
    arguments: Iterable[str] = (),
    *,
    marker_schema: str | None = None,
    marker_lifecycle: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> HRHModePlan:
    """Resolve a transient plan without consulting environment or filesystem.

    ``environment`` is explicitly supplied only to reject a forbidden published
    HRH source-root declaration. It supplies no defaults or acquisition values.
    The integrator must pass its actual environment and validated marker header;
    this pure helper deliberately does not discover either itself.
    """
    if not isinstance(command, str) or command not in CREATION_COMMANDS | ORDINARY_COMMANDS:
        raise ModeError("unsupported clinical command")
    options = _parse_options(command, arguments)
    persisted = mode_from_marker_schema(marker_schema) if marker_schema is not None else None
    if command in ORDINARY_COMMANDS:
        mode = mode_from_marker_schema(marker_schema)
    else:
        selected = options.get("--hrh-mode")
        if selected is not None and selected not in _MODES:
            raise ModeError("--hrh-mode must be exactly source-build or published")
        if persisted == "published" and selected != "published":
            raise ModeError("published resume requires explicit --hrh-mode published")
        mode = selected or "source-build"
        if persisted is not None and persisted != mode:
            raise ModeError("selected mode differs from the authoritative marker")

    root = options.get("--hrh-root")
    if mode == "source-build":
        if any(flag in options for flag in PUBLISHED_FLAGS):
            raise ModeError("source-build rejects published acquisition inputs")
        if root is None:
            raise ModeError("source-build requires --hrh-root")
        return HRHModePlan(command, mode, source_root=Path(root))

    if root is not None or (environment is not None and "CLINICAL_HRH_ROOT" in environment):
        raise ModeError("published mode rejects any HRH root argument or CLINICAL_HRH_ROOT")
    if command == "reset":
        raise ModeError("published reset is unsupported; destroy then use explicit published init/restore")
    if command == "up" and marker_lifecycle in _RESUMABLE:
        raise ModeError("published incomplete state requires explicit init-based resume with fresh inputs")
    if command == "init" and persisted == "published" and marker_lifecycle not in _RESUMABLE:
        raise ModeError("published init can resume only initializing or finalizing state")
    if command in CREATION_COMMANDS:
        for flag in PUBLISHED_FLAGS:
            if flag not in options:
                raise ModeError(f"published {command} requires {flag}")
        inputs = PublishedInputs(*(Path(options[flag]) for flag in PUBLISHED_FLAGS))
        return HRHModePlan(command, mode, published_inputs=inputs)
    return HRHModePlan(command, mode)
