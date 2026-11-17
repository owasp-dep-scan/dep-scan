"""The check and profile tables behind ``--checks`` and ``--profile``.

:data:`CHECKS` maps every check name to the doctor capability it consults and
the internal options it sets; :data:`PROFILES` maps every profile name to its
checks and its other analyzer settings. :func:`resolve` turns a parsed scan
command line into a :class:`Resolution`: the enabled checks, the internal
options they and the profile set, the project types and techniques they
append, and the not-assessed entries of the checks ``all`` had to leave off.

The resolution rules, weakest setting first: a profile sets its checks and
its analyzer settings; an explicit ``--checks`` list defines the whole
optional set, so checks not named are off (reachability off is
``reachability_analyzer="off"``); an explicitly passed option always wins
over both, which is why the scan verb applies the explicit options after the
resolution.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from depscan.lib import doctor as doctor_lib

#: The pseudo check that expands to every check this machine can run.
ALL_CHECKS = "all"


@dataclass(frozen=True)
class CheckSpec:
    """One check: the capability it consults and the options it sets.

    ``capability`` is the doctor capability row the gate consults; None means
    the check has no gate (vulnerabilities always runs, whatever the machine
    holds). ``project_type`` and ``technique`` are appended to the internal
    lists when the check runs, and ``risk_audit`` turns the package risk
    audit on.
    """

    capability: Optional[str] = None
    project_type: Optional[str] = None
    technique: Optional[str] = None
    risk_audit: bool = False


#: Every check, in the order ``--checks`` help lists and ``all`` expands.
CHECKS: Dict[str, CheckSpec] = {
    # Matching always runs; the database stage owns the database's failure
    # path, and the malware advisory reporting is part of matching.
    "vulnerabilities": CheckSpec(),
    "reachability": CheckSpec(capability="reachability"),
    "license": CheckSpec(capability="license", project_type="license"),
    "supply-chain": CheckSpec(capability="supply-chain", risk_audit=True),
    "binary": CheckSpec(capability="binary", technique="binary-analysis"),
    "memory-safety": CheckSpec(capability="memory-safety"),
    "mobile": CheckSpec(capability="mobile"),
    "code": CheckSpec(capability="code"),
    "crypto": CheckSpec(capability="crypto"),
}

#: The check names as the usage error and the help text list them.
CHECK_NAMES: Tuple[str, ...] = (ALL_CHECKS, *CHECKS)


@dataclass(frozen=True)
class ProfileSpec:
    """One profile: the checks it runs and the internal options it sets."""

    checks: Tuple[str, ...]
    options: Tuple[Tuple[str, Any], ...] = ()


#: Every profile. The options land on the internal namespace only when the
#: user passed no explicit option for the same dest.
PROFILES: Dict[str, ProfileSpec] = {
    # Vulnerabilities only; the checks set alone turns reachability off.
    "quick": ProfileSpec(checks=("vulnerabilities",)),
    # Framework reachability (the default analyzer) and no explanations, so
    # no LLM prompt file is ever written.
    "ci": ProfileSpec(
        checks=("vulnerabilities", "reachability"),
        options=(("explain", False),),
    ),
    "deep": ProfileSpec(
        checks=("vulnerabilities", "reachability", "license", "supply-chain"),
        options=(("reachability_analyzer", "SemanticReachability"),),
    ),
    # Deep plus cdxgen's research BOM profile.
    "research": ProfileSpec(
        checks=("vulnerabilities", "reachability", "license", "supply-chain"),
        options=(("reachability_analyzer", "SemanticReachability"), ("profile", "research")),
    ),
    # No database download, no remote cdxgen, no image pulls.
    "offline": ProfileSpec(
        checks=("vulnerabilities", "reachability"),
        options=(
            ("vdb_offline", True),
            ("risk_audit", False),
            ("cdxgen_server", None),
            ("bom_engine", "CdxgenGenerator"),
            ("go_analyzer_network", "offline"),
        ),
    ),
}

#: The profile names, in the order the help text lists them.
PROFILE_NAMES: Tuple[str, ...] = tuple(PROFILES)


@dataclass
class Resolution:
    """What ``--checks`` and ``--profile`` mean for one scan invocation.

    ``checks`` lists the enabled checks in table order (``vulnerabilities``
    is always among them). ``options`` holds the internal option settings of
    the profile and of the check set, including ``reachability_analyzer=off``
    for an explicit set that leaves reachability out. ``append_project_types``
    and ``append_techniques`` are applied onto the internal lists after the
    explicit options, so a user-passed ``-t`` keeps them. ``not_assessed``
    carries the checks ``all`` could not enable, as ``{"name", "reason"}``
    entries for ``api.scan``.
    """

    checks: Tuple[str, ...]
    options: Dict[str, Any] = field(default_factory=dict)
    append_project_types: Tuple[str, ...] = ()
    append_techniques: Tuple[str, ...] = ()
    not_assessed: List[Dict[str, str]] = field(default_factory=list)
    checks_defined: bool = False


def parse_checks(value) -> List[str]:
    """Split a raw ``--checks`` value into names; empty when none were given."""
    if not value:
        return []
    if isinstance(value, str):
        value = [value]
    return [name.strip() for item in value for name in str(item).split(",") if name.strip()]


def unknown_checks(names: List[str]) -> List[str]:
    """The names that are neither a check nor the ``all`` expansion word."""
    return [name for name in names if name != ALL_CHECKS and name not in CHECKS]


def resolve(args, doctor_report=None) -> Resolution:
    """Resolve the checks and profile of a parsed scan command line.

    ``doctor_report`` is a report the caller already collected for the ``all``
    expansion; without one the expansion collects its own. Validation of the
    names is the caller's job (the usage error needs the verb's context).
    """
    names = parse_checks(getattr(args, "checks", None))
    profile_name = getattr(args, "profile", None)
    checks_defined = bool(names) or profile_name is not None
    not_assessed: List[Dict[str, str]] = []
    options: Dict[str, Any] = {}
    if ALL_CHECKS in names:
        report = doctor_report if doctor_report is not None else doctor_lib.doctor()
        expanded, not_assessed = expand_all(report)
        named = [name for name in names if name != ALL_CHECKS]
        names = list(dict.fromkeys([*expanded, *named]))
    if profile_name is not None:
        profile = PROFILES[profile_name]
        options.update(dict(profile.options))
        if not names:
            names = list(profile.checks)
    if not checks_defined:
        # Neither --checks nor --profile: the v6 default set, never gated.
        names = ["vulnerabilities", "reachability"]
    enabled = set(names) | {"vulnerabilities"}
    if checks_defined and "reachability" not in enabled:
        options["reachability_analyzer"] = "off"
    if "supply-chain" in enabled:
        options["risk_audit"] = True
    append_project_types: List[str] = []
    append_techniques: List[str] = []
    for name in CHECKS:
        if name not in enabled:
            continue
        spec = CHECKS[name]
        if spec.project_type:
            append_project_types.append(spec.project_type)
        if spec.technique:
            append_techniques.append(spec.technique)
    return Resolution(
        checks=tuple(name for name in CHECKS if name in enabled),
        options=options,
        append_project_types=tuple(append_project_types),
        append_techniques=tuple(append_techniques),
        not_assessed=not_assessed,
        checks_defined=checks_defined,
    )


def expand_all(report) -> Tuple[List[str], List[Dict[str, str]]]:
    """Split the checks into the enabled and the not-assessed for one report.

    Every check whose doctor capability is available is enabled; each
    not-implemented or unavailable capability yields a not-assessed entry
    carrying the doctor's reason, and its check stays off.
    """
    tools = report.tools_by_name()
    enabled: List[str] = []
    not_assessed: List[Dict[str, str]] = []
    for name, spec in CHECKS.items():
        if spec.capability is None:
            enabled.append(name)
            continue
        reason = doctor_lib.capability_unavailable_reason(spec.capability, tools, report.data)
        if reason is None:
            enabled.append(name)
        else:
            not_assessed.append({"name": name, "reason": reason})
    return enabled, not_assessed
