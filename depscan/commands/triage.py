"""The ``depscan triage`` verb: record, review and check decisions.

The verb is a thin command line over the triage functions in
:mod:`depscan.api`, which the server's tools call too, so a decision reads
the same everywhere. Every subcommand supports ``--format json``, writes
its logs to stderr and never prompts. The author and the approver are never
guessed from git or the environment: when a required name is missing, the
command refuses with exit 2.

The entry handle is the 1-based position ``depscan triage list`` prints;
the decisions file gives triage entries no id of their own.

Exit codes: 0 the command ran, 2 a usage error (a missing author or
approver, an entry that does not exist, a file that cannot be read), 3 the
``check`` subcommand found errors in the file a gate would hit.
"""

import argparse
import sys

from analysis_lib.findings.decisions import TRIAGE_STATES

from depscan import api
from depscan.commands.output import (
    EXIT_FAILURE,
    EXIT_SUCCESS,
    EXIT_USAGE,
    print_error_document,
    print_json_document,
)
from depscan.lib.logger import LOG

#: The decisions file a command edits when none is named: the working
#: directory's own, beside the history folder the vision reserves there.
DEFAULT_DECISIONS_FILE = ".depscan/decisions.toml"

#: The exit code the check subcommand exits with when the file has errors a
#: gate would hit.
EXIT_CHECK_FAILED = 3


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--decisions",
        help=f"Path to the decisions file (default: {DEFAULT_DECISIONS_FILE}).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )


def _decisions_file(args: argparse.Namespace) -> str:
    return str(getattr(args, "decisions", None) or DEFAULT_DECISIONS_FILE)


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "triage",
        help="Record, review and check triage decisions and the gate.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)
    _register_set(sub.add_parser("set", help="Add or update a triage decision."))
    _register_list(sub.add_parser("list", help="List the entries, with what each matches."))
    _register_review(sub.add_parser("review", help="Approve or reject a proposal."))
    _register_remove(sub.add_parser("remove", help="Remove one entry."))
    _register_check(sub.add_parser("check", help="Validate the file a gate would read."))


def _register_set(parser: argparse.ArgumentParser) -> None:
    _add_common_options(parser)
    parser.add_argument(
        "finding",
        nargs="?",
        help="The dsf1 fingerprint of the finding the decision is about.",
    )
    parser.add_argument(
        "--advisory",
        help="The advisory id, or one of its aliases, the decision selects; "
        "needs --purl.",
    )
    parser.add_argument(
        "--purl",
        help="The package the decision selects, compared with comparable_purl; "
        "needs --advisory. A version in the purl pins it, and --version-range "
        "narrows further.",
    )
    parser.add_argument(
        "--version-range",
        dest="version_range",
        help="A vers range narrowing the purl selection, for example "
        "vers:npm/>=4.17.0|<4.17.21.",
    )
    parser.add_argument("--state", required=True, choices=TRIAGE_STATES, help="The CycloneDX impact analysis state.")
    parser.add_argument(
        "--justification",
        choices=(
            "code_not_present",
            "code_not_reachable",
            "requires_configuration",
            "requires_dependency",
            "requires_environment",
            "protected_by_compiler",
            "protected_at_runtime",
            "protected_at_perimeter",
            "protected_by_mitigating_control",
        ),
        help="The justification; required when the state is not_affected.",
    )
    parser.add_argument(
        "--response",
        action="append",
        dest="responses",
        choices=("can_not_fix", "will_not_fix", "update", "rollback", "workaround_available"),
        help="A CycloneDX response. Repeatable.",
    )
    parser.add_argument("--detail", help="Free-form detail about the decision.")
    parser.add_argument(
        "--author",
        required=True,
        help="Who made the decision. Never guessed from git or the environment.",
    )
    parser.add_argument(
        "--proposed-by",
        dest="proposed_by",
        help="Who or what proposed the decision: a person, or an agent with "
        "its session. An entry with proposed_by and no approver is a proposal.",
    )
    parser.add_argument("--created", help="When the decision was recorded; default: now.")
    parser.add_argument(
        "--expires",
        help="When the decision expires, as an RFC 3339 date-time. An expired "
        "decision does not suppress and the scan warns about it.",
    )


def _register_list(parser: argparse.ArgumentParser) -> None:
    _add_common_options(parser)
    parser.add_argument(
        "scan_dir",
        nargs="?",
        help="A scan directory to match the entries against, so the listing "
        "names what each entry matches and flags the stale ones.",
    )


def _register_review(parser: argparse.ArgumentParser) -> None:
    _add_common_options(parser)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--approve", type=int, help="The entry number to approve.")
    group.add_argument("--reject", type=int, help="The proposal number to reject and remove.")
    parser.add_argument(
        "--approver",
        required=True,
        help="Who approved the proposal. Never guessed from git or the environment.",
    )


def _register_remove(parser: argparse.ArgumentParser) -> None:
    _add_common_options(parser)
    parser.add_argument("entry", type=int, help="The entry number to remove.")


def _register_check(parser: argparse.ArgumentParser) -> None:
    _add_common_options(parser)
    parser.add_argument(
        "scan_dir",
        nargs="?",
        help="A scan directory to also report the stale and expired entries "
        "against.",
    )


def _print_listing(document, json_output: bool) -> None:
    if json_output:
        print_json_document(document)
        return
    from rich.markup import escape

    from depscan.lib.logger import console

    for entry in document["entries"]:
        selector = ", ".join(
            f"{key} {value}"
            for key, value in entry.items()
            if key in ("finding", "advisory", "purl", "version_range")
        )
        line = (
            f"{entry['index']}: {escape(selector)} state {entry['state']} "
            f"status {entry['status']}"
        )
        if entry.get("author"):
            line += f" author {entry['author']}"
        if entry.get("approver"):
            line += f" approver {entry['approver']}"
        if entry.get("proposedBy"):
            line += f" proposed by {entry['proposedBy']}"
        if entry.get("expires"):
            line += f" expires {entry['expires']}"
        console.print(line)
        if document.get("scanDir") and "matches" in entry:
            if entry["matches"]:
                console.print(f"    matches {len(entry['matches'])} finding(s)")
            elif entry["status"] == "live":
                console.print("    matches no finding in this scan (stale)")
    summary = (
        f"{len(document['entries'])} entries, {len(document['stale'])} stale, "
        f"{len(document['expired'])} expired, {len(document['proposals'])} proposals"
    )
    console.print(summary)


def _print_result(document, json_output: bool) -> None:
    if json_output:
        print_json_document(document)
        return
    from rich.markup import escape

    from depscan.lib.logger import console

    entry = document["entry"]
    selector = ", ".join(
        f"{key} {value}"
        for key, value in entry.items()
        if key in ("finding", "advisory", "purl", "version_range")
    )
    console.print(
        f"{document['result']}: entry {entry['index']} ({escape(selector)}) "
        f"in {document['decisionsFile']}"
    )


def run(args: argparse.Namespace) -> int:
    """Run the triage verb; the process exit code."""
    json_output = args.format == "json"
    file = _decisions_file(args)
    verb = f"triage {getattr(args, 'subcommand', '')}".strip()
    try:
        if args.subcommand == "set":
            document = api.triage_set(
                file=file,
                state=args.state,
                author=args.author,
                finding=args.finding,
                advisory=args.advisory,
                purl=args.purl,
                version_range=args.version_range,
                justification=args.justification,
                responses=args.responses,
                detail=args.detail,
                proposed_by=args.proposed_by,
                created=args.created,
                expires=args.expires,
            )
            document["subcommand"] = "set"
            _print_result(document, json_output)
            return EXIT_SUCCESS
        if args.subcommand == "list":
            document = api.triage_entries(file=file, scan_dir=args.scan_dir)
            document["subcommand"] = "list"
            _print_listing(document, json_output)
            return EXIT_SUCCESS
        if args.subcommand == "review":
            document = api.triage_review(
                file=file,
                approver=args.approver,
                approve=args.approve,
                reject=args.reject,
            )
            document["subcommand"] = "review"
            _print_result(document, json_output)
            return EXIT_SUCCESS
        if args.subcommand == "remove":
            document = api.triage_remove(file=file, entry=args.entry)
            document["subcommand"] = "remove"
            _print_result(document, json_output)
            return EXIT_SUCCESS
        if args.subcommand == "check":
            document = api.triage_check(file=file, scan_dir=args.scan_dir)
            document["subcommand"] = "check"
            if json_output:
                print_json_document(document)
            else:
                _print_listing(document, json_output=False)
                for error in document.get("errors") or []:
                    print(error, file=sys.stderr)
            if document.get("errors") or not document.get("valid", True):
                return EXIT_CHECK_FAILED
            return EXIT_SUCCESS
        message = f"depscan triage: unknown subcommand {args.subcommand!r}"
        if json_output:
            print_error_document(EXIT_USAGE, "triage", message)
        else:
            print(message, file=sys.stderr)
        return EXIT_USAGE
    except api.TriageApiError as exc:
        message = f"depscan {verb}: {exc}"
        if json_output:
            print_error_document(EXIT_USAGE, "triage", message)
        else:
            print(message, file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # noqa: BLE001 - json stdout always carries a document
        message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        LOG.exception("The triage command stopped with an unexpected error: %s", message)
        if json_output:
            print_error_document(EXIT_FAILURE, "triage", message)
        else:
            print(f"depscan {verb}: {message}", file=sys.stderr)
        return EXIT_FAILURE
