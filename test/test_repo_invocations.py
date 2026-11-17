"""Every depscan invocation in the repository's own files uses the v7 verbs.

The repository ships its command line in workflows, scripts, Dockerfiles,
compose files and the README. When the verb command line landed, each of
those invocations was rewritten; this test keeps a v6 shape (options before
any verb) from creeping back into any of them.

The extractor walks the files the repository publishes, joins shell
continuation lines and pulls out every ``depscan`` command it can tokenize.
Prose that merely mentions depscan is told apart from a command by position:
a command starts a line or follows ``run`` or a shell separator, so words
such as ``--cov=depscan`` or ``--collect-submodules depscan`` never count.
"""

import re
from pathlib import Path

import pytest

from depscan.commands import VERBS, build_parser
from depscan.commands.translate import translate

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Every file the check walks: the CI configuration, the contributed tooling
#: and examples, the container build files and the README.
FILE_GLOBS = (
    ".github/**/*",
    "contrib/**/*",
    "Dockerfile",
    "Dockerfile.al9",
    "docker-compose.yml",
    "README.md",
)

#: The ten registered verbs plus the help flags argparse answers before any
#: verb is required.
ACCEPTED_FIRST_TOKENS = frozenset(VERBS) | {"-h", "--help"}

#: A word that must not survive anywhere in the walked files: both console
#: scripts were folded into verbs.
REMOVED_COMMANDS = ("depscan-vdb", "depscan-validate")

#: ``depscan`` as a command word: not glued into a larger token before or
#: after, so paths (``depscan/cli.py``), option values (``--cov=depscan``),
#: hyphenated names (``depscan-linux-amd64``) and quoted words never match.
_DEPSCAN_WORD = re.compile(r"(?<![\w/.=@$-])(depscan)(?=$|\s)")

#: Tokens that may carry a depscan command on their right-hand side.
_COMMAND_PREFIXES = frozenset({"run", "&&", "||", ";", "|"})

#: Punctuation prose glues to the end of a quoted command.
_TRAILING_PROSE = "\"'.,):;"

#: A bare ``name:tag`` image reference (a single letter before the colon is a
#: drive letter, not a one-character repository name).
_TAG_REFERENCE = re.compile(r"^(?![A-Za-z]:)[^\s/:@]+:[^\s/:@]+$")

#: Unquoted characters that end a command and start shell plumbing.
_SEPARATORS = "|&;>`"


def _walk_files():
    """Every existing file the check reads, as paths relative to the repo."""
    seen = set()
    for pattern in FILE_GLOBS:
        for path in sorted(REPO_ROOT.glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                yield path


def _read_text(path):
    """The file's text, or None when it is not decodable text at all."""
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _join_continuations(text):
    """Join lines that continue with a trailing backslash.

    Returns ``(first_lineno, joined_line)`` pairs with 1-based line numbers,
    so a failure can name the line the command starts on.
    """
    joined = []
    buffer = ""
    start = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        buffer = f"{buffer} {line.strip()}" if buffer else line
        start = start or lineno
        if buffer.rstrip().endswith("\\"):
            buffer = buffer.rstrip()[:-1].rstrip()
            continue
        joined.append((start, buffer))
        buffer = ""
        start = 0
    if buffer:
        joined.append((start, buffer))
    return joined


def _tokenize(tail):
    """Split the text after ``depscan`` into argv tokens.

    Quotes are dropped the way a shell drops them, an unquoted separator ends
    the command, and prose punctuation on the final token is stripped.
    """
    tokens = []
    current = ""
    quote = None
    for char in tail:
        if quote:
            if char == quote:
                quote = None
            else:
                current += char
        elif char in "\"'":
            quote = char
        elif char in _SEPARATORS:
            break
        elif char.isspace():
            if current:
                tokens.append(current)
                current = ""
        else:
            current += char
    if current:
        tokens.append(current)
    while tokens and not tokens[-1].rstrip(_TRAILING_PROSE):
        tokens.pop()
    if tokens:
        tokens[-1] = tokens[-1].rstrip(_TRAILING_PROSE)
        if not tokens[-1]:
            tokens.pop()
    return tokens


def _in_command_position(line, match):
    """Whether the match starts a command rather than naming depscan in prose.

    A command begins a line, follows ``run`` (as in ``uv run depscan``) or
    follows a shell separator. Anything else, a sentence, an option value or
    an argument to another tool, is prose.
    """
    prefix = line[: match.start()].rstrip()
    if not prefix:
        return True
    last = prefix.split()[-1]
    return last in _COMMAND_PREFIXES


def extract_invocations() -> list[tuple[Path, int, list[str]]]:
    """Every ``(path, lineno, argv)`` depscan command in the walked files."""
    found: list[tuple[Path, int, list[str]]] = []
    for path in _walk_files():
        text = _read_text(path)
        if text is None:
            continue
        for lineno, line in _join_continuations(text):
            for match in _DEPSCAN_WORD.finditer(line):
                if not _in_command_position(line, match):
                    continue
                tokens = _tokenize(line[match.end() :])
                if not tokens:
                    # A bare word at the end of a sentence, not a command.
                    continue
                found.append((path, lineno, ["depscan", *tokens]))
    return found


def _looks_like_target(token):
    """Whether a raw token names a scan target rather than a plain word.

    Targets in the published commands are purls, image references (a tag or a
    sha256 digest) and paths (absolute, relative or through a shell
    variable). Project-type words such as ``docker`` or ``docker,license``
    never match, so the predicate separates a lost target from a type value.
    """
    return (
        token.startswith("pkg:")
        or "@sha256:" in token
        or token.startswith(("/", "./", "$", "~"))
        or "/" in token
        or bool(_TAG_REFERENCE.match(token))
    )


def test_no_invocation_keeps_a_v6_leading_option():
    """A command whose first token is an option is the v6 options-first shape."""
    leftovers = [
        f"{path.relative_to(REPO_ROOT)}:{lineno}: {' '.join(argv)}"
        for path, lineno, argv in extract_invocations()
        if argv[1].startswith("-") and argv[1] not in ("-h", "--help")
    ]
    assert not leftovers, "v6 invocations remain: " + "\n".join(leftovers)


def test_every_invocation_names_a_registered_verb():
    """The token after depscan is a verb or a help flag, never prose."""
    offenders = [
        f"{path.relative_to(REPO_ROOT)}:{lineno}: {' '.join(argv)}"
        for path, lineno, argv in extract_invocations()
        if argv[1] not in ACCEPTED_FIRST_TOKENS
    ]
    assert not offenders, "unknown verbs in invocations: " + "\n".join(offenders)


def _matrix_substituted(argv):
    r"""argv with ``${{ ... }}`` expressions replaced by a plain word.

    A workflow runner evaluates the expressions before the shell sees the
    line, so a value such as ``containertests_${{ matrix.os }}`` reaches the
    command as one word. Whitespace tokenization cuts the raw line at the
    expression's spaces; substituting first restores the word structure the
    runner produces.
    """
    return re.sub(r"\$\{\{[^}]*\}\}", "m", " ".join(argv)).split()


def _parse_scan(argv):
    """Parse a scan invocation through the real registry parser.

    Returns ``(namespace, problem)``; exactly one of them is None. argparse
    answers a usage error with SystemExit, which carries no namespace.
    """
    try:
        return build_parser().parse_args(_matrix_substituted(argv)[1:]), None
    except SystemExit:
        return None, f"the parser rejects the command: {' '.join(argv)}"


def test_type_values_never_swallow_a_target():
    """A target written after -t/--type is consumed as another type value.

    ``-t/--type`` takes one or more values, so a positional target that
    follows it never reaches ``targets``: with zero targets the scan verb
    scans the current directory under the swallowed image reference as a
    project type. Every published scan that names a type is parsed with the
    real parser: the raw values behind the type option must all be plain
    type words, and a command that names a target-like token anywhere must
    keep a non-empty target list.
    """
    problems = []
    for path, lineno, argv in extract_invocations():
        if argv[1] != "scan" or not {"-t", "--type"} & set(argv):
            continue
        where = f"{path.relative_to(REPO_ROOT)}:{lineno}: {' '.join(argv)}"
        tokens = _matrix_substituted(argv)
        namespace, problem = _parse_scan(argv)
        if problem:
            problems.append(f"{where}: {problem}")
            continue
        for index, token in enumerate(tokens):
            if token not in ("-t", "--type"):
                continue
            absorbed = []
            for value in tokens[index + 1 :]:
                if value.startswith("-"):
                    break
                absorbed.append(value)
            swallowed = [value for value in absorbed if _looks_like_target(value)]
            if swallowed:
                problems.append(
                    f"{where}: -t absorbed target-like values {swallowed}; "
                    "move the target in front of the options"
                )
        target_like = [token for token in tokens[2:] if _looks_like_target(token)]
        if target_like and not getattr(namespace, "targets", None):
            problems.append(f"{where}: names {target_like} but parses with no target")
    assert not problems, "\n".join(problems)


def test_dockertests_ubuntu_scan_keeps_its_target():
    """The ubuntu image is the scan's target, not a second type value."""
    matches = [
        (path, lineno, argv)
        for path, lineno, argv in extract_invocations()
        if path.name == "dockertests.yml" and "ubuntu:latest" in argv
    ]
    assert len(matches) == 1, "expected exactly one ubuntu:latest scan"
    _, _, argv = matches[0]
    namespace, problem = _parse_scan(argv)
    assert problem is None, problem
    assert getattr(namespace, "targets", None) == ["ubuntu:latest"]
    assert list(getattr(namespace, "project_type", None) or []) == ["docker"]


@pytest.mark.parametrize(
    "removed", REMOVED_COMMANDS, ids=lambda name: name.replace("depscan-", "")
)
def test_removed_console_scripts_are_gone(removed):
    """depscan-vdb and depscan-validate must not appear anywhere at all."""
    for path in _walk_files():
        text = _read_text(path)
        if text is None:
            continue
        assert removed not in text, f"{path.relative_to(REPO_ROOT)} still names {removed}"


#: Representative before/after pairs for the rewrites the files carry. Each
#: ``before`` is the v6 argv a file used, each ``after`` the translator's v7
#: command for it, so the pairs double as a check that the translator still
#: produces the shapes the repository publishes.
TRANSLATED_PAIRS = [
    # dockertests.yml: container reference, digest reference, bom file
    (
        [
            "--no-banner",
            "--src",
            "shiftleft/scan-slim",
            "-o",
            "containertests",
            "-t",
            "docker,license",
            "--no-vuln-table",
        ],
        "depscan scan shiftleft/scan-slim --no-banner --reports-dir containertests "
        "--type docker,license --no-vuln-table",
    ),
    (
        [
            "--no-banner",
            "-t",
            "docker",
            "--src",
            "ubuntu:latest",
            "-o",
            "containertests",
            "--no-vuln-table",
        ],
        "depscan scan ubuntu:latest --no-banner --reports-dir containertests "
        "--type docker --no-vuln-table",
    ),
    (
        ["--no-banner", "--bom", "sbom-docker.cdx.json", "-o", "reports", "--no-vuln-table"],
        "depscan scan sbom-docker.cdx.json --no-banner --reports-dir reports --no-vuln-table",
    ),
    # repotests.yml and the lifecycle workflows
    (
        [
            "--src",
            "${GITHUB_WORKSPACE}/repotests/java-sec-code",
            "--reports-dir",
            "reports",
            "--profile",
            "research",
            "-t",
            "java",
            "--bom-engine",
            "CdxgenGenerator",
            "--reachability-analyzer",
            "SemanticReachability",
            "--explain",
        ],
        "depscan scan ${GITHUB_WORKSPACE}/repotests/java-sec-code --reports-dir reports "
        "--bom-profile research --bom-engine CdxgenGenerator "
        "--reachability-analyzer SemanticReachability --type java --explain",
    ),
    (
        [
            "--src",
            "${GITHUB_WORKSPACE}/repotests/attestation-client-samples",
            "--reports-dir",
            "reports",
            "-t",
            "cpp",
            "--vulnerability-analyzer",
            "LifecycleAnalyzer",
        ],
        "depscan scan ${GITHUB_WORKSPACE}/repotests/attestation-client-samples "
        "--reports-dir reports --vulnerability-analyzer LifecycleAnalyzer --type cpp",
    ),
    # gobintests.yml: binary directory
    (
        [
            "--no-banner",
            "--src",
            "${HOME}/.local/share/soar/bin",
            "--reports-dir",
            "bintests",
            "-t",
            "binary",
        ],
        "depscan scan ${HOME}/.local/share/soar/bin --no-banner --reports-dir "
        "bintests --type binary",
    ),
    # pythonapp.yml: purl targets and the config file
    (["--purl", "pkg:pypi/requests@2.32.1"], "depscan scan pkg:pypi/requests@2.32.1"),
    (
        ["--purl", "pkg:pypi/custom-test@1.0.0", "--custom-data", "custom_vulns"],
        "depscan scan pkg:pypi/custom-test@1.0.0 --custom-data custom_vulns",
    ),
    (
        ["--config", ".config/depscan-dev.toml"],
        "depscan scan --config .config/depscan-dev.toml",
    ),
    # csafdemo.yml
    (["--bom", "./bom.json", "--csaf"], "depscan scan ./bom.json --csaf"),
    # dockertests.yml: the ubuntu image. The translator's ordering keeps the
    # target in front of the options, which is what keeps it out of the
    # one-or-more values -t/--type consumes.
    (
        [
            "--no-banner",
            "-t",
            "docker",
            "--src",
            "ubuntu:latest",
            "-o",
            "containertests",
            "--no-vuln-table",
        ],
        "depscan scan ubuntu:latest --no-banner --reports-dir containertests "
        "--type docker --no-vuln-table",
    ),
    # README.md quick-start shapes
    (
        ["-i", "./my-rust-app", "-o", "./reports", "--profile", "research"],
        "depscan scan ./my-rust-app --reports-dir ./reports --bom-profile research",
    ),
    (
        [
            "--profile",
            "research",
            "-t",
            "java",
            "-i",
            "./my-java-app",
            "-o",
            "./reports",
            "--explain",
        ],
        "depscan scan ./my-java-app --reports-dir ./reports --bom-profile research "
        "--type java --explain",
    ),
    (
        ["--src", "/tmp/scanslim.tar", "-o", "reports", "-t", "docker"],
        "depscan scan /tmp/scanslim.tar --reports-dir reports --type docker",
    ),
    # README.md and docker-compose.yml server mode
    (
        [
            "--server",
            "--server-host",
            "0.0.0.0",
            "--server-port",
            "7070",
            "--cdxgen-server",
            "http://cdxgen:9090",
        ],
        "depscan serve --server-host 0.0.0.0 --server-port 7070 "
        "--cdxgen-server http://cdxgen:9090",
    ),
    # .github/ISSUE_TEMPLATE/false_positive.yaml
    (["--purl", "purl-of-the-wrong-positive"], "depscan scan purl-of-the-wrong-positive"),
    # the version smoke tests of the standalone binaries
    (["--version"], "depscan version"),
    (["-v"], "depscan version"),
]


@pytest.mark.parametrize(
    "before,after", TRANSLATED_PAIRS, ids=[str(index) for index in range(len(TRANSLATED_PAIRS))]
)
def test_translator_produces_the_published_shapes(before, after):
    """The v6 argv of every rewritten line translates to its v7 command."""
    assert translate(before) == after


#: Content the position-based extractor cannot see (backticked, quoted or
#: variable-indirected), asserted directly against the file text.
TARGETED_CONTENT = {
    ".github/ISSUE_TEMPLATE/false_positive.yaml": 'depscan scan "pkg:<purl-of-the-false-positive>"',
    ".github/scripts/repotest-project.sh": '$DEPSCAN scan "$PROJECT_DIR" --target-kind bom-dir',
    ".github/workflows/repotests.yml": "depscan scan ${GITHUB_WORKSPACE}/repotests/dejacode/reports "
    "--target-kind bom-dir",
    ".github/workflows/sea-linux.yml": "./dist/${{ matrix.binary_name }} version",
    ".github/workflows/sea-mac.yml": "./dist/${{ matrix.binary_name }} version",
    ".github/workflows/sea-win.yml": '& "dist\\$env:BINARY_NAME.exe" version',
    "Dockerfile": 'CMD [ "depscan", "scan" ]',
    "Dockerfile.al9": 'CMD [ "depscan", "scan" ]',
    "docker-compose.yml": "entrypoint: depscan serve --server-host 0.0.0.0 "
    "--server-port 7070 --cdxgen-server http://cdxgen:9090",
    "README.md": "depscan vdb download --flavor app-only",
}


@pytest.mark.parametrize(
    "relative_path,expected", TARGETED_CONTENT.items(), ids=sorted(TARGETED_CONTENT)
)
def test_hand_adjusted_rewrites_are_present(relative_path, expected):
    """The rewrites that needed judgement survive in their files verbatim."""
    text = _read_text(REPO_ROOT / relative_path)
    assert text is not None and expected in text, f"{expected!r} is missing from {relative_path}"
