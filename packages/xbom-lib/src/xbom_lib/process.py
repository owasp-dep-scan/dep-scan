"""Build the command for an external tool so that no shell re-parses it.

dep-scan passes values that a caller can influence, such as the source
directory, to cdxgen and to the rusi, golem and dosai plugins. On Linux and
macOS the argument list goes straight to ``execve``, so every value stays a
single argument. Windows has no ``execve``: ``CreateProcess`` receives one
command line, and when the program is a batch file (``.cmd`` or ``.bat``,
which is how npm installs cdxgen) Windows runs it through cmd.exe. cmd.exe
treats ``&``, ``|``, ``<``, ``>`` and ``"`` as shell syntax, even when Python
started the process with ``shell=False``, so a directory named
``x&calc`` would start a second program.

:func:`build_command` returns a value that is safe to pass to
:func:`subprocess.run` with ``shell=False`` on every platform:

* On Linux and macOS the argument list is returned unchanged.
* On Windows the program is looked up on ``PATH`` without the current
  directory, so a ``cdxgen.cmd`` planted in the scanned project is never
  picked up.
* An npm shim such as ``cdxgen.cmd`` is replaced by the ``node`` command the
  shim would have run, so cmd.exe is not involved at all.
* Any other batch file runs through cmd.exe with every argument quoted, and
  an argument that cmd.exe would still interpret inside quotes is refused.
"""

from __future__ import annotations

import ntpath
import os
import re
import subprocess
import sys
from typing import Callable, List, Optional, Sequence, Union

WINDOWS_BATCH_SUFFIXES = (".bat", ".cmd")

DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD"

# cmd.exe gives these characters a meaning even inside a double-quoted
# argument: '"' ends the quoted region, '%' expands an environment variable,
# '!' expands one when delayed expansion is on, and a line break or NUL ends
# the command.
UNSAFE_BATCH_ARG_CHARS = frozenset('"%!\r\n\x00')

# The last line of the shim that npm's cmd-shim writes for a node program:
#   endLocal & ... & "%_prog%"  "%dp0%\node_modules\<pkg>\bin\<script>.js" %*
# where %_prog% is the node.exe next to the shim, or else "node" from PATH.
NPM_SHIM_SCRIPT_RE = re.compile(r'"%_prog%"\s+"%dp0%\\([^"%\r\n]+\.(?:js|cjs|mjs))"\s+%\*')

# npm shims are well under 1 KB. Anything larger is not one.
MAX_NPM_SHIM_SIZE = 64 * 1024


class UnsafeCommandError(subprocess.SubprocessError):
    """An argument cannot be passed to a Windows batch file safely."""


def _pathext_list(pathext: Optional[str]) -> List[str]:
    if pathext is None:
        pathext = os.environ.get("PATHEXT") or DEFAULT_PATHEXT
    return [ext for ext in pathext.split(";") if ext]


def windows_which(
    command: str,
    path_env: Optional[str] = None,
    pathext: Optional[str] = None,
    isfile: Callable[[str], bool] = os.path.isfile,
) -> Optional[str]:
    """Find ``command`` the way cmd.exe would, but never in the current directory.

    cmd.exe and ``shutil.which`` both search the current directory before
    ``PATH`` on Windows. The tools run with the scanned project as their
    working directory, and the CLI is often started from inside the project,
    so a ``cdxgen.cmd`` committed to that project would run instead of the
    real cdxgen. Relative ``PATH`` entries are skipped for the same reason.

    :param command: Program name, or a path to it, with or without extension.
    :param path_env: ``PATH`` value to search. Defaults to the environment.
    :param pathext: ``PATHEXT`` value. Defaults to the environment.
    :param isfile: File check, replaceable in tests.
    :returns: The path of the program, or ``None`` when it was not found.
    """
    if not command:
        return None
    exts = _pathext_list(pathext)
    suffix = ntpath.splitext(command)[1].lower()
    if suffix and suffix in (ext.lower() for ext in exts):
        names = [command]
    else:
        names = [command + ext for ext in exts]
    if ntpath.dirname(command):
        # An explicit path is the caller's choice, so it is honoured as given.
        # CreateProcess also accepts a path without its extension.
        for candidate in [command, *names]:
            if isfile(candidate):
                return candidate if ntpath.isabs(candidate) else os.path.abspath(candidate)
        return None
    if path_env is None:
        path_env = os.environ.get("PATH", "")
    for directory in path_env.split(";"):
        directory = directory.strip().strip('"')
        if not directory or not ntpath.isabs(directory):
            continue
        for name in names:
            candidate = ntpath.join(directory, name)
            if isfile(candidate):
                return candidate
    return None


def parse_npm_shim(text: str) -> Optional[str]:
    """Return the script path, relative to the shim, that an npm shim runs.

    Only the layout written by npm's cmd-shim is recognised. Any other batch
    file returns ``None`` and is run through cmd.exe with quoted arguments.
    """
    match = NPM_SHIM_SCRIPT_RE.search(text)
    return match.group(1) if match else None


def npm_shim_command(
    shim_path: str,
    which: Callable[[str], Optional[str]] = windows_which,
    isfile: Callable[[str], bool] = os.path.isfile,
) -> Optional[List[str]]:
    """Return ``[node, script]`` for an npm shim, or ``None`` for any other file.

    The shim runs the ``node.exe`` next to it when there is one, and otherwise
    ``node`` from ``PATH``, with the script path it names. Running that
    command directly gives the tool the same arguments without cmd.exe.
    """
    try:
        if os.path.getsize(shim_path) > MAX_NPM_SHIM_SIZE:
            return None
        with open(shim_path, encoding="utf-8", errors="replace") as fp:
            text = fp.read()
    except OSError:
        return None
    script_rel = parse_npm_shim(text)
    if not script_rel:
        return None
    shim_dir = ntpath.dirname(shim_path)
    script = ntpath.join(shim_dir, script_rel)
    if not isfile(script):
        return None
    node = ntpath.join(shim_dir, "node.exe")
    if not isfile(node):
        node = which("node")
    if not node or ntpath.splitext(node)[1].lower() in WINDOWS_BATCH_SUFFIXES:
        return None
    return [node, script]


def quote_batch_arg(arg: str) -> str:
    """Quote one argument for a batch file run through cmd.exe.

    Inside double quotes cmd.exe leaves ``&``, ``|``, ``<``, ``>``, ``^``,
    parentheses and spaces alone. The characters in
    :data:`UNSAFE_BATCH_ARG_CHARS` cannot be made safe that way, so an
    argument that contains one is refused.

    Backslashes are literal inside the quotes, except for a run right before
    the closing quote, which the program would read as an escaped quote. That
    trailing run is doubled, as :func:`subprocess.list2cmdline` does.

    :raises UnsafeCommandError: when the argument contains an unsafe character.
    """
    unsafe = sorted(set(arg) & UNSAFE_BATCH_ARG_CHARS)
    if unsafe:
        raise UnsafeCommandError(
            "Refusing to pass an argument containing "
            f"{', '.join(repr(c) for c in unsafe)} to a Windows batch file: {arg!r}"
        )
    body = arg.rstrip("\\")
    trailing = len(arg) - len(body)
    return '"' + body + "\\" * (2 * trailing) + '"'


def batch_command_line(batch_file: str, args: Sequence[str], comspec: str) -> str:
    """Build the cmd.exe command line that runs ``batch_file`` with ``args``.

    ``/d`` skips the AutoRun commands from the registry, ``/v:off`` keeps
    delayed expansion off, and ``/s /c "..."`` makes cmd.exe drop exactly the
    outer pair of quotes and run what is inside.
    """
    inner = " ".join(quote_batch_arg(a) for a in [batch_file, *args])
    return f'"{comspec}" /d /v:off /s /c "{inner}"'


def _comspec() -> str:
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    return ntpath.join(system_root, "System32", "cmd.exe")


def build_command(args: Sequence[str]) -> Union[List[str], str]:
    """Return what to pass to :func:`subprocess.run` (with ``shell=False``).

    :param args: The program followed by its arguments.
    :returns: A list on Linux and macOS and for Windows executables, or a
        cmd.exe command line string for a Windows batch file that is not an
        npm shim.
    :raises FileNotFoundError: when the program is not found on Windows.
    :raises UnsafeCommandError: when a batch file would receive an argument
        that cmd.exe would interpret.
    """
    argv = [str(a) for a in args]
    if sys.platform != "win32" or not argv:
        return argv
    return _build_windows_command(argv)


def _build_windows_command(argv: List[str]) -> Union[List[str], str]:
    found = windows_which(argv[0])
    if found is None:
        if ntpath.dirname(argv[0]):
            # CreateProcess does not search for a name that carries a
            # directory, so a missing path simply fails to start, as before.
            return argv
        raise FileNotFoundError(f"{argv[0]} was not found on PATH")
    program: str = found
    if ntpath.splitext(program)[1].lower() not in WINDOWS_BATCH_SUFFIXES:
        return [program, *argv[1:]]
    node_command = npm_shim_command(program)
    if node_command:
        return [*node_command, *argv[1:]]
    return batch_command_line(program, argv[1:], _comspec())
