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
  picked up. :func:`find_executable` applies the same rule to the checks
  that decide whether a tool is installed.
* An npm shim such as ``cdxgen.cmd`` is replaced by the ``node`` command the
  shim would have run, so cmd.exe is not involved at all.
* Any other batch file runs through cmd.exe with every argument quoted, and
  an argument containing a character that cmd.exe or the batch file itself
  could interpret is refused, because a wrapper that expands ``%~1`` or
  copies ``%*`` into a variable re-parses its arguments.
* Only ``.exe``, ``.com``, ``.bat`` and ``.cmd`` files are started.

:func:`tool_env` adds ``NoDefaultCurrentDirectoryInExePath`` to the child
environment on Windows, so neither cmd.exe nor the tool itself runs a bare
command name from the scanned project.
"""

from __future__ import annotations

import ntpath
import os
import re
import shutil
import subprocess
import sys
from typing import Callable, List, Optional, Sequence, Union

WINDOWS_BATCH_SUFFIXES = (".bat", ".cmd")

WINDOWS_EXECUTABLE_SUFFIXES = (".exe", ".com")

DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD"

# Characters refused in arguments for a batch file that is not an npm shim.
# cmd.exe gives '"', '%', '!', line breaks and NUL a meaning even inside a
# double-quoted argument. '&', '|', '<', '>' and '^' are safe inside the quotes
# this module adds, but a wrapper that uses %~1 or copies %* into a variable
# strips those quotes and runs them, so they are refused as well.
UNSAFE_BATCH_ARG_CHARS = frozenset('"%!\r\n\x00&|<>^')

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
    return [ext.strip() for ext in pathext.split(";") if ext.strip()]


def windows_suffix(path: str) -> str:
    """Return the lower-case extension Windows uses for ``path``.

    Windows ignores trailing dots and spaces in file names, so ``run.bat.``
    and ``run.bat `` both start ``run.bat``.
    """
    return ntpath.splitext(path.rstrip(" ."))[1].lower()


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
    suffix = windows_suffix(command)
    has_pathext_suffix = bool(suffix) and suffix in (ext.lower() for ext in exts)
    if has_pathext_suffix:
        names = [command]
    else:
        names = [command + ext for ext in exts]
    if ntpath.dirname(command):
        # An explicit path is the caller's choice, so it is honoured as given.
        # Names with a PATHEXT extension come first: npm writes an
        # extensionless shell script next to cdxgen.cmd, which Windows cannot
        # start. A name with some other extension is tried last, as given.
        candidates = names if has_pathext_suffix or not suffix else [*names, command]
        for candidate in candidates:
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


def find_executable(name: str) -> Optional[str]:
    """Find a program on ``PATH``, never in the current directory on Windows.

    Use this instead of :func:`shutil.which` to decide whether a tool is
    installed, so the check and :func:`build_command` agree on the program.
    """
    if sys.platform == "win32":
        return windows_which(name)
    return shutil.which(name)


def tool_env(env: Optional[dict] = None) -> dict:
    """Return the environment for a tool, ``os.environ`` when ``env`` is None.

    On Windows ``NoDefaultCurrentDirectoryInExePath`` is set, so cmd.exe and
    the tool's own child processes look up bare command names on ``PATH``
    only. The tools run inside the scanned project, where a planted
    ``node.bat`` or ``npm.cmd`` would otherwise run first.
    """
    result = dict(os.environ if env is None else env)
    if sys.platform == "win32":
        result["NoDefaultCurrentDirectoryInExePath"] = "1"
    return result


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
    if not node or windows_suffix(node) not in WINDOWS_EXECUTABLE_SUFFIXES:
        return None
    return [node, script]


def quote_batch_arg(arg: str) -> str:
    """Quote one argument for a batch file run through cmd.exe.

    Inside double quotes cmd.exe leaves parentheses and spaces alone. The
    characters in :data:`UNSAFE_BATCH_ARG_CHARS` cannot be made safe for
    every batch file, so an argument that contains one is refused.

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
        that cmd.exe would interpret, or when the program is not an
        executable or batch file.
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
    suffix = windows_suffix(program)
    if suffix in WINDOWS_EXECUTABLE_SUFFIXES:
        return [program, *argv[1:]]
    if suffix not in WINDOWS_BATCH_SUFFIXES:
        raise UnsafeCommandError(f"Refusing to start {program}: not an executable or batch file")
    node_command = npm_shim_command(program)
    if node_command:
        return [*node_command, *argv[1:]]
    return batch_command_line(program, argv[1:], _comspec())
