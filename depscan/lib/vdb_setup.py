"""Database selection and setup for a scan.

Everything a scan needs before it can search: resolving which database image
the run uses, downloading or refreshing it (with retries), the opt-in shard
mode, read-only SQLite tuning and the guard that refuses to answer from an
empty database. The ``depscan-vdb`` command reuses the download helpers.
"""

import os
import time

from analysis_lib.packages import get_all_pkg_list, get_pkg_list
from vdb.lib import config
from vdb.lib import db as db_lib
from vdb.lib.utils import parse_purl

from depscan.lib.config import (
    VDB_AGE_HOURS,
    VDB_FLAVORS,
    read_vdb_image_marker,
    resolve_vdb_flavor,
    resolve_vdb_image_url,
    vdb_shards_marker,
    write_vdb_image_marker,
)
from depscan.lib.logger import LOG


def _positive_int_env(name: str, default: int) -> int:
    """Read a positive int from the environment, falling back to ``default``."""
    try:
        value = int(os.getenv(name, ""))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


# The database image is a multi-hundred-MB pull; a dropped connection
# mid-stream raises ChunkedEncodingError / urllib3 ProtocolError /
# IncompleteRead. These are transient (common in CI), so retry a few times
# before giving up.
VDB_DOWNLOAD_MAX_ATTEMPTS = _positive_int_env("VDB_DOWNLOAD_RETRIES", 3)
VDB_DOWNLOAD_RETRY_BACKOFF_SEC = _positive_int_env("VDB_DOWNLOAD_RETRY_BACKOFF_SEC", 5)


def download_vdb_with_retries(vdb_database_url, attempts=VDB_DOWNLOAD_MAX_ATTEMPTS):
    """Install the vulnerability database image, retrying transient errors.

    vdb's ``refresh_full_image`` stages, validates and atomically swaps the
    artifact, so the local database is untouched unless a usable image arrived
    completely; depscan never unpacks into the database directory itself. The
    download can still fail partway through with a variety of exceptions
    raised across the requests/urllib3 layers, so we retry with a linear
    backoff and re-raise the last error if every attempt fails.
    """
    from vdb.lib import db_cmd

    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            return db_cmd.refresh_full_image(image_url=vdb_database_url)
        except Exception as e:  # noqa: BLE001 - transient failures vary by layer
            last_exc = e
            if attempt < attempts:
                LOG.warning(
                    "Vulnerability database download failed (attempt %d/%d): %s. Retrying ...",
                    attempt,
                    attempts,
                    e,
                )
                time.sleep(VDB_DOWNLOAD_RETRY_BACKOFF_SEC * attempt)
            else:
                LOG.error(
                    "Vulnerability database download failed after %d attempt(s).",
                    attempts,
                )
    if last_exc is not None:
        raise last_exc


def vdb_download_needed(resolved_url, data_dir):
    """Decide whether the scan should (re-)download the vdb.

    The DB is re-downloaded when it is stale (time-based, via
    ``vdb.lib.db.needs_update``) OR when the depscan-owned variant marker differs
    from the freshly resolved image ref. The marker check catches a
    scope/time/tier/distro switch that ``needs_update`` would otherwise miss
    for up to ``VDB_AGE_HOURS`` because vdb metadata does not record the
    source variant.

    :param resolved_url: the image ref the scan resolved for this run
    :param data_dir: the vdb data directory (``config.DATA_DIR``)
    :return: ``(should_download, reason)`` where *reason* is ``"stale"``,
        ``"variant-change"``, or ``None``.
    """
    # needs_update returns default_status when the on-disk DB has no usable
    # metadata (a fresh install or a missing/corrupt DB). In that case we must
    # download, so default_status is True. (The previous
    # ``get_db_file_metadata is not None`` compared the function object, not its
    # result, so it was always True by accident; calling it would wrongly
    # return False on a fresh install and skip the download.)
    stale = db_lib.needs_update(
        days=0,
        hours=VDB_AGE_HOURS,
        default_status=True,
    )
    if stale:
        return True, "stale"
    marker = read_vdb_image_marker(data_dir)
    if marker is not None and marker != resolved_url:
        LOG.info(
            "vdb variant changed from '%s' to '%s'; forcing re-download.",
            marker,
            resolved_url,
        )
        return True, "variant-change"
    return False, None


def _select_flavor(args):
    """Choose the database flavor from the flavor and legacy options.

    ``--vdb-flavor`` wins; the deprecated ``--vdb-scope``/``--vdb-time``/
    ``--vdb-extended`` triple (plus ``USE_VDB_10Y``) is mapped through
    ``VDB_LEGACY_FLAVOR_MAP``, and each legacy option in use logs one warning
    naming the flavor the selection resolved to. Combinations with no v7
    flavor (a two-year window in any scope, an app+OS 10-year or extended
    variant, any per-distro selection) raise, naming the flavors, instead of
    silently mapping onto a bigger or smaller database.

    :return: ``(flavor, legacy_flags)``; *legacy_flags* lists the deprecated
        selectors in use, used by the caller to decide whether the choice was
        explicit.
    """
    flavor = getattr(args, "vdb_flavor", None)
    legacy_flags = [
        flag
        for flag, value in (
            ("--vdb-scope", getattr(args, "vdb_scope", None)),
            ("--vdb-time", getattr(args, "vdb_time", None)),
            ("--vdb-extended", bool(getattr(args, "vdb_extended", None))),
        )
        if value
    ]
    if flavor is not None:
        if legacy_flags:
            raise ValueError(
                "--vdb-flavor cannot be combined with the deprecated "
                "--vdb-scope, --vdb-time or --vdb-extended options."
            )
        return flavor, legacy_flags
    time_window = getattr(args, "vdb_time", None)
    scope = getattr(args, "vdb_scope", None)
    if not time_window and os.getenv("USE_VDB_10Y", "") in ("true", "1"):
        # USE_VDB_10Y has no v7 constant; the v7 10-year flavors are
        # app-scope, so the scope moves with it. The env var is not an
        # explicit flavor choice, so --severity may still add metadata.
        legacy_flags.append("USE_VDB_10Y")
        time_window = "10y"
        if scope is None:
            scope = "app"
    flavor = resolve_vdb_flavor(
        scope=scope or "app+os",
        time=time_window or "default",
        extended=bool(getattr(args, "vdb_extended", None)),
    )
    for flag in legacy_flags:
        LOG.warning(
            "%s is deprecated; this scan uses the '%s' flavor. Pass "
            "--vdb-flavor %s to select it directly.",
            flag,
            flavor,
            flavor,
        )
    return flavor, legacy_flags


def resolve_scan_vdb_image(args):
    """Resolve the database image the scan should use, and its flavor.

    Precedence, highest first:

    1. ``VDB_DATABASE_URL`` or ``--vdb-image`` -> used verbatim (flavor None).
    2. ``--vdb-flavor`` -> one of the five published flavors.
    3. The legacy ``--vdb-scope``/``--vdb-time``/``--vdb-extended`` triple
       (plus ``USE_VDB_10Y``), mapped through ``VDB_LEGACY_FLAVOR_MAP``.
    4. Nothing given -> ``full``.

    ``--severity`` upgrades an automatic selection to the metadata flavor
    (``app-extended``, or ``app-10y-extended`` under ``USE_VDB_10Y``) and sets
    ``VDB_INCLUDE_METADATA=true`` so the severity push-down into the search
    layer fires. A flavor the user chose explicitly is never overridden; the
    depscan-side severity floor (``analysis_lib.prioritize.vuln_meets_severity``)
    still filters the final VDR.

    :return: ``(url, user_pinned, flavor)``; *flavor* is ``None`` for a pinned
        image.
    """
    pinned = os.getenv("VDB_DATABASE_URL") or getattr(args, "vdb_image", None)
    if pinned:
        if args.severity and "-extended" not in pinned:
            LOG.info(
                "--severity is set but a non-extended vdb image is pinned. The "
                "severity floor is still applied to the final VDR. Use an "
                "*-extended image (or clear the pin) to push the filter into "
                "the search layer."
            )
        return pinned, True, None

    if getattr(args, "vdb_distro", None):
        raise ValueError(
            "vdb 7 publishes no per-distro complete database. Published "
            f"flavors: {', '.join(VDB_FLAVORS)}."
        )

    flavor, legacy_flags = _select_flavor(args)

    # An explicit choice is a flag; the deprecated USE_VDB_10Y env var is not
    # one, so --severity may still upgrade it to the metadata flavor.
    explicit_choice = bool(getattr(args, "vdb_flavor", None)) or any(
        flag != "USE_VDB_10Y" for flag in legacy_flags
    )
    if args.severity and not explicit_choice and "extended" not in flavor:
        # The metadata flavors are the answer to --severity's push-down.
        flavor = "app-10y-extended" if flavor == "app-10y" else "app-extended"
    if "extended" in flavor:
        os.environ["VDB_INCLUDE_METADATA"] = "true"
    if args.severity and not explicit_choice:
        LOG.info(
            "--severity needs metadata search; using the extended vdb flavor (%s).",
            flavor,
        )
    elif args.severity and "extended" not in flavor:
        LOG.info(
            "--severity is set with an explicitly chosen vdb flavor without "
            "metadata. The severity floor is still applied to the final VDR."
        )
    url = resolve_vdb_image_url(
        flavor=flavor, compression=getattr(args, "vdb_compression", None) or "xz"
    )
    return url, False, flavor


def configure_vdb_readonly():
    """Default vdb SQLite to read-only/immutable + WAL for scan runs.

    These defaults let SQLite skip lock acquisition and journal overhead on
    the read-only scan path, which is a prerequisite for safe concurrent
    reads and a small speed win. They are applied AFTER the vdb download so
    the update path is never opened immutable.

    Override with ``VDB_SQLITE_IMMUTABLE=false`` or
    ``VDB_SQLITE_JOURNAL_MODE=DELETE``.
    """
    if os.getenv("VDB_SQLITE_IMMUTABLE", "").lower() not in ("false", "0"):
        os.environ["VDB_SQLITE_IMMUTABLE"] = "true"
        # config.VDB_SQLITE_IMMUTABLE was captured at import time; patch it so
        # vdb.lib.db._sqlite_uri picks up immutable=1 on the first connection.
        config.VDB_SQLITE_IMMUTABLE = True
    if not os.getenv("VDB_SQLITE_JOURNAL_MODE"):
        os.environ["VDB_SQLITE_JOURNAL_MODE"] = "WAL"


class VdbUnusableError(RuntimeError):
    """The vulnerability database cannot answer a scan; the message says why."""


def ensure_vdb_usable():
    """Stop the scan when the local vulnerability database cannot answer.

    A database with no rows, a missing database, or a directory holding only
    v6 files (vdb 7 reads ``.vdb7`` databases and does not migrate v6
    artifacts) must fail the scan loudly: a scan that reports zero findings
    from zero data looks exactly like a clean result. vdb's own CLI refuses
    to answer on an empty database for the same reason.

    Reuses vdb's guard (``vdb.cli._warn_if_database_empty``, which prints the
    directory, the remedies and the v6-files hint) after opening the
    connections it needs; if the guard is not importable in a future vdb,
    falls back to the row count through ``vdb.lib.db``. Raises
    :class:`VdbUnusableError`, after logging why, when the database cannot
    answer.
    """
    db_lib.reset_connections()
    try:
        db_lib.get(read_only=True)
    except Exception as e:  # noqa: BLE001 - any driver error means unusable
        message = (
            f"The vulnerability database at {config.DATA_DIR} could not be opened ({e}). "
            "Fetch one with `depscan-vdb download` or 'vdb db refresh full'."
        )
        LOG.error(message)
        raise VdbUnusableError(message) from e
    try:
        # vdb's guard prints the empty-database message (directory, remedies,
        # v6-files paragraph) and returns True when the database is empty.
        from vdb.cli import _warn_if_database_empty

        if _warn_if_database_empty():
            message = (
                "Cannot scan without a vulnerability database. Fetch one with "
                "`depscan-vdb download` or 'vdb db refresh full'."
            )
            LOG.error(message)
            raise VdbUnusableError(message)
        return
    except ImportError:
        pass
    _, cve_index_count = db_lib.stats()
    if not cve_index_count:
        message = (
            f"The vulnerability database at {config.DATA_DIR} is empty; no search can "
            "return results. Fetch one with `depscan-vdb download` or 'vdb db refresh full'."
        )
        LOG.error(message)
        raise VdbUnusableError(message)


# --- opt-in shard mode -------------------------------------------------------
# With VDB_USE_SHARDS=true a scan refreshes the type shards serving its purl
# types instead of a complete database. Searches fan out only when the
# connected main database is itself a shard, so the first refreshed shard is
# connected as the main database with the store beside it (the layout vdb
# documents for shard deployments). Shards are opt-in: a mixed project whose
# types no shard covers would otherwise read as clean.
#
# A scan never reaches for the network mid-run: VDB_AUTO_FETCH stays off (a
# vdb opt-in), so an uncovered type stays a coverage gap to report, not a
# download to trigger.


def collect_purl_types(args, src_dir):
    """The purl types a scan will search, when they are known before matching.

    A single ``--purl`` knows its type from the argument; ``--bom`` and
    ``--bom-dir`` read the type off every component purl. Returns an empty
    list when the types are not known up front (depscan generating the BOM
    itself), which callers treat as "cannot use shards this run".
    """
    purl_types = []
    seen = set()
    if args.search_purl:
        purl_obj = parse_purl(args.search_purl)
        purl_obj["purl"] = args.search_purl
        pkg_list = [purl_obj]
    elif args.bom and os.path.isfile(args.bom):
        pkg_list, _lifecycles = get_pkg_list(args.bom)
    elif args.bom_dir and os.path.isdir(args.bom_dir):
        pkg_list = get_all_pkg_list(args.bom_dir)
    else:
        return []
    for pkg in pkg_list:
        purl = pkg.get("purl") or ""
        if not purl.startswith("pkg:"):
            continue
        purl_type = purl.split("pkg:", 1)[1].split("/", 1)[0].lower()
        if purl_type and purl_type not in seen:
            seen.add(purl_type)
            purl_types.append(purl_type)
    return purl_types


def report_shard_coverage(purl_types, store_dir=None):
    """Record and print the purl types no local shard covers.

    A type with no shard is NOT assessed; it must never read as clean. The
    answer comes from vdb's own coverage reporting
    (``shard_store.coverage_for_types``), never from a local type-to-shard
    table. Stale shards warn separately: "no data for X" and "old data for X"
    are different conditions. Everything a later task needs for the scan
    manifest is collected here, in this one function.
    """
    from vdb.lib import shard_store

    coverage, _records = shard_store.coverage_for_types(purl_types, store_dir=store_dir)
    uncovered = sorted(coverage.uncovered_types)
    if uncovered:
        LOG.warning(
            "purl type(s) %s have no local shard, so components of those types "
            "were NOT assessed; this is not a clean result. Refresh the shards "
            "(depscan-vdb download --shards %s ...) or use a complete database.",
            ", ".join(uncovered),
            ", ".join(uncovered),
        )
    for shard_name in coverage.stale_shards:
        LOG.warning(
            "shard %s is much older than its siblings; answers for the types it "
            "serves may be out of date. Refresh it with `depscan-vdb download "
            "--shards %s`.",
            shard_name,
            shard_name,
        )
    return coverage


def shards_refresh_needed(shard_names, store_dir=None):
    """Decide whether the shard store can serve *shard_names* as they are.

    The store is the truth, not the marker: a scan whose types are a subset
    of what was already fetched must not re-download. Refresh when a needed
    shard is missing from the store, or when a stored shard is older than
    ``VDB_AGE_HOURS`` (the same window the complete database uses).
    """
    from vdb.lib import db_cmd

    status = db_cmd.store_status(store_dir)
    shards = status.get("shards") or []
    present = {shard.get("name") for shard in shards}
    missing = [name for name in shard_names if name not in present]
    if missing:
        return True, f"missing shards: {', '.join(missing)}"
    # Only the shards this scan reads decide; an old shard it does not need
    # would otherwise force a refresh of the needed ones on every run.
    for shard in shards:
        if shard.get("name") not in shard_names:
            continue
        age_days = shard.get("age_days")
        if age_days is None or age_days * 24 >= VDB_AGE_HOURS:
            return True, "stale"
    return False, None


def refresh_shards_with_retries(shard_names, store_dir=None, attempts=VDB_DOWNLOAD_MAX_ATTEMPTS):
    """Refresh the named shards through vdb, retrying transient network errors.

    Each shard lands with an atomic directory rename, so an interruption
    leaves every shard either refreshed or at its previous complete artifact;
    depscan never unpacks into the store itself.
    """
    from vdb.lib import db_cmd

    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            return db_cmd.refresh_shards(shard_names, store_dir=store_dir)
        except Exception as e:  # noqa: BLE001 - transient failures vary by layer
            last_exc = e
            if attempt < attempts:
                LOG.warning(
                    "Shard refresh failed (attempt %d/%d): %s. Retrying ...",
                    attempt,
                    attempts,
                    e,
                )
                time.sleep(VDB_DOWNLOAD_RETRY_BACKOFF_SEC * attempt)
            else:
                LOG.error("Shard refresh failed after %d attempt(s).", attempts)
    if last_exc is not None:
        raise last_exc


def connect_shard_as_main(shard_dir, store_dir):
    """Connect one shard as the main database so searches fan out.

    vdb consults the shard store only when the main database is itself a
    shard; this points the main-database paths (and the environment, for
    subprocesses) at *shard_dir* and the store at *store_dir*, then reopens
    the connections. The caller must refresh the shards first so the store
    beside the main shard is complete.
    """
    from vdb.lib import shard_store

    os.environ["VDB_HOME"] = shard_dir
    os.environ["VDB_SHARDS_DIR"] = store_dir
    config.DATA_DIR = shard_dir
    config.VDB_BIN_FILE = os.path.join(shard_dir, "data.vdb7")
    config.VDB_BIN_INDEX = os.path.join(shard_dir, "data.index.vdb7")
    config.VDB_SHARDS_DIR = store_dir
    db_lib.reset_connections()
    shard_store.reset()


def setup_shards_for_scan(purl_types):
    """Opt-in shard mode: refresh and connect the shards serving *purl_types*.

    Returns the connected shard names, or an empty list when the store cannot
    serve the scan (no types, or a refresh that placed nothing).
    """
    from vdb.lib.shard_store import canonical_shard_for_type

    shard_names = []
    for purl_type in purl_types:
        name = canonical_shard_for_type(purl_type)
        if name not in shard_names:
            shard_names.append(name)
    if not shard_names:
        return []
    store_dir = config.VDB_SHARDS_DIR
    marker_data_dir = config.DATA_DIR
    needed, reason = shards_refresh_needed(shard_names, store_dir=store_dir)
    if needed:
        LOG.info(
            "Refreshing vdb shard(s) %s into %s (%s). Please wait ...",
            ", ".join(shard_names),
            store_dir,
            reason,
        )
        placed = refresh_shards_with_retries(shard_names, store_dir=store_dir)
        if not placed:
            message = f"No shard could be refreshed into {store_dir}."
            LOG.error(message)
            raise VdbUnusableError(message)
        write_vdb_image_marker(vdb_shards_marker(shard_names), marker_data_dir)
    connect_shard_as_main(os.path.join(store_dir, shard_names[0]), store_dir)
    report_shard_coverage(purl_types, store_dir=store_dir)
    return shard_names


__all__ = [
    "collect_purl_types",
    "configure_vdb_readonly",
    "connect_shard_as_main",
    "download_vdb_with_retries",
    "VdbUnusableError",
    "ensure_vdb_usable",
    "refresh_shards_with_retries",
    "report_shard_coverage",
    "resolve_scan_vdb_image",
    "setup_shards_for_scan",
    "shards_refresh_needed",
    "vdb_download_needed",
]
