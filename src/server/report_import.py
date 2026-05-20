"""Process ``.tfreport`` bundles dropped into ``.threatforest/imports/``.

Called from ``ApplicationRegistry.discover_applications`` so importing is
fully passive: the user copies a file in, opens the Applications page,
the new app appears.

Layout under the imports directory::

    imports/
      <bundle>.tfreport               ← pending; processed on next discover
      processed/<bundle>.tfreport     ← moved here on success
      failed/<bundle>.tfreport        ← moved here on failure
      failed/<bundle>.error.txt       ← reason
      README.md                       ← seeded at startup, never processed

Imported folders carry these markers in ``metadata.json``::

    {
      "name": "<source app name>",
      "description": "...",
      "imported_from_app_id": "<source manifest source_app_id>",
      "imported_from_app_name": "<source manifest source_app_name>",
      "imported_at": "<iso>"
    }

The absence of a ``path`` field is the read-only signal — the rest of the
server never tries to re-scan an imported app because it has no source
directory to point at.
"""

from __future__ import annotations

import json
import logging
import shutil
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from server.report_bundle import MANIFEST_FILENAME, SCHEMA_VERSION

if TYPE_CHECKING:
    from server.registry import ApplicationRegistry


logger = logging.getLogger(__name__)


@dataclass
class ImportResult:
    """Outcome for a single ``.tfreport`` bundle."""

    bundle: str
    status: str  # "imported" | "merged" | "skipped" | "failed"
    folder_name: str | None = None
    versions_added: list[str] = field(default_factory=list)
    versions_skipped: list[str] = field(default_factory=list)
    error: str | None = None


def process_pending_imports(
    imports_dir: Path,
    registry: "ApplicationRegistry",
) -> list[ImportResult]:
    """Process every ``*.tfreport`` in *imports_dir*.

    Each bundle is opened, validated, and extracted. Successful bundles are
    moved to ``imports/processed/``; failed ones to ``imports/failed/`` with
    a sibling ``.error.txt`` describing the failure.

    The function never raises — every error is captured into the returned
    ``ImportResult`` list. The discovery path that calls this must keep
    listing applications even when imports fail.
    """
    if not imports_dir.is_dir():
        return []

    processed_dir = imports_dir / "processed"
    failed_dir = imports_dir / "failed"

    results: list[ImportResult] = []
    for bundle in sorted(imports_dir.iterdir()):
        if bundle.is_dir() or bundle.suffix != ".tfreport":
            continue
        try:
            result = _import_bundle(bundle, registry)
        except Exception as exc:  # noqa: BLE001 — captured into result
            logger.exception("Unhandled error importing bundle: %s", bundle.name)
            result = ImportResult(
                bundle=bundle.name,
                status="failed",
                error=f"Unhandled error: {exc}",
            )

        if result.status == "failed":
            failed_dir.mkdir(parents=True, exist_ok=True)
            try:
                shutil.move(str(bundle), str(failed_dir / bundle.name))
                (failed_dir / f"{bundle.name}.error.txt").write_text(
                    result.error or "Unknown error",
                    encoding="utf-8",
                )
            except OSError:
                logger.exception("Could not move failed bundle %s", bundle.name)
        else:
            processed_dir.mkdir(parents=True, exist_ok=True)
            try:
                shutil.move(str(bundle), str(processed_dir / bundle.name))
            except OSError:
                logger.exception(
                    "Imported %s but could not move to processed/", bundle.name
                )

        results.append(result)

    return results


def _import_bundle(
    bundle: Path,
    registry: "ApplicationRegistry",
) -> ImportResult:
    """Validate and extract a single bundle. Pure function — no fs side effects on failure."""
    try:
        with zipfile.ZipFile(bundle, mode="r") as zf:
            manifest = _read_manifest(zf)
            _validate_zip_paths(zf)

            slug, folder_name, mode = _resolve_target_folder(manifest, registry)
            if folder_name is None:
                return ImportResult(
                    bundle=bundle.name,
                    status="failed",
                    error=(
                        "Cannot disambiguate target folder — every "
                        "candidate name is taken. Rename the source "
                        "application and re-export."
                    ),
                )

            target_dir = registry.runs_root / folder_name
            versions_added, versions_skipped = _extract_versions(
                zf, manifest, target_dir
            )
            bundle_app_meta = _read_bundle_application_metadata(zf)
            _extract_business_context(zf, target_dir)
            _write_imported_metadata(
                target_dir,
                manifest,
                bundle_app_meta=bundle_app_meta,
                mode=mode,
            )
    except zipfile.BadZipFile:
        return ImportResult(
            bundle=bundle.name,
            status="failed",
            error="File is not a valid zip archive.",
        )
    except _ManifestError as exc:
        return ImportResult(bundle=bundle.name, status="failed", error=str(exc))
    except _ZipSlipError as exc:
        return ImportResult(bundle=bundle.name, status="failed", error=str(exc))

    if not versions_added and versions_skipped:
        return ImportResult(
            bundle=bundle.name,
            status="skipped",
            folder_name=folder_name,
            versions_skipped=versions_skipped,
        )
    return ImportResult(
        bundle=bundle.name,
        status="merged" if mode == "merge" else "imported",
        folder_name=folder_name,
        versions_added=versions_added,
        versions_skipped=versions_skipped,
    )


# ─── manifest + zip safety ────────────────────────────────────────


class _ManifestError(Exception):
    pass


class _ZipSlipError(Exception):
    pass


def _read_manifest(zf: zipfile.ZipFile) -> dict:
    try:
        raw = zf.read(MANIFEST_FILENAME).decode("utf-8")
    except KeyError:
        raise _ManifestError(
            f"Bundle is missing {MANIFEST_FILENAME} — not a ThreatForest report."
        )
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _ManifestError(f"Manifest is not valid JSON: {exc}")
    if not isinstance(manifest, dict):
        raise _ManifestError("Manifest must be a JSON object.")

    schema = manifest.get("schema_version")
    if schema != SCHEMA_VERSION:
        raise _ManifestError(
            f"Unsupported schema_version {schema!r}; this server expects "
            f"{SCHEMA_VERSION}."
        )
    if not manifest.get("source_app_slug"):
        raise _ManifestError("Manifest is missing source_app_slug.")
    if not isinstance(manifest.get("versions"), list) or not manifest["versions"]:
        raise _ManifestError("Manifest has no versions to import.")
    return manifest


def _validate_zip_paths(zf: zipfile.ZipFile) -> None:
    """Reject any zip entry that escapes the implicit extraction root.

    We don't actually use ``zf.extract`` (we read entries explicitly) so
    zip-slip via absolute paths or ``..`` is harder to hit, but a defence-
    in-depth check costs nothing and protects against future refactors that
    switch to ``extractall``.
    """
    for name in zf.namelist():
        if name.startswith("/") or name.startswith("\\"):
            raise _ZipSlipError(f"Bundle contains absolute path: {name!r}")
        # PurePosix-style walk — the entries are written with forward slashes
        parts = name.replace("\\", "/").split("/")
        if any(p == ".." for p in parts):
            raise _ZipSlipError(f"Bundle contains parent-directory escape: {name!r}")


# ─── target folder resolution + collision rules ───────────────────


def _resolve_target_folder(
    manifest: dict,
    registry: "ApplicationRegistry",
) -> tuple[str, str | None, str]:
    """Decide which folder under ``runs/`` to extract into.

    Returns ``(slug, folder_name, mode)`` where ``mode`` is one of:

    - ``"merge"``  — folder exists and was imported from the same source app;
                     new versions are added to it.
    - ``"new"``    — folder doesn't exist or needs a ``--imported`` suffix.

    Returns ``folder_name=None`` if every candidate is taken (extremely
    unlikely — would require the user to have ``--imported``,
    ``--imported-2``, … all the way up to 99 already in place).
    """
    runs_root = registry.runs_root
    runs_root.mkdir(parents=True, exist_ok=True)

    source_slug = manifest["source_app_slug"]
    source_app_id = manifest.get("source_app_id")
    scope = manifest.get("scope", "single-version")

    # 1. Same-source-app merge: existing imported folder whose
    #    metadata.imported_from_app_id matches.
    if source_app_id and scope == "single-version":
        for child in runs_root.iterdir():
            if not child.is_dir():
                continue
            meta = _read_metadata(child)
            if meta.get("imported_from_app_id") == source_app_id:
                return source_slug, child.name, "merge"

    # 2. Slug is free → use it.
    if not (runs_root / source_slug).exists():
        return source_slug, source_slug, "new"

    # 3. Suffix with ``--imported``, then ``--imported-2`` etc. The base slug
    #    is always taken at this point (case 2 already returned), so we start
    #    suffixing immediately. Cap at 99 to avoid runaway loops on
    #    pathological filesystems.
    base = f"{source_slug}--imported"
    if not (runs_root / base).exists():
        return source_slug, base, "new"
    for n in range(2, 100):
        candidate = f"{base}-{n}"
        if not (runs_root / candidate).exists():
            return source_slug, candidate, "new"

    return source_slug, None, "new"


def _read_metadata(folder: Path) -> dict:
    meta_file = folder / "metadata.json"
    if not meta_file.is_file():
        return {}
    try:
        data = json.loads(meta_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


# ─── extraction ───────────────────────────────────────────────────


def _extract_versions(
    zf: zipfile.ZipFile,
    manifest: dict,
    target_dir: Path,
) -> tuple[list[str], list[str]]:
    """Copy every ``versions/<ts>/...`` entry to *target_dir*.

    Versions whose folder already exists in *target_dir* are skipped
    silently — re-imports must never overwrite local edits (e.g. mitigation
    overrides the recipient added after a previous import).
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    declared_versions = list(manifest.get("versions") or [])
    added: list[str] = []
    skipped: list[str] = []

    for version_id in declared_versions:
        version_dir = target_dir / version_id
        if version_dir.exists():
            skipped.append(version_id)
            continue
        prefix = f"versions/{version_id}/"
        # ZIP namelist is flat — pick the entries for this version and
        # re-create the on-disk hierarchy under the version folder.
        entries = [
            name
            for name in zf.namelist()
            if name.startswith(prefix) and not name.endswith("/")
        ]
        if not entries:
            # Manifest claimed a version we don't have data for. Skip
            # rather than failing the whole bundle — the rest may still be
            # useful.
            skipped.append(version_id)
            continue
        version_dir.mkdir(parents=True, exist_ok=True)
        for entry in entries:
            relative = entry[len(prefix):]  # strip "versions/<ts>/"
            dest = version_dir / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(entry) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        added.append(version_id)

    return added, skipped


def _read_bundle_application_metadata(zf: zipfile.ZipFile) -> dict:
    """Read ``application/metadata.json`` out of the bundle, or return ``{}``."""
    try:
        raw = zf.read("application/metadata.json").decode("utf-8")
    except KeyError:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _extract_business_context(zf: zipfile.ZipFile, target_dir: Path) -> None:
    """Persist ``application/business_context.json`` next to ``metadata.json``.

    Imported applications don't have a v2 ``Application`` record (no entry
    in ``applications.json``), so the apps-list endpoint can't fetch the
    business context the usual way. Saving it as a sidecar file under the
    project folder lets the registry surface it on discover.

    Bundles built from a v1 folder-only app won't include this file —
    that's fine, the recipient just sees no business-context section.
    """
    try:
        raw = zf.read("application/business_context.json").decode("utf-8")
    except KeyError:
        return
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "business_context.json").write_text(
        json.dumps(data, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _write_imported_metadata(
    target_dir: Path,
    manifest: dict,
    *,
    bundle_app_meta: dict,
    mode: str,
) -> None:
    """Write/update ``metadata.json`` to mark the folder as imported.

    On merge we keep the existing ``imported_at`` (it represents the first
    time we saw this app) but bump ``last_imported_at`` so the user can see
    when versions were last appended. On a fresh import we write both.

    The ``path`` field is deliberately omitted — its absence is the
    read-only signal the rest of the server uses to disable re-runs.
    """
    meta_file = target_dir / "metadata.json"
    now = datetime.now(tz=timezone.utc).isoformat()

    existing = _read_metadata(target_dir) if mode == "merge" else {}

    meta = {
        **existing,
        "name": manifest.get("source_app_name", existing.get("name", "Imported app")),
        "description": (
            existing.get("description")
            or bundle_app_meta.get("description", "")
        ),
        "imported_from_app_id": manifest.get("source_app_id", ""),
        "imported_from_app_name": manifest.get(
            "source_app_name", existing.get("imported_from_app_name", "")
        ),
        "imported_at": existing.get("imported_at", now),
        "last_imported_at": now,
        "created_at": existing.get("created_at") or now,
    }
    meta_file.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")


def ensure_imports_dir(imports_dir: Path) -> None:
    """Create *imports_dir* and seed a README on first run."""
    imports_dir.mkdir(parents=True, exist_ok=True)
    readme = imports_dir / "README.md"
    if not readme.is_file():
        readme.write_text(_README_BODY, encoding="utf-8")


_README_BODY = """# ThreatForest report imports

Drop ``*.tfreport`` files in this directory to import threat models from
another ThreatForest install. They will appear on the Applications page
the next time it is loaded.

Subdirectories are managed by ThreatForest — do not place bundles inside
them:

- ``processed/`` — bundles successfully imported.
- ``failed/`` — bundles that could not be imported, with a sibling
  ``.error.txt`` explaining the reason.

Imported applications are read-only — the recipient does not have the
source code, so re-running is disabled. Their version history is editable
(mitigation status overrides) just like locally-scanned apps.
"""
