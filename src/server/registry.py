"""Application registry that discovers ThreatForest output directories."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from server.models import ApplicationSummary, VersionSummary


def slugify(name: str) -> str:
    """Convert a project directory name into a URL-safe slug.

    Lowercases, replaces non-alphanumeric runs with hyphens, and strips
    leading/trailing hyphens.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower())
    return slug.strip("-")


class ApplicationRegistry:
    """Discovers and indexes ThreatForest output across configured scan paths.

    Each scan path is expected to contain project directories.  A project is
    recognised when it contains the marker file:

        ``{project_dir}/.threatforest/output/threatforest_data.json``

    The ``.threatforest/output/`` directory may exist at the top level of
    the project directory, or within a subdirectory (e.g., when a user
    points to a parent repo that contains the actual application in a
    child folder).  The registry searches recursively for the first
    ``.threatforest/output/`` containing ``threatforest_data.json``.

    Version directories are the *subdirectories* inside the output
    directory (excluding the JSON file itself).  Each version directory
    represents a single ThreatForest run.
    """

    ATTACK_TREES_REL = Path(".threatforest") / "output"
    METADATA_FILE = "threatforest_data.json"

    def __init__(self, scan_paths: list[Path]) -> None:
        self.scan_paths = scan_paths

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # Maximum depth to search for .threatforest inside a project directory.
    # Covers cases like project_dir/sub_app/.threatforest/output/
    _MAX_SEARCH_DEPTH = 3

    def _find_metadata(self, project_dir: Path) -> Path | None:
        """Find metadata file, searching subdirectories if not at top level.

        Checks project_dir/.threatforest/output/ first, then searches
        up to ``_MAX_SEARCH_DEPTH`` levels deep for any
        ``.threatforest/output/`` directory containing the metadata file.
        """
        # 1. Check top-level first (fast path)
        top = project_dir / self.ATTACK_TREES_REL / self.METADATA_FILE
        if top.is_file():
            return top

        # 2. Depth-limited search for .threatforest/output/ in subdirectories
        result = self._find_threatforest_file(project_dir, self.METADATA_FILE)
        return result

    def _find_output_dir(self, project_dir: Path) -> Path | None:
        """Find the output directory containing metadata.

        Checks project_dir/.threatforest/output/ first, then searches
        up to ``_MAX_SEARCH_DEPTH`` levels deep for any
        ``.threatforest/output/`` directory containing the metadata file.
        """
        # 1. Check top-level first (fast path)
        d = project_dir / self.ATTACK_TREES_REL
        if (d / self.METADATA_FILE).is_file():
            return d

        # 2. Depth-limited search for .threatforest/output/ in subdirectories
        metadata_path = self._find_threatforest_file(project_dir, self.METADATA_FILE)
        if metadata_path is not None:
            return metadata_path.parent

        return None

    def _find_threatforest_file(self, root: Path, filename: str, _depth: int = 0) -> Path | None:
        """Depth-limited search for .threatforest/output/{filename}.

        Searches up to ``_MAX_SEARCH_DEPTH`` directory levels below *root*
        to avoid expensive recursive scans on large directory trees (e.g.,
        the user's home directory).
        """
        if _depth >= self._MAX_SEARCH_DEPTH:
            return None

        try:
            children = sorted(root.iterdir())
        except (PermissionError, OSError):
            return None

        for child in children:
            if not child.is_dir():
                continue
            if child.name == ".threatforest":
                candidate = child / "output" / filename
                if candidate.is_file():
                    return candidate
            else:
                # Recurse into non-hidden subdirectories only
                if not child.name.startswith("."):
                    result = self._find_threatforest_file(child, filename, _depth + 1)
                    if result is not None:
                        return result

        return None

    def discover_applications(self) -> list[ApplicationSummary]:
        """Scan all configured paths and return discovered applications."""
        apps: dict[str, ApplicationSummary] = {}

        for scan_path in self.scan_paths:
            if not scan_path.is_dir():
                continue

            for project_dir in sorted(scan_path.iterdir()):
                if not project_dir.is_dir():
                    continue

                metadata_path = self._find_metadata(project_dir)
                if metadata_path is None:
                    continue

                app_id = slugify(project_dir.name)
                if app_id in apps:
                    continue

                summary = self._build_application_summary(
                    app_id, project_dir, metadata_path, scan_path
                )
                if summary is not None:
                    apps[app_id] = summary

        return list(apps.values())

    def get_versions(self, app_id: str) -> list[VersionSummary]:
        """Return version summaries for *app_id*, sorted by run date descending."""
        attack_trees_dir, scan_path = self._find_attack_trees_dir(app_id)
        if attack_trees_dir is None:
            return []

        versions: list[VersionSummary] = []
        for child in attack_trees_dir.iterdir():
            if not child.is_dir():
                continue
            version = self._build_version_summary(child, scan_path)
            if version is not None:
                versions.append(version)

        # If no version subdirs but metadata exists, treat as flat layout
        if not versions:
            metadata_path = attack_trees_dir / self.METADATA_FILE
            if metadata_path.is_file():
                metadata = self._read_metadata(metadata_path) or {}
                mtime = attack_trees_dir.stat().st_mtime
                run_date = datetime.fromtimestamp(
                    mtime, tz=timezone.utc
                ).isoformat()

                versions.append(
                    VersionSummary(
                        id="latest",
                        run_date=run_date,
                        status=metadata.get("status", "complete"),
                        threat_count=metadata.get("threat_count", 0) or (metadata.get("extraction_summary") or {}).get("total_threats", 0),
                        high_severity_count=metadata.get("high_severity_count", 0) or (metadata.get("extraction_summary") or {}).get("high_severity_count", 0),
                        categories=metadata.get("categories", []),
                    )
                )

        # Sort by run_date descending
        versions.sort(key=lambda v: v.run_date, reverse=True)
        return versions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_attack_trees_dir(self, app_id: str) -> tuple[Path, Path | None] | tuple[None, None]:
        """Locate the output directory for a given application id."""
        for scan_path in self.scan_paths:
            if not scan_path.is_dir():
                continue
            for project_dir in scan_path.iterdir():
                if not project_dir.is_dir():
                    continue
                if slugify(project_dir.name) == app_id:
                    output_dir = self._find_output_dir(project_dir)
                    if output_dir is not None:
                        return output_dir, scan_path
        return None, None

    def _build_application_summary(
        self,
        app_id: str,
        project_dir: Path,
        metadata_path: Path,
        scan_path: Path | None = None,
    ) -> ApplicationSummary | None:
        """Parse metadata and build an ApplicationSummary."""
        metadata = self._read_metadata(metadata_path)
        if metadata is None:
            return None

        attack_trees_dir = metadata_path.parent
        version_dirs = [
            d for d in attack_trees_dir.iterdir() if d.is_dir()
        ]

        if version_dirs:
            # Versioned layout
            last_run_date = self._latest_run_date(version_dirs)
            version_count = len(version_dirs)
        else:
            # Flat layout: no version subdirs but metadata exists
            version_count = 1
            mtime = attack_trees_dir.stat().st_mtime
            last_run_date = datetime.fromtimestamp(
                mtime, tz=timezone.utc
            ).isoformat()

        # Extract name and description — check multiple possible locations
        # in the threatforest_data.json structure
        name = (
            metadata.get("name")
            or (metadata.get("project_info") or {}).get("application_name")
            or project_dir.name
        )
        description = (
            metadata.get("description")
            or (metadata.get("project_info") or {}).get("short_summary")
            or (metadata.get("project_info") or {}).get("summary", "")
        )

        return ApplicationSummary(
            id=app_id,
            name=name,
            description=description,
            version_count=version_count,
            last_run_date=last_run_date,
        )

    def _build_version_summary(
        self, version_dir: Path, scan_path: Path | None = None
    ) -> VersionSummary | None:
        """Build a VersionSummary from a version directory."""
        run_date = self._extract_run_date(version_dir)

        # Look for a threatforest_data.json inside the version dir for
        # threat count and categories; fall back to the parent-level one.
        version_metadata_path = version_dir / self.METADATA_FILE
        parent_metadata_path = version_dir.parent / self.METADATA_FILE

        metadata: dict = {}
        if version_metadata_path.is_file():
            metadata = self._read_metadata(version_metadata_path) or {}
        elif parent_metadata_path.is_file():
            metadata = self._read_metadata(parent_metadata_path) or {}

        threat_count = metadata.get("threat_count", 0)
        high_severity_count = metadata.get("high_severity_count", 0)
        # Also check extraction_summary for these counts
        extraction = metadata.get("extraction_summary", {})
        if extraction:
            threat_count = threat_count or extraction.get("total_threats", 0)
            high_severity_count = high_severity_count or extraction.get("high_severity_count", 0)
        categories = metadata.get("categories", [])
        status = metadata.get("status", "complete")

        return VersionSummary(
            id=version_dir.name,
            run_date=run_date,
            status=status,
            threat_count=threat_count,
            high_severity_count=high_severity_count,
            categories=categories,
        )

    # ------------------------------------------------------------------
    # Metadata / date helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_metadata(path: Path) -> dict | None:
        """Read and parse a JSON metadata file, returning None on failure."""
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def _extract_run_date(version_dir: Path) -> str:
        """Derive an ISO-format run date from a version directory.

        Tries to parse the directory name as a date/timestamp first.  Falls
        back to the directory's filesystem modification time.
        """
        name = version_dir.name

        # Try common date formats in directory names
        for fmt in ("%Y-%m-%d", "%Y%m%d", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(name, fmt).replace(
                    tzinfo=timezone.utc
                ).isoformat()
            except ValueError:
                continue

        # Fallback: use the directory mtime
        mtime = version_dir.stat().st_mtime
        return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

    @classmethod
    def _latest_run_date(cls, version_dirs: list[Path]) -> str:
        """Return the most recent run date across version directories."""
        if not version_dirs:
            return ""

        dates: list[str] = []
        for d in version_dirs:
            dates.append(cls._extract_run_date(d))

        # ISO dates sort lexicographically
        dates.sort(reverse=True)
        return dates[0]
