"""Application registry that discovers ThreatForest runs from the centralized
``.threatforest/runs/`` directory.

Layout::

    <repo_root>/.threatforest/runs/
        <project_name>/
            metadata.json          # { path, description, name, created_at }
            <YYYYMMDD_HHMMSS>/     # one per scan run
                state/             # intermediate agent state files
                output/            # final artifacts (threatforest_data.json, report)
        <parent--project_name>/    # disambiguated when names collide
            ...
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from server.models import ApplicationSummary, VersionSummary

PAUSE_STATE_KEY = "pause_state.json"


def _workspace(run_dir: Path) -> "LocalFilesystemWorkspace":
    # Local import to avoid a circular via `threatforest.__init__ -> cli -> registry`.
    from threatforest.workspace import LocalFilesystemWorkspace

    return LocalFilesystemWorkspace(run_dir)


def slugify(name: str) -> str:
    """Convert a project directory name into a URL-safe slug."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower())
    return slug.strip("-")


def get_runs_root() -> Path:
    """Return the centralized runs directory at the repo root."""
    # repo root is three levels up from this file: src/server/registry.py
    repo_root = Path(__file__).resolve().parent.parent.parent
    return repo_root / ".threatforest" / "runs"


def resolve_project_folder(project_path: str | Path) -> tuple[str, Path]:
    """Determine the folder name under ``.threatforest/runs/`` for a project.

    Returns ``(folder_name, runs_root)`` where *folder_name* is the directory
    name to use inside ``.threatforest/runs/``.

    If a project with the same base name already exists but points to a
    different path, the parent directory is prepended as
    ``<parent>--<project>`` to disambiguate.

    Raises
    ------
    ValueError
        If the disambiguated name also collides (extremely unlikely).
    """
    project = Path(project_path).expanduser().resolve()
    base_name = project.name
    runs_root = get_runs_root()
    runs_root.mkdir(parents=True, exist_ok=True)

    candidate = runs_root / base_name
    if candidate.is_dir():
        meta_file = candidate / "metadata.json"
        if meta_file.is_file():
            existing = json.loads(meta_file.read_text(encoding="utf-8"))
            existing_path = Path(existing.get("path", "")).resolve()
            if existing_path != project:
                # Disambiguate: prepend parent folder name
                parent_name = project.parent.name
                disambiguated = f"{parent_name}--{base_name}"
                candidate2 = runs_root / disambiguated
                if candidate2.is_dir():
                    meta2 = candidate2 / "metadata.json"
                    if meta2.is_file():
                        existing2 = json.loads(meta2.read_text(encoding="utf-8"))
                        if Path(existing2.get("path", "")).resolve() != project:
                            raise ValueError(
                                f"A project named '{base_name}' already exists "
                                f"at '{existing_path}'. Cannot register "
                                f"'{project}' — disambiguated name "
                                f"'{disambiguated}' is also taken."
                            )
                    return disambiguated, runs_root
                return disambiguated, runs_root
    return base_name, runs_root


def create_run_directory(
    project_path: str | Path,
    folder_name: str | None = None,
    display_name: str | None = None,
) -> tuple[Path, Path]:
    """Create a timestamped run directory for a project scan.

    Returns ``(run_dir, project_dir)`` where:
    - *run_dir* is ``<runs_root>/<project_folder>/<YYYYMMDD_HHMMSS>/``
    - *project_dir* is ``<runs_root>/<project_folder>/``

    Also creates/updates ``metadata.json`` in the project directory.

    ``folder_name`` lets the caller pin the project folder to a specific
    name (used by v2 Application-scoped runs so every run for a given app
    lands in the same folder regardless of the project path basename).
    When omitted, the folder name is derived from the project path basename
    via ``resolve_project_folder``.

    ``display_name`` overrides the human-readable ``name`` written into
    ``metadata.json``. v2 callers pass ``Application.name`` so the folder
    doesn't end up labelled with the project path basename (which can be a
    cryptic directory name that leaks into breadcrumbs).
    """
    project = Path(project_path).expanduser().resolve()
    if folder_name is None:
        folder_name, runs_root = resolve_project_folder(project)
    else:
        runs_root = get_runs_root()
        runs_root.mkdir(parents=True, exist_ok=True)
    project_dir = runs_root / folder_name
    project_dir.mkdir(parents=True, exist_ok=True)

    # Create timestamped run directory
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = project_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    # Create state and output subdirectories
    (run_dir / "state").mkdir(exist_ok=True)
    (run_dir / "output").mkdir(exist_ok=True)

    # Create or update metadata.json
    meta_file = project_dir / "metadata.json"
    if meta_file.is_file():
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        meta["path"] = str(project)
        # Refresh the display name if the caller provided an authoritative one
        # — pre-existing metadata may hold a stale project-basename fallback.
        if display_name:
            meta["name"] = display_name
    else:
        meta = {
            "name": display_name or project.name,
            "path": str(project),
            "description": "",
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
        }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return run_dir, project_dir


class ApplicationRegistry:
    """Discovers applications from the centralized ``.threatforest/runs/`` directory.

    Each subdirectory of ``runs/`` is a project.  Inside each project
    directory there is a ``metadata.json`` and zero or more timestamped
    run directories (``YYYYMMDD_HHMMSS``), each containing
    ``output/threatforest_data.json``.
    """

    METADATA_FILE = "threatforest_data.json"

    def __init__(self) -> None:
        self.runs_root = get_runs_root()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_applications(self) -> list[ApplicationSummary]:
        """Scan ``.threatforest/runs/`` and return discovered applications."""
        if not self.runs_root.is_dir():
            return []

        apps: list[ApplicationSummary] = []
        for project_dir in sorted(self.runs_root.iterdir()):
            if not project_dir.is_dir():
                continue
            meta_file = project_dir / "metadata.json"
            if not meta_file.is_file():
                continue

            summary = self._build_application_summary(project_dir)
            if summary is not None:
                apps.append(summary)

        return apps

    def get_versions(
        self,
        app_id: str,
        active_run_ids: dict[str, str] | None = None,
    ) -> list[VersionSummary]:
        """Return version summaries for *app_id*, sorted by run date descending.

        Each version is labelled ``"Version N"`` where ``N`` counts from 1
        for the oldest run — so the newest run carries the largest number.

        ``active_run_ids`` maps version folder names (``YYYYMMDD_HHMMSS``) to
        the in-flight ``run_id`` tracked by ``RunManager``. When provided, any
        version whose folder is still the target of a live run is tagged with
        that ``run_id`` and keeps an ``in-progress`` status — so the UI can
        route the user to the progress page instead of a not-yet-written
        dashboard.
        """
        project_dir = self._find_project_dir(app_id)
        if project_dir is None:
            return []

        versions: list[VersionSummary] = []
        for child in sorted(project_dir.iterdir(), reverse=True):
            if not child.is_dir() or child.name == "__pycache__":
                continue
            # Skip non-timestamp directories
            if not re.match(r"^\d{8}_\d{6}$", child.name):
                continue
            active_run_id = (active_run_ids or {}).get(child.name)
            version = self._build_version_summary(child, active_run_id=active_run_id)
            if version is not None:
                versions.append(version)

        # Assign user-friendly labels. `versions` is sorted newest-first, so
        # the first element gets the largest number (total count).
        total = len(versions)
        for idx, v in enumerate(versions):
            v.display_name = f"Version {total - idx}"

        return versions

    def get_project_dir(self, app_id: str) -> Path | None:
        """Return the project directory for an app_id, or None."""
        return self._find_project_dir(app_id)

    def delete_version(self, app_id: str, version_id: str) -> bool:
        """Remove a single timestamped run directory for an application.

        Returns ``True`` if the folder was deleted, ``False`` if the project
        directory or version folder could not be found. The ``version_id``
        must be the on-disk ``YYYYMMDD_HHMMSS`` folder name — ``"latest"`` is
        not accepted here because deletion of "whichever version is newest
        right now" is ambiguous and error-prone.

        Raises
        ------
        OSError
            If the folder exists but ``shutil.rmtree`` fails. The caller is
            responsible for surfacing this to the user.
        """
        import shutil

        project_dir = self._find_project_dir(app_id)
        if project_dir is None:
            return False
        if not re.match(r"^\d{8}_\d{6}$", version_id):
            return False
        version_dir = project_dir / version_id
        if not version_dir.is_dir():
            return False
        shutil.rmtree(str(version_dir))
        return True

    def get_version_data_path(self, app_id: str, version_id: str) -> Path | None:
        """Return the path to threatforest_data.json for a specific version.

        If *version_id* is ``"latest"``, resolves to the most recent
        timestamped run directory.
        """
        project_dir = self._find_project_dir(app_id)
        if project_dir is None:
            return None

        if version_id == "latest":
            version_id = self._resolve_latest_version(project_dir)
            if version_id is None:
                return None

        data_file = project_dir / version_id / "output" / self.METADATA_FILE
        if data_file.is_file():
            return data_file
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_project_dir(self, app_id: str) -> Path | None:
        """Locate the project directory for a given app_id."""
        if not self.runs_root.is_dir():
            return None
        for project_dir in self.runs_root.iterdir():
            if not project_dir.is_dir():
                continue
            if slugify(project_dir.name) == app_id:
                return project_dir
        return None

    @staticmethod
    def _resolve_latest_version(project_dir: Path) -> str | None:
        """Return the most recent YYYYMMDD_HHMMSS directory name, or None."""
        candidates = [
            d for d in project_dir.iterdir()
            if d.is_dir() and re.match(r"^\d{8}_\d{6}$", d.name)
        ]
        if not candidates:
            return None
        return sorted(candidates, key=lambda d: d.name, reverse=True)[0].name

    def _build_application_summary(self, project_dir: Path) -> ApplicationSummary | None:
        """Build an ApplicationSummary from a project directory."""
        meta_file = project_dir / "metadata.json"
        meta = self._read_json(meta_file)
        if meta is None:
            return None

        app_id = slugify(project_dir.name)

        # Count version (timestamp) directories
        version_dirs = [
            d for d in project_dir.iterdir()
            if d.is_dir() and re.match(r"^\d{8}_\d{6}$", d.name)
        ]
        version_count = len(version_dirs)

        # Determine last run date from the most recent timestamp dir
        if version_dirs:
            latest = sorted(version_dirs, key=lambda d: d.name, reverse=True)[0]
            last_run_date = self._extract_run_date(latest)
        else:
            last_run_date = meta.get("created_at", "")

        # Display name: convert "parent--project" back to "Parent/Project"
        raw_name = project_dir.name
        if "--" in raw_name:
            parts = raw_name.split("--", 1)
            display_name = f"{parts[0].title()}/{parts[1]}"
        else:
            display_name = meta.get("name", raw_name)

        # Description: prefer metadata.json, fall back to latest run's data
        description = meta.get("description", "")
        if not description and version_dirs:
            latest = sorted(version_dirs, key=lambda d: d.name, reverse=True)[0]
            run_data = self._read_json(latest / "output" / self.METADATA_FILE)
            if run_data:
                description = (
                    run_data.get("description")
                    or (run_data.get("project_info") or {}).get("short_summary")
                    or (run_data.get("project_info") or {}).get("summary", "")
                )
                # Persist back to metadata.json for future reads
                if description:
                    meta["description"] = description
                    meta_file.write_text(
                        json.dumps(meta, indent=2), encoding="utf-8"
                    )

        return ApplicationSummary(
            id=app_id,
            name=display_name,
            description=description,
            version_count=version_count,
            last_run_date=last_run_date,
        )

    def _build_version_summary(
        self,
        version_dir: Path,
        active_run_id: str | None = None,
    ) -> VersionSummary | None:
        """Build a VersionSummary from a timestamped run directory.

        The presence of ``output/threatforest_data.json`` is the completion
        marker — if it's missing we treat the version as still in progress
        rather than silently reporting "complete". When ``active_run_id`` is
        provided the version is forced to ``in-progress`` and tagged with the
        live run id regardless of any stale metadata on disk.
        """
        run_date = self._extract_run_date(version_dir)

        data_file = version_dir / "output" / self.METADATA_FILE
        has_output = data_file.is_file()
        metadata: dict = {}
        if has_output:
            metadata = self._read_json(data_file) or {}

        threat_count = metadata.get("threat_count", 0)
        high_severity_count = metadata.get("high_severity_count", 0)
        extraction = metadata.get("extraction_summary", {})
        if extraction:
            threat_count = threat_count or extraction.get("total_threats", 0)
            high_severity_count = high_severity_count or extraction.get(
                "high_severity_count", 0
            )
        categories = metadata.get("categories", [])

        # Status resolution:
        #   - output artefact present → trust its ``status`` field (or default
        #     to "complete" for legacy runs that didn't record one).
        #   - no artefact but a live run is tracking this folder → in-progress.
        #   - no artefact and no live run → the run crashed or was abandoned
        #     by a previous server session; mark "abandoned" so the UI can
        #     avoid routing users to a dashboard that will never render.
        if has_output:
            status = metadata.get("status", "complete")
        elif active_run_id is not None:
            status = "in-progress"
        else:
            status = "abandoned"

        return VersionSummary(
            id=version_dir.name,
            run_date=run_date,
            status=status,
            threat_count=threat_count,
            high_severity_count=high_severity_count,
            categories=categories,
            run_id=active_run_id,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_run_date(version_dir: Path) -> str:
        """Derive an ISO-format run date from a YYYYMMDD_HHMMSS directory name."""
        name = version_dir.name
        try:
            return datetime.strptime(name, "%Y%m%d_%H%M%S").replace(
                tzinfo=timezone.utc
            ).isoformat()
        except ValueError:
            pass
        # Fallback: filesystem mtime
        mtime = version_dir.stat().st_mtime
        return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

    def discover_paused_runs(self) -> list[dict]:
        """Return applications whose most recent run has a pause_state.json with intent 'pause'.

        Each entry contains the application summary fields plus pause metadata
        so the UI can offer a resume action.
        """
        if not self.runs_root.is_dir():
            return []

        paused: list[dict] = []
        for project_dir in sorted(self.runs_root.iterdir()):
            if not project_dir.is_dir():
                continue
            meta_file = project_dir / "metadata.json"
            if not meta_file.is_file():
                continue

            # Find the latest timestamped run directory
            latest = self._resolve_latest_version(project_dir)
            if latest is None:
                continue

            workspace = _workspace(project_dir / latest)
            if not workspace.exists(PAUSE_STATE_KEY):
                continue

            try:
                pause_data = workspace.read_json(PAUSE_STATE_KEY)
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(pause_data, dict) or pause_data.get("intent") != "pause":
                continue

            meta = self._read_json(meta_file) or {}
            app_id = slugify(project_dir.name)
            raw_name = project_dir.name
            if "--" in raw_name:
                parts = raw_name.split("--", 1)
                display_name = f"{parts[0].title()}/{parts[1]}"
            else:
                display_name = meta.get("name", raw_name)

            paused.append({
                "id": app_id,
                "name": display_name,
                "project_path": meta.get("path", ""),
                "paused_at": pause_data.get("paused_at", ""),
                "completed_nodes": pause_data.get("completed_nodes", []),
                "run_dir": str(project_dir / latest),
                "config": pause_data.get("config", {}),
            })

        return paused

    def delete_pause_state(self, app_id: str) -> bool:
        """Remove pause_state.json from the latest run of an application.

        Returns True if a file was deleted, False if nothing was found.
        """
        project_dir = self._find_project_dir(app_id)
        if project_dir is None:
            return False

        latest = self._resolve_latest_version(project_dir)
        if latest is None:
            return False

        return _workspace(project_dir / latest).delete(PAUSE_STATE_KEY)

    @staticmethod
    def _read_json(path: Path) -> dict | None:
        """Read and parse a JSON file, returning None on failure."""
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
