"""Application repository layer backed by ``.threatforest/applications.json``.

Applications are first-class persistent entities in the v2 UX model. Each
record has a stable ID, a user-chosen name, a fixed on-disk run directory,
and a business-context block that the user fills in at creation and can
edit later. All fields of ``BusinessContext`` are required so every run has
authoritative user input to seed the scanner agent with.

Storage format: a single JSON object keyed by ``app_id`` sitting alongside
the existing ``runs/`` directory. Matches the filesystem-first convention
used by the rest of the server — no database.

Uniqueness rules:
- ``name`` — case-insensitive unique across all applications.
- ``project_path`` — one application per folder (409 on collision).

``app_id`` format is a short ULID-style token (time-ordered, URL safe)
independent of name and path so renaming never invalidates URLs.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from server.models import (
    Application,
    ApplicationCreateRequest,
    ApplicationUpdateRequest,
    BusinessContext,
)
from server.registry import get_runs_root, slugify


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ApplicationError(Exception):
    """Base class for application-repository errors."""


class ApplicationNotFoundError(ApplicationError):
    """Raised when an ``app_id`` does not resolve to a stored application."""


class ApplicationNameConflictError(ApplicationError):
    """Raised when a proposed name collides with an existing application."""


class ApplicationPathConflictError(ApplicationError):
    """Raised when a proposed ``project_path`` already belongs to another app."""


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

def _get_store_path() -> Path:
    """Location of the applications store, alongside ``runs/``."""
    return get_runs_root().parent / "applications.json"


def _generate_app_id() -> str:
    """Generate a short, time-ordered, URL-safe application ID.

    Format: ``app_<8 hex chars time>_<6 hex chars random>``. Not a true ULID
    but stable, sortable, and opaque enough for the UX.
    """
    ts = int(datetime.now(tz=timezone.utc).timestamp())
    return f"app_{ts:08x}{secrets.token_hex(3)}"


def _normalise_path(project_path: str) -> str:
    """Return an absolute, resolved string form of a project path."""
    return str(Path(project_path).expanduser().resolve())


def _normalise_name(name: str) -> str:
    """Case-insensitive, whitespace-collapsed form used for uniqueness checks."""
    return re.sub(r"\s+", " ", name.strip().lower())


def _derive_run_dir_name(name: str, existing: set[str]) -> str:
    """Pick an on-disk folder name derived from *name*, avoiding collisions."""
    base = slugify(name) or "app"
    candidate = base
    suffix = 2
    while candidate in existing:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


class ApplicationRepository:
    """Thread-safe repository for the applications store.

    All mutation methods take the internal lock and write the file
    atomically (write-to-tmp + rename).
    """

    def __init__(self, store_path: Path | None = None) -> None:
        self._store_path = store_path or _get_store_path()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> dict[str, dict]:
        """Return the raw store as a dict keyed by ``app_id``."""
        if not self._store_path.is_file():
            return {}
        try:
            data = json.loads(self._store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return data

    def _save(self, data: dict[str, dict]) -> None:
        """Atomically write the store."""
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._store_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self._store_path)

    @staticmethod
    def _to_model(record: dict) -> Application:
        return Application.model_validate(record)

    @staticmethod
    def _to_record(app: Application) -> dict:
        return app.model_dump()

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def list_applications(self) -> list[Application]:
        """Return all stored applications, ordered by ``created_at`` asc."""
        data = self._load()
        apps = [self._to_model(rec) for rec in data.values()]
        apps.sort(key=lambda a: a.created_at)
        return apps

    def get_application(self, app_id: str) -> Application:
        """Return the application for *app_id* or raise ``ApplicationNotFoundError``."""
        data = self._load()
        record = data.get(app_id)
        if record is None:
            raise ApplicationNotFoundError(f"Unknown application: {app_id}")
        return self._to_model(record)

    def find_by_name(self, name: str) -> Application | None:
        """Return an application with a matching (case-insensitive) name, or None."""
        target = _normalise_name(name)
        for app in self.list_applications():
            if _normalise_name(app.name) == target:
                return app
        return None

    def find_by_project_path(self, project_path: str) -> Application | None:
        """Return an application whose ``project_path`` matches, or None."""
        target = _normalise_path(project_path)
        for app in self.list_applications():
            if _normalise_path(app.project_path) == target:
                return app
        return None

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    def create_application(self, request: ApplicationCreateRequest) -> Application:
        """Create a new application, enforcing name + path uniqueness.

        Raises
        ------
        ApplicationNameConflictError
            If ``name`` collides (case-insensitive) with an existing app.
        ApplicationPathConflictError
            If ``project_path`` is already registered to another app.
        """
        with self._lock:
            data = self._load()
            existing = [self._to_model(rec) for rec in data.values()]

            name_key = _normalise_name(request.name)
            for app in existing:
                if _normalise_name(app.name) == name_key:
                    raise ApplicationNameConflictError(
                        f"An application named '{request.name}' already exists."
                    )

            path_key = _normalise_path(request.project_path)
            for app in existing:
                if _normalise_path(app.project_path) == path_key:
                    raise ApplicationPathConflictError(
                        f"An application is already registered for project path "
                        f"'{path_key}': '{app.name}'."
                    )

            now = datetime.now(tz=timezone.utc).isoformat()
            run_dir_names = {app.run_dir_name for app in existing}
            run_dir_name = _derive_run_dir_name(request.name, run_dir_names)

            app = Application(
                id=_generate_app_id(),
                name=request.name.strip(),
                slug=slugify(request.name),
                project_path=path_key,
                business_context=request.business_context,
                created_at=now,
                updated_at=now,
                run_dir_name=run_dir_name,
            )
            data[app.id] = self._to_record(app)
            self._save(data)
            return app

    def update_application(
        self, app_id: str, request: ApplicationUpdateRequest
    ) -> Application:
        """Apply partial updates to an application.

        Only ``name`` and ``business_context`` are user-editable. A rename
        also regenerates ``slug`` but leaves ``run_dir_name`` untouched so
        existing run artefacts on disk stay where they are.

        Raises
        ------
        ApplicationNotFoundError
            If the app does not exist.
        ApplicationNameConflictError
            If the new name collides with another application.
        """
        with self._lock:
            data = self._load()
            record = data.get(app_id)
            if record is None:
                raise ApplicationNotFoundError(f"Unknown application: {app_id}")

            current = self._to_model(record)

            new_name = current.name
            new_slug = current.slug
            if request.name is not None and request.name.strip() != current.name:
                proposed = request.name.strip()
                proposed_key = _normalise_name(proposed)
                for other_id, other_rec in data.items():
                    if other_id == app_id:
                        continue
                    other = self._to_model(other_rec)
                    if _normalise_name(other.name) == proposed_key:
                        raise ApplicationNameConflictError(
                            f"An application named '{proposed}' already exists."
                        )
                new_name = proposed
                new_slug = slugify(proposed)

            new_context: BusinessContext = (
                request.business_context
                if request.business_context is not None
                else current.business_context
            )

            updated = Application(
                id=current.id,
                name=new_name,
                slug=new_slug,
                project_path=current.project_path,
                business_context=new_context,
                created_at=current.created_at,
                updated_at=datetime.now(tz=timezone.utc).isoformat(),
                run_dir_name=current.run_dir_name,
            )
            data[app_id] = self._to_record(updated)
            self._save(data)
            return updated

    def delete_application(self, app_id: str) -> None:
        """Remove the application record. Does not touch run artefacts on disk.

        Raises
        ------
        ApplicationNotFoundError
            If the app does not exist.
        """
        with self._lock:
            data = self._load()
            if app_id not in data:
                raise ApplicationNotFoundError(f"Unknown application: {app_id}")
            data.pop(app_id)
            self._save(data)


# ---------------------------------------------------------------------------
# Module-level singleton — matches RunManager / Config access pattern used
# elsewhere in the server.
# ---------------------------------------------------------------------------

_repository: ApplicationRepository | None = None


def get_repository() -> ApplicationRepository:
    """Return the process-wide ``ApplicationRepository`` singleton."""
    global _repository
    if _repository is None:
        _repository = ApplicationRepository()
    return _repository
