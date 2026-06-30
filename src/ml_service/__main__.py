"""Launch the ML service: ``python -m ml_service`` (or via the TS CLI / supervisor).

Env:
    TF_ML_HOST   (default 127.0.0.1)  — bind host; keep loopback so the model
                                         server isn't publicly exposed.
    TF_ML_PORT   (default 8770)       — bind port (the TS engine's default client target).
    TF_ML_WARM   (default 1)          — eagerly load model + graphs at startup.
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("TF_ML_HOST", "127.0.0.1")
    port = int(os.environ.get("TF_ML_PORT", "8770"))
    warm = os.environ.get("TF_ML_WARM", "1") not in ("0", "false", "False", "")

    # Build the app with the requested warm flag rather than importing the
    # module-level `app` (which is constructed warm=False for test imports).
    from ml_service.app import create_app

    uvicorn.run(create_app(warm=warm), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
