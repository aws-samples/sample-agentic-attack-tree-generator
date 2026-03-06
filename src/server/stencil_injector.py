"""Post-processing hook to inject Stencil CDN references into generated dashboard HTML.

After the ThreatForest pipeline generates ``attack_trees_dashboard.html``, this
module injects the Stencil (AWS Design System) CSS/JS CDN links and ThreatForest
branding CSS custom properties into the ``<head>`` so the dashboard renders with
consistent styling.

Requirement 9.2: Generated HTML includes Stencil CDN stylesheet/script references
                  and ThreatForest branding colors from console.css.
Requirement 9.4: Stencil CDN resources loaded on every page.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Stencil CDN URLs (v4)
STENCIL_CSS_URL = "https://d3bqhfbip4ze4a.cloudfront.net/stencil/v4/stencil.css"
STENCIL_ESM_JS_URL = "https://d3bqhfbip4ze4a.cloudfront.net/stencil/v4/stencil.esm.js"
STENCIL_JS_URL = "https://d3bqhfbip4ze4a.cloudfront.net/stencil/v4/stencil.js"

# ThreatForest branding CSS custom properties (mirrored from console.css :root)
THREATFOREST_CSS_PROPERTIES = """\
:root {
  --tf-primary:        #15803d;
  --tf-primary-dark:   #166534;
  --tf-accent:         #16a34a;
  --tf-success:        #15803d;
  --tf-warning:        #ea580c;
  --tf-error:          #dc2626;
  --tf-info:           #0369a1;
  --tf-bg:             #f9fafb;
  --tf-surface:        #ffffff;
  --tf-text:           #111827;
  --tf-text-secondary: #6b7280;
  --tf-border:         #e5e7eb;
}"""


def build_stencil_snippet() -> str:
    """Return the HTML snippet to inject into ``<head>``."""
    return (
        "\n"
        "<!-- Stencil (AWS Design System) - injected by ThreatForest -->\n"
        f'<link rel="stylesheet" href="{STENCIL_CSS_URL}" />\n'
        f'<script type="module" src="{STENCIL_ESM_JS_URL}"></script>\n'
        f'<script nomodule src="{STENCIL_JS_URL}"></script>\n'
        "<style>\n"
        f"{THREATFOREST_CSS_PROPERTIES}\n"
        "</style>\n"
    )


def inject_stencil_references(html_path: str | Path) -> bool:
    """Inject Stencil CDN and ThreatForest CSS into a generated HTML file.

    Reads the file at *html_path*, locates the ``</head>`` tag, inserts the
    Stencil CDN ``<link>``/``<script>`` tags and a ``<style>`` block with
    ThreatForest CSS custom properties just before it, then writes the file
    back.

    Parameters
    ----------
    html_path:
        Path to the HTML file to modify.

    Returns
    -------
    bool
        ``True`` if injection succeeded, ``False`` if the file could not be
        processed (missing, no ``</head>`` tag, etc.).
    """
    path = Path(html_path)

    if not path.is_file():
        logger.warning("Stencil injection skipped — file not found: %s", path)
        return False

    try:
        html = path.read_text(encoding="utf-8")
    except OSError:
        logger.exception("Stencil injection failed — cannot read: %s", path)
        return False

    # Case-insensitive search for </head>
    head_close_lower = html.lower().find("</head>")
    if head_close_lower == -1:
        logger.warning("Stencil injection skipped — no </head> tag in: %s", path)
        return False

    # Already injected? Skip to avoid duplicates.
    if STENCIL_CSS_URL in html:
        logger.info("Stencil references already present in: %s", path)
        return True

    snippet = build_stencil_snippet()
    modified = html[:head_close_lower] + snippet + html[head_close_lower:]

    try:
        path.write_text(modified, encoding="utf-8")
    except OSError:
        logger.exception("Stencil injection failed — cannot write: %s", path)
        return False

    logger.info("Stencil CDN references injected into: %s", path)
    return True
