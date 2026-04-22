# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Sphinx configuration for AMA Cryptography Python API documentation

from __future__ import annotations

import os
import sys
import urllib.request
from urllib.error import URLError

# Add source to path
# Add parent directory to path so autodoc can find ama_cryptography package
sys.path.insert(0, os.path.abspath(".."))

# Tell ama_cryptography modules that we are in a documentation build so the
# INVARIANT-7 import guards in crypto_api.py / key_management.py permit
# introspection without a native backend.  The call-time enforcement
# (_enforce_invariant7*) still raises if any code is actually executed.
os.environ.setdefault("AMA_SPHINX_BUILD", "1")

# Project information
project = "AMA Cryptography"
copyright = "2025-2026, Steel Security Advisors LLC"
author = "Andrew E. A."
version = "2.1.5"
release = "2.1.5"

# General configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx.ext.coverage",
    "sphinx.ext.mathjax",
    "sphinx_rtd_theme",
    "sphinx_autodoc_typehints",
]

# Napoleon settings (for Google/NumPy style docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_type_aliases = None

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}
autodoc_typehints = "description"
autodoc_type_aliases = {}

# Autosummary settings
autosummary_generate = True
autosummary_imported_members = False

# Intersphinx mapping.  Prefer vendored inventories under docs/_intersphinx/
# when available (offline CI).  For remote URLs we probe reachability at
# conf-load time and drop unreachable entries so that sandboxed / offline
# runners do not emit a bare "failed to reach any of the inventories"
# warning that would break strict (``-W``) builds.  Operators who want
# deterministic offline builds should vendor inventories under
# docs/_intersphinx/ per the README there.
_INTERSPHINX_CACHE = os.path.join(os.path.dirname(__file__), "_intersphinx")
_INTERSPHINX_PROBE_TIMEOUT = float(os.environ.get("AMA_INTERSPHINX_PROBE_TIMEOUT", "3"))


def _vendored_inventory(name: str) -> str | None:
    path = os.path.join(_INTERSPHINX_CACHE, f"{name}.inv")
    return path if os.path.exists(path) else None


def _inventory_reachable(url: str) -> bool:
    """Probe ``{url}/objects.inv`` and return True if it is fetchable.

    Used to decide whether to include a remote intersphinx entry.  Uses
    a short timeout so sandboxed builds do not block.
    """
    probe = url.rstrip("/") + "/objects.inv"
    try:
        req = urllib.request.Request(probe, method="HEAD")
        with urllib.request.urlopen(req, timeout=_INTERSPHINX_PROBE_TIMEOUT) as resp:
            return 200 <= resp.status < 400
    except (URLError, OSError, ValueError):
        return False


def _build_intersphinx_mapping() -> dict:
    """Assemble ``intersphinx_mapping`` using vendored > reachable > drop."""
    candidates = {
        "python": "https://docs.python.org/3",
        "numpy": "https://numpy.org/doc/stable/",
        "scipy": "https://docs.scipy.org/doc/scipy/",
    }
    mapping: dict = {}
    for name, url in candidates.items():
        vendored = _vendored_inventory(name)
        if vendored is not None:
            mapping[name] = (url, vendored)
        elif _inventory_reachable(url):
            mapping[name] = (url, None)
        # else: drop — offline build, no cross-references for this project.
    return mapping


intersphinx_mapping = _build_intersphinx_mapping()
intersphinx_disabled_reftypes: list = []
intersphinx_timeout = 5

# Defence-in-depth: if a probe briefly succeeds but the real fetch fails
# mid-build (transient 5xx), classify the resulting message as a
# non-fatal warning category so -W does not abort strict builds.
suppress_warnings = [
    "intersphinx.external",
    "config.cache",
]

# Templates path
templates_path = ["_templates"]

# Source suffix
source_suffix = ".rst"

# Master document
master_doc = "index"

# Language
language = "en"

# List of patterns to exclude
exclude_patterns = ["_build", "_intersphinx", "Thumbs.db", ".DS_Store"]

# Pygments style
pygments_style = "sphinx"

# Sphinx TODO extension settings
todo_include_todos = True

# HTML output options
html_theme = "sphinx_rtd_theme"
# sphinx-rtd-theme >=3.0.0 removed canonical_url, analytics_id, logo_only, and
# display_version; the project version is now rendered automatically via the
# Sphinx `version` variable defined above.
html_theme_options = {
    "prev_next_buttons_location": "bottom",
    "style_external_links": False,
    "style_nav_header_background": "#2980B9",
    # Toc options
    "collapse_navigation": False,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "includehidden": True,
    "titles_only": False,
}

html_static_path = ["_static"]
html_logo = None
html_favicon = None

# HTML output
html_title = f"{project} v{version}"
html_short_title = project
html_show_sourcelink = True
html_show_sphinx = True
html_show_copyright = True

# HTML help
htmlhelp_basename = "AmaCryptographydoc"

# LaTeX output
latex_elements = {}
latex_documents = [
    (master_doc, "AmaCryptography.tex", f"{project} Documentation", author, "manual"),
]

# Manual pages
man_pages = [(master_doc, "ama-cryptography", f"{project} Documentation", [author], 1)]

# Texinfo output
texinfo_documents = [
    (
        master_doc,
        "AmaCryptography",
        f"{project} Documentation",
        author,
        "AmaCryptography",
        "Quantum-Resistant Cryptographic Protection System.",
        "Miscellaneous",
    ),
]

# Epub output
epub_title = project
epub_exclude_files = ["search.html"]
