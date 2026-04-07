# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Sphinx configuration for AMA Cryptography Python API documentation

import os
import sys

# Add source to path
# Add parent directory to path so autodoc can find ama_cryptography package
sys.path.insert(0, os.path.abspath(".."))

# Project information
project = "AMA Cryptography"
copyright = "2025-2026, Steel Security Advisors LLC"
author = "Andrew E. A."
version = "2.1.2"
release = "2.1.2"

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

# Intersphinx mapping
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "numpy": ("https://numpy.org/doc/stable/", None),
    "scipy": ("https://docs.scipy.org/doc/scipy/", None),
}

# Templates path
templates_path = ["_templates"]

# Source suffix
source_suffix = ".rst"

# Master document
master_doc = "index"

# Language
language = "en"

# List of patterns to exclude
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Pygments style
pygments_style = "sphinx"

# Sphinx TODO extension settings
todo_include_todos = True

# HTML output options
html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "canonical_url": "",
    "analytics_id": "",
    "logo_only": False,
    "display_version": True,
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
