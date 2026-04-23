# Intersphinx inventory cache

This directory holds optional cached copies of remote Sphinx ``objects.inv``
files used by ``sphinx.ext.intersphinx`` for cross-project references.

Populating it is **optional** — the build falls back to the remote URLs
listed in ``docs/conf.py`` when a local inventory is absent.

To populate for fully-offline doc builds:

```sh
curl -L https://docs.python.org/3/objects.inv -o docs/_intersphinx/python.inv
curl -L https://numpy.org/doc/stable/objects.inv -o docs/_intersphinx/numpy.inv
curl -L https://docs.scipy.org/doc/scipy/objects.inv -o docs/_intersphinx/scipy.inv
```

``docs/conf.py`` picks up any ``<name>.inv`` file here automatically.
