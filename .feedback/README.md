# Feedback task starting environment

Upstream: https://github.com/cunla/fakeredis-py
Upstream commit: `a8e10d75aaf0dc5e7b34bb39047efcefcb8fbec6`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= test/test_internals/test_acl_save_load.py test/test_internals/test_async_connection.py::test_from_url
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `2 passed, 1 warning in 0.03s`
Whole-command wall time: 0.726 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
