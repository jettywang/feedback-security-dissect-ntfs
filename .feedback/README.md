# Feedback task starting environment

Upstream: https://github.com/fox-it/dissect.ntfs
Upstream commit: `83f71a87e173613580eb31f64c600789f4259c20`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.
System prerequisite: git-lfs is installed; run git lfs install --local and git lfs pull after cloning.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-13): `36 passed in 13.14s`
Whole-command wall time: 13.449 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
