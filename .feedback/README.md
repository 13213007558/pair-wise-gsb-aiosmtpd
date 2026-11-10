# Feedback task starting environment

Upstream: https://github.com/aio-libs/aiosmtpd
Upstream commit: `0aef6a19bf3c43ebded54ee943aaacbff93d68bf`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= aiosmtpd/tests/test_proxyprotocol.py::TestProxyData aiosmtpd/tests/test_proxyprotocol.py::TestProxyTLV aiosmtpd/tests/test_proxyprotocol.py::TestGetV1 aiosmtpd/tests/test_proxyprotocol.py::TestGetV2 -o asyncio_default_fixture_loop_scope=function
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-10): `92 passed in 3.16s`
Whole-command wall time: 3.393 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
