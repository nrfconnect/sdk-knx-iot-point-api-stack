"""Root conftest for the runtime tier (tests/runtime).

The fixtures, constants, helpers and hooks themselves live in
`tests/common/fixtures.py`, NOT here, so that the tests can also import
them by name (`from fixtures import DUT_IA, set_lsm, ...`) the way the
test modules do. A conftest is not importable under a stable module name
from a sibling directory, which is why the split exists.

This file is the part pytest itself looks at: pytest only collects
fixtures and hooks from `conftest.py`, so everything `fixtures.py`
defines has to be re-exported into this module's namespace.

`from fixtures import *` does that for the fixtures, the constants and
the helpers (fixtures.py defines no `__all__`, so the star-import takes
every public name). The `pytest_*` hooks come along with it too, but
they are listed explicitly below: a hook that silently stops being
re-exported is a silent behaviour change — `--run-record` quietly
becoming an unknown option, or the module ordering quietly reverting to
alphabetical — so they are named where a reader can see them.
"""

import os
import sys

# A normal checkout of the test tool instead of the submodule (pytest.ini).
if os.environ.get("KNX_TOOL_DIR"):
    sys.path.insert(0, os.path.abspath(os.environ["KNX_TOOL_DIR"]))

from fixtures import *                                        # noqa: F401,F403

# Hooks, explicitly (see the module docstring).
from fixtures import (pytest_addoption, pytest_collection_modifyitems,  # noqa: F401
                      pytest_configure)
