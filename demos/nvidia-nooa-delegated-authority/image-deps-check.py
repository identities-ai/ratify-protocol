import pathlib
import sys

import mcp
import nooa
import ratify_protocol_v2

# The module path matters as much as the version: it is how a run states whether
# the SDK came from the staged, locked dependency tree or from somewhere else.
print(
    "IMAGE_DEPS_OK",
    sys.version.split()[0],
    nooa.__version__,
    ratify_protocol_v2.__version__,
    pathlib.Path(ratify_protocol_v2.__file__).resolve().parent,
)
