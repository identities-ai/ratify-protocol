# SPDX-License-Identifier: Apache-2.0
"""Content hash over the staged dependency tree.

Used to tag the NOOA sandbox image. Stable while the dependency set is
unchanged, so Docker's layer cache is reused across runs and a rebuild only
happens when the tree actually differs. Hashes relative paths and sizes rather
than file contents: it has to be fast over ~240 MB, and it only needs to detect
a changed dependency set, not to attest to file integrity. The immutable base
digest and the resolved image id are what the artifact records for provenance.
"""

import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.rglob("*")):
    if path.is_file():
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.stat().st_size.to_bytes(8, "big"))
print(digest.hexdigest())
