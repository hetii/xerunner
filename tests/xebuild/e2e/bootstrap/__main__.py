"""`python -m tests.xebuild.e2e.bootstrap`: make the material, print its variables."""

import shlex

from . import prepare

for name, value in sorted(prepare().items()):
    print("export %s=%s" % (name, shlex.quote(value)))
