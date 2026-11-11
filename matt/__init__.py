"""MATT -- Man At The Top.

A two-stage credential-recovery toolkit for an authorized MITM engagement:

  stage 1 (capture)  pull wire bytes off the interface and write a
                     deterministic, machine-readable capture_report.json
  stage 2 (analyze)  decode those bytes into hashcat-format candidates and
                     render prose that a human can act on

Token economy (the whole point of the design):

  A default run costs ZERO usage tokens. ``matt.core`` imports the standard
  library only, no module touches the network at import time, and
  ``analyze()`` falls back to the built-in ``stage2_prose`` writer. Exactly one
  function in this package can open a socket -- ``matt.model.call_model`` --
  and it runs only when the operator passes ``--use-model``.

``matt.cli`` is exported too, lazily via PEP 562 ``__getattr__``, so that
``import matt`` and ``python3 -m matt.cli`` do not bind that module twice::

    matt/__init__.py  matt/core.py  matt/capture.py  matt/model.py  matt/cli.py
    tests/test_core.py
    requirements.txt
"""

__version__ = "1.7.0"

from . import core
from . import capture
from . import model

__all__ = ["__version__", "core", "capture", "model", "cli"]


def __getattr__(name):
    if name == "cli":
        # importlib.import_module, not "from . import": the latter re-enters
        # this hook while binding the name and recurses until the stack dies.
        import importlib
        return importlib.import_module(f"{__name__}.cli")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
