import importlib
import importlib.abc
import importlib.util
import sys


PREFIX = "numpy._core"
TARGET_PREFIX = "numpy.core"


def _seed_aliases():
    try:
        numpy_core = importlib.import_module(TARGET_PREFIX)
        sys.modules.setdefault(PREFIX, numpy_core)
    except Exception:
        return

    for name in ("_multiarray_umath", "multiarray", "numeric", "numerictypes", "umath"):
        try:
            module = importlib.import_module(f"{TARGET_PREFIX}.{name}")
            sys.modules.setdefault(f"{PREFIX}.{name}", module)
        except Exception:
            continue


class _NumpyCoreCompatLoader(importlib.abc.Loader):
    def __init__(self, alias_name: str, target_name: str):
        self.alias_name = alias_name
        self.target_name = target_name

    def create_module(self, spec):
        module = importlib.import_module(self.target_name)
        sys.modules[self.alias_name] = module
        return module

    def exec_module(self, module):
        return None


class _NumpyCoreCompatFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != PREFIX and not fullname.startswith(PREFIX + "."):
            return None

        mapped_name = TARGET_PREFIX + fullname[len(PREFIX):]
        target_spec = importlib.util.find_spec(mapped_name)
        if target_spec is None:
            return None

        return importlib.util.spec_from_loader(
            fullname,
            _NumpyCoreCompatLoader(fullname, mapped_name),
            is_package=bool(target_spec.submodule_search_locations),
        )


if not any(isinstance(finder, _NumpyCoreCompatFinder) for finder in sys.meta_path):
    sys.meta_path.insert(0, _NumpyCoreCompatFinder())

_seed_aliases()
