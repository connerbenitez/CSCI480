# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


ROOT = Path(SPECPATH).resolve().parent


def data_tree(relative_dir: str):
    base = ROOT / relative_dir
    if not base.exists():
        return []
    pairs = []
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        relative_parent = path.relative_to(base).parent
        target_dir = Path(relative_dir) / relative_parent
        pairs.append((str(path), str(target_dir)))
    return pairs


datas = []
datas += data_tree("Frontend")
datas += data_tree("ML")

hiddenimports = []
hiddenimports += collect_submodules("Backend")
hiddenimports += collect_submodules("ML")
hiddenimports += collect_submodules("scapy")
hiddenimports += [
    "numpy._core",
    "numpy.core",
    "numpy.core.multiarray",
    "numpy.core.numeric",
    "numpy.core.numerictypes",
    "numpy.core.umath",
    "numpy.core._multiarray_umath",
]


a = Analysis(
    [str(ROOT / "run_project.py")],
    pathex=[str(ROOT), str(ROOT / "Backend"), str(ROOT / "ML")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(ROOT / "packaging" / "pyi_rth_numpy_pickle_compat.py")],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    name="CSCI480 Layered IDS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CSCI480 Layered IDS",
)
