"""Environment diagnostics; this module reports tools but never installs or executes them."""
from __future__ import annotations

import importlib.util
import json
import platform
import shutil
import sys
from typing import Any

PYTHON_MODULES = {
    "PySide6": "pip install '.[desktop]'",
    "playwright": "pip install '.[web]' then python -m playwright install chromium",
    "onnx": "pip install onnx",
    "onnxruntime": "pip install onnxruntime",
    "tflite_runtime": "Install a wheel matching your Python and OS, or use TensorFlow Lite tooling",
}

EXTERNAL_TOOLS = {
    "jadx": "Install JADX and add its executable to PATH",
    "apktool": "Install APKTool and add it to PATH",
    "ilspycmd": "dotnet tool install --global ilspycmd",
    "pycdc": "Install pycdc and add it to PATH",
    "decompyle3": "pip install decompyle3",
    "uncompyle6": "pip install uncompyle6",
    "ghidraRun": "Install Ghidra and add its launcher to PATH",
    "adb": "Install Android Platform Tools",
    "docker": "Install Docker Engine/Desktop for future sandboxed analysis",
    "git": "Install Git",
    "pyinstaller": "pip install pyinstaller",
}


def collect_diagnostics() -> dict[str, Any]:
    modules = []
    for name, hint in PYTHON_MODULES.items():
        try:
            available = importlib.util.find_spec(name) is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            available = False
        modules.append({"name": name, "available": available, "install_hint": hint})
    tools = [
        {"name": name, "available": shutil.which(name) is not None,
         "path": shutil.which(name), "install_hint": hint}
        for name, hint in EXTERNAL_TOOLS.items()
    ]
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "modules": modules,
        "tools": tools,
        "note": "Diagnostics only: Reforge never installs external tools or executes analyzed targets automatically."
    }


def render_diagnostics(report: dict[str, Any]) -> str:
    lines = [f"Python: {report['python']}", f"Platform: {report['platform']}", "", "Python modules:"]
    lines.extend(f"  {'OK' if x['available'] else 'MISSING':7} {x['name']} — {x['install_hint']}"
                 for x in report["modules"])
    lines += ["", "External tools:"]
    lines.extend(f"  {'OK' if x['available'] else 'MISSING':7} {x['name']} — {x['install_hint']}"
                 for x in report["tools"])
    lines += ["", report["note"]]
    return "\n".join(lines)
