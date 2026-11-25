"""Safe project scaffold generation from an explicit, reviewed reconstruction spec."""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any


def _slug(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,49}", value):
        raise ValueError("Project name must start with a letter and contain only letters, digits, '_' or '-' (max 50)")
    return value.lower().replace("-", "_")


def load_spec(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.stat().st_size > (1 << 20):
        raise ValueError("Reconstruction spec exceeds 1 MiB")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Spec must be a JSON object")
    name = data.get("name")
    platform = data.get("platform")
    description = data.get("description", "")
    features = data.get("features", [])
    if not isinstance(name, str):
        raise ValueError("Spec requires a string 'name'")
    slug = _slug(name)
    if platform not in {"python", "web"}:
        raise ValueError("platform must be 'python' or 'web' for this generator version")
    if not isinstance(description, str) or len(description) > 1000:
        raise ValueError("description must be a string of at most 1000 characters")
    if not isinstance(features, list) or len(features) > 40 or not all(
        isinstance(x, str) and 1 <= len(x) <= 200 for x in features
    ):
        raise ValueError("features must be a list of up to 40 strings (1–200 characters each)")
    return {"name": name, "slug": slug, "platform": platform,
            "description": description, "features": features}


def _write_new(root: Path, relative: str, content: str) -> None:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("Generated path is not safe")
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def generate_project(spec_path: Path, output: Path) -> dict[str, Any]:
    spec = load_spec(spec_path)
    output = Path(output).expanduser().absolute()
    if output.is_symlink():
        raise ValueError("Output directory must not be a symlink")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError("Output must be a new or empty directory; existing files will not be overwritten")
    output.mkdir(parents=True, exist_ok=True)
    features_md = "\n".join(f"- {x}" for x in spec["features"]) or "- To be specified"
    if spec["platform"] == "python":
        toml_description = json.dumps(spec["description"])
        package = spec["slug"]
        files = {
            "pyproject.toml": f'''[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "{package.replace("_", "-")}"
version = "0.1.0"
description = {toml_description}
requires-python = ">=3.10"

[tool.pytest.ini_options]
testpaths = ["tests"]
''',
            f"{package}/__init__.py": '"""Generated application package."""\n',
            f"{package}/main.py": '''def main() -> int:
    print("Application scaffold is ready. Implement verified requirements here.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
            "tests/test_smoke.py": f'''from {package}.main import main


def test_main_returns_success():
    assert main() == 0
''',
            "README.md": f"# {spec['name']}\n\n{spec['description']}\n\n## Verified feature checklist\n{features_md}\n\nThis is a generated scaffold, not a recovered copy of the original application.\n"
        }
    else:
        title = html.escape(spec["name"])
        description = html.escape(spec["description"])
        feature_html = "\n".join(f"<li>{html.escape(x)}</li>" for x in spec["features"])
        files = {
            "index.html": f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <meta name="description" content="{description}">
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <main>
    <p class="eyebrow">GENERATED PROJECT SCAFFOLD</p>
    <h1>{title}</h1>
    <p>{description}</p>
    <h2>Verified requirements</h2>
    <ul>{feature_html}</ul>
  </main>
  <script src="app.js"></script>
</body>
</html>
''',
            "styles.css": '''* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: #11151b; color: #edf2f7;
       font: 16px/1.6 system-ui, sans-serif; display: grid; place-items: center; }
main { width: min(760px, 92vw); padding: 48px; background: #1a2029;
       border: 1px solid #303a48; border-radius: 18px; }
h1 { color: #f2c14e; font-size: clamp(2rem, 7vw, 4rem); margin: 0; }
.eyebrow { color: #9aa7b8; letter-spacing: .18em; font-size: .75rem; }
''',
            "app.js": '''// Generated starter. Add behavior only from verified requirements.
console.info("Project scaffold loaded.");
''',
            "README.md": f"# {spec['name']}\n\n{spec['description']}\n\n## Verified feature checklist\n{features_md}\n\nThis is a generated scaffold, not a recovered copy of the original application.\n"
        }
    for relative, content in files.items():
        _write_new(output, relative, content)
    (output / "reconstruction-spec.json").write_text(
        json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {"project": spec["name"], "platform": spec["platform"],
            "output": str(output), "files": sorted([*files, "reconstruction-spec.json"]),
            "status": "scaffold_generated"}
