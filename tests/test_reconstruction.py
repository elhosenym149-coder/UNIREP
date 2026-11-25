import json
import pytest

from unirep.reconstruction.generator import generate_project, load_spec


def test_generates_web_scaffold_with_escaped_content(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({
        "name": "Demo",
        "platform": "web",
        "description": "<script>alert('x')</script>",
        "features": ["Login & profile"]
    }))
    out = tmp_path / "generated"
    result = generate_project(spec, out)
    html = (out / "index.html").read_text()
    assert result["status"] == "scaffold_generated"
    assert "&lt;script&gt;" in html
    assert "Login &amp; profile" in html


def test_generator_refuses_to_overwrite_existing_files(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"name": "Demo", "platform": "python"}))
    out = tmp_path / "existing"
    out.mkdir()
    (out / "keep.txt").write_text("keep")
    with pytest.raises(FileExistsError):
        generate_project(spec, out)
    assert (out / "keep.txt").read_text() == "keep"


def test_generator_rejects_invalid_project_name(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"name": "../escape", "platform": "web"}))
    with pytest.raises(ValueError):
        load_spec(spec)


def test_generates_python_project(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"name": "Demo_App", "platform": "python",
                                "description": 'A project with "quotes"'}))
    out = tmp_path / "python_project"
    generate_project(spec, out)
    assert (out / "demo_app" / "main.py").exists()
    pyproject = (out / "pyproject.toml").read_text()
    assert 'description = "A project with \\"quotes\\""' in pyproject
