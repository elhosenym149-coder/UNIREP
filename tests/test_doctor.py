from unirep.doctor import collect_diagnostics, render_diagnostics


def test_doctor_reports_environment_without_installing_tools():
    report = collect_diagnostics()
    assert report["python"]
    assert isinstance(report["modules"], list)
    assert isinstance(report["tools"], list)
    rendered = render_diagnostics(report)
    assert "Python modules:" in rendered
    assert "External tools:" in rendered
