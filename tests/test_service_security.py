import pytest

from unirep.service.server import serve


def test_lan_server_requires_tls_or_explicit_insecure_opt_in(tmp_path):
    with pytest.raises(ValueError, match="requires TLS"):
        serve(host="0.0.0.0", roots=[str(tmp_path)])


def test_server_requires_certificate_and_key_together(tmp_path):
    with pytest.raises(ValueError, match="Both --cert and --key"):
        serve(host="0.0.0.0", roots=[str(tmp_path)], certfile="cert.pem")


def test_server_rejects_short_explicit_bearer_token(tmp_path):
    with pytest.raises(ValueError, match="24 characters"):
        serve(host="127.0.0.1", roots=[str(tmp_path)], token="short")
