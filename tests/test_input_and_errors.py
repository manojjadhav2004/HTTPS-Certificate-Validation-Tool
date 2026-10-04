"""Bad input and network problems must give a clean error, never a traceback."""
import socket
import threading

import pytest

from cert_validator import validate
from utils.target import InvalidTargetError, parse_target


@pytest.mark.parametrize("bad", [
    "", "   ", "http://example.com", "ftp://example.com", "bad host name", "exa mple.com",
    "-bad-.com", "a" * 300 + ".com", "example.com:99999", "user@example.com", "https://", "exa_mple!.com",
])
def test_invalid_url_is_rejected(bad):
    with pytest.raises(InvalidTargetError):
        parse_target(bad)
    report = validate(bad)
    assert report.error["kind"] == "invalid_input"
    assert report.verdict is None


def test_invalid_port_is_rejected():
    assert validate("example.com", 70000).error["kind"] == "invalid_input"
    assert validate("example.com", 0).error["kind"] == "invalid_input"


@pytest.mark.parametrize("text,expected", [
    ("example.com", ("example.com", 443)),
    ("EXAMPLE.com", ("example.com", 443)),
    ("https://example.com/some/path?x=1", ("example.com", 443)),
    ("https://example.com:8443", ("example.com", 8443)),
    ("example.com:4443", ("example.com", 4443)),
    ("localhost", ("localhost", 443)),
    ("127.0.0.1", ("127.0.0.1", 443)),
    ("[::1]:4443", ("::1", 4443)),
])
def test_valid_targets_are_parsed(text, expected):
    assert parse_target(text) == expected


def test_port_argument_overrides_default():
    assert parse_target("example.com", 4443) == ("example.com", 4443)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_unreachable_server_connection_refused():
    report = validate("localhost", _free_port(), timeout=3)
    assert report.error["kind"] == "refused"
    assert report.verdict is None
    assert report.certificate is None


def test_dns_failure():
    report = validate("this-host-does-not-exist.invalid", timeout=3)
    assert report.error["kind"] == "dns"


def test_timeout_when_server_never_answers():
    """A server that accepts the TCP connection but never speaks TLS."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    held = []
    stop = threading.Event()

    def accept_and_hold():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(listener.accept()[0])
            except OSError:
                continue

    thread = threading.Thread(target=accept_and_hold, daemon=True)
    thread.start()
    try:
        report = validate("127.0.0.1", port, timeout=1)
        assert report.error["kind"] == "timeout"
    finally:
        stop.set()
        thread.join()
        for conn in held:
            conn.close()
        listener.close()


def test_server_that_does_not_speak_tls():
    """Plain TCP server answering garbage -> clean 'tls' error."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]

    def answer():
        for _ in range(2):  # verified attempt + inspection attempt
            try:
                conn, _ = listener.accept()
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                conn.close()
            except OSError:
                return

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    report = validate("127.0.0.1", port, timeout=3)
    listener.close()
    assert report.error["kind"] == "tls"


def test_missing_ca_file():
    report = validate("localhost", 4443, ca_file="does/not/exist.pem")
    assert report.error["kind"] == "ca_file"


def test_broken_ca_file(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("this is not a certificate")
    report = validate("localhost", 4443, ca_file=str(bad))
    assert report.error["kind"] == "ca_file"
