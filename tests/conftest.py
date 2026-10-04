import pytest

from lab.generate_certs import generate_all
from lab.serve import start_servers, stop_servers
from utils.paths import LAB_CA_PATH


@pytest.fixture(scope="session")
def lab_servers():
    """Starts the local HTTPS lab (ports 4443-4448) once for the whole test run."""
    generate_all()
    servers = start_servers(skip_busy=True)
    yield
    stop_servers(servers)


@pytest.fixture(scope="session")
def ca_file():
    return str(LAB_CA_PATH)


def check_status(report, name):
    return next(c.status for c in report.checks if c.name == name)
