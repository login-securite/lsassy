import logging
import pytest

LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope='function')
def example_fixture():
    LOGGER.info("Setting Up Example Fixture...")
    yield
    LOGGER.info("Tearing Down Example Fixture...")
