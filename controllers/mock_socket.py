import logging


class MockSocket:
    """Mock implementation of a socket to ease testing."""
    def __init__(self):
        self.address = None

    def bind(self, address):
        self.address = address

    def send(self, data, flags: int = None):
        logging.info(f'[{self.address}] {data}')
