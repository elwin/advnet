import logging


class SimpleSwitchThriftAPI:
    def __init__(self, thrift_port):
        self.thrift_port = thrift_port
        self.packets = 0
        self.bytes = 0
        pass

    def table_set_default(self, table_name, action_name, action_params=[]):
        logging.info(f'[{self.thrift_port}] <table_set_default> {table_name} - {action_name} - {action_params}')

    def reset_state(self):
        logging.info(f'[{self.thrift_port}] <reset state>')

    def table_add(self, table_name, action_name, match_keys, action_params=[], prio=0, rates=None, pkts=None,
                  byts=None):
        logging.info(f'[{self.thrift_port}] <table add> {table_name} {action_name} {match_keys} {action_params}')

    def counter_read(self, counter_name: str, index: int):
        self.bytes += 100
        self.packets += 1
        return self.bytes, self.packets

    def register_write(self, register_name: str, index, value: int):
        logging.info(f'[{self.thrift_port}] [register_mod] setting {register_name}[{index}] -> {value}')

