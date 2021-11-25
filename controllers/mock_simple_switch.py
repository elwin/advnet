class SimpleSwitchThriftAPI:
    def __init__(self, thrift_port):
        self.thrift_port = thrift_port
        pass

    def table_set_default(self, table_name, action_name, action_params=[]):
        print(f'[{self.thrift_port}] <table_set_default> {table_name} - {action_name} - {action_params}')

    def reset_state(self):
        print(f'[{self.thrift_port}] <reset state>')

    def table_add(self, table_name, action_name, match_keys, action_params=[], prio=0, rates=None, pkts=None,
                  byts=None):
        print(f'[{self.thrift_port}] <table add> {table_name} {action_name} {match_keys} {action_params}')
