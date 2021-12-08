import logging
import typing
from dataclasses import dataclass

try:
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ModuleNotFoundError:
    pass


@dataclass(init=True, frozen=True)
class TableAdd:
    table_name: str
    action_name: str
    match_keys: typing.Tuple
    action_params: typing.Tuple

    def __str__(self):
        return f'<table_add> {self.table_name} / {self.action_name} -> {list(self.match_keys)}, {list(self.action_params)}'


@dataclass(init=True, frozen=True)
class TableSetDefault:
    table_name: str
    action_name: str

    def __str__(self):
        return f'<table_set_default> {self.table_name} / {self.action_name}'


class Configuration:
    table_set_default: typing.List[TableSetDefault]
    table_add: typing.List[TableAdd]

    def __init__(self):
        self.table_set_default = []
        self.table_add = []


class SmartSwitch:
    def __init__(self, api, name: str):
        self.api = api
        self.name = name

        self.old_config = Configuration()
        self.new_config = Configuration()

    def table_set_default(self, table_name, action_name):
        self.new_config.table_set_default.append(TableSetDefault(
            table_name=table_name,
            action_name=action_name,
        ))
        # self.new_config.table_set_default.append((table_name, action_name))
        return self.api.table_set_default(table_name, action_name, [])

    def reset_state(self):
        return self.api.reset_state()

    def table_add(self, table_name, action_name, match_keys, action_params):
        self.new_config.table_add.append(TableAdd(
            table_name=table_name,
            action_name=action_name,
            match_keys=tuple(match_keys),
            action_params=tuple(action_params),
        ))

        # return self.api.table_add(table_name, action_name, match_keys, action_params)

    def counter_read(self, counter_name: str, index: int):
        return self.api.counter_read(counter_name, index)

    def apply_table_add(self):
        adds: typing.Set[TableAdd] = set(self.new_config.table_add) - set(self.old_config.table_add)
        removes: typing.Set[TableAdd] = set(self.old_config.table_add) - set(self.new_config.table_add)

        # TODO likely won't have to remove entries that are replaced
        #  with new entries with the same table_name and match_keys
        for remove in removes:
            self.api.table_delete_match(remove.table_name, list(remove.match_keys))
            logging.info(f'[table_mod][{self.name}] removing {remove}')

        for add in adds:
            self.api.table_add(
                add.table_name,
                add.action_name,
                list(add.match_keys),
                list(add.action_params),
            )
            logging.info(f'[table_mod][{self.name}] adding {add}')

    def apply_table_set_default(self):
        adds: typing.Set[TableSetDefault] = set(self.new_config.table_set_default) - set(
            self.old_config.table_set_default)
        removes: typing.Set[TableSetDefault] = set(self.old_config.table_set_default) - set(
            self.new_config.table_set_default)

        for add in adds:
            self.api.table_set_default(
                add.table_name,
                add.action_name,
            )
            logging.info(f'[table_mod][{self.name}] adding {add}')

        for remove in removes:
            raise Exception(f'cannot remove {remove}')

    def apply(self):
        self.apply_table_set_default()
        self.apply_table_add()
        self.old_config = self.new_config
        self.new_config = Configuration()
