import logging
import time
import typing
from dataclasses import dataclass

try:
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ModuleNotFoundError:
    pass


# TODO Refactor
def time_function(f: typing.Callable):
    start = time.time()
    x = f()
    duration = time.time() - start
    duration = round(duration * 1000, 2)
    logging.info(f'[timing] executed {f.__name__} in {duration}ms')
    return x


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


@dataclass(init=True, frozen=True)
class RegisterSet:
    register_name: str
    index: int
    value: int

    def __str__(self):
        return f'<table_set_default> {self.register_name}[{self.index}] -> {self.value}'


class Configuration:
    table_set_default: typing.List[TableSetDefault]
    table_add: typing.List[TableAdd]
    register_set: typing.List[RegisterSet]

    def __init__(self):
        self.table_set_default = []
        self.table_add = []
        self.table_add_match_only = []


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

        self.new_config.table_add_match_only.append(TableAdd(
            table_name=table_name,
            action_name=action_name,
            match_keys=tuple(match_keys),
            action_params=(),
        ))

        # return self.api.table_add(table_name, action_name, match_keys, action_params)

    def counter_read(self, counter_name: str, index: int):
        return self.api.counter_read(counter_name, index)

    def apply_table_add(self):
        adds: typing.Set[TableAdd] = set(self.new_config.table_add) - set(self.old_config.table_add)
        removes: typing.Set[TableAdd] = set(self.old_config.table_add_match_only) - set(
            self.new_config.table_add_match_only)

        # TODO likely won't have to remove entries that are replaced
        #  with new entries with the same table_name and match_keys
        for remove in removes:
            logging.info(f'[table_mod][{self.name}] removing {remove}')
            self.api.table_delete_match(remove.table_name, list(remove.match_keys))

        for add in adds:
            entry = TableAdd(
                table_name=add.table_name,
                action_name=add.action_name,
                match_keys=add.match_keys,
                action_params=(),
            )
            if entry in self.old_config.table_add_match_only:
                logging.info(f'[table_mod][{self.name}] modifying {add}')
                self.api.table_modify_match(
                    add.table_name,
                    add.action_name,
                    list(add.match_keys),
                    list(add.action_params),
                )
            else:
                logging.info(f'[table_mod][{self.name}] adding {add}')
                self.api.table_add(
                    add.table_name,
                    add.action_name,
                    list(add.match_keys),
                    list(add.action_params),
                )

    def register_write(self, register_name: str, index, value: int):
        logging.info(f'[register_mod][{self.name}] setting {register_name}[{index}] -> {value}')
        self.api.register_write(
            register_name=register_name,
            index=index,
            value=value,
        )

    def apply_table_set_default(self):
        adds: typing.Set[TableSetDefault] = set(self.new_config.table_set_default) - set(
            self.old_config.table_set_default)
        removes: typing.Set[TableSetDefault] = set(self.old_config.table_set_default) - set(
            self.new_config.table_set_default)

        for add in adds:
            logging.info(f'[table_mod][{self.name}] adding {add}')
            self.api.table_set_default(
                add.table_name,
                add.action_name,
            )

        for remove in removes:
            raise Exception(f'cannot remove {remove}')

    def apply(self):
        self.apply_table_set_default()
        self.apply_table_add()
        self.old_config = self.new_config
        self.new_config = Configuration()
