import logging
import typing
from dataclasses import dataclass

try:
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ModuleNotFoundError:
    pass


@dataclass(init=True, frozen=True)
class TableAdd:
    """Represents a table add entry"""
    table_name: str
    action_name: str
    match_keys: typing.Tuple
    action_params: typing.Tuple

    def __str__(self):
        return f'<table_add> {self.table_name} / {self.action_name} -> {list(self.match_keys)}, {list(self.action_params)}'


class Configuration:
    """Represents a configuration consisting of table add entries that should be part of the switch"""

    def __init__(self):
        """
        self.table_add corresponds to the set of table entries to be added.
        self.table_add_match_only is the same as self.table_add but
        with action_params cleared - used for in-place updates.
        """
        self.table_add = set()
        self.table_add_match_only = set()


class SmartSwitch:
    """
    Collects table entries that should be added but doesn't forward them
    to the switch yet. Only after calling apply() the entries are
    compared to what previously has been written to the switch,
    and only the difference is actually forwarded.
    """

    def __init__(self, api, name: str):
        self.api = api
        self.name = name

        self.old_config = Configuration()
        self.new_config = Configuration()

    def table_add(self, table_name, action_name, match_keys, action_params):
        """Collect a table entry to be added."""
        self.new_config.table_add.add(TableAdd(
            table_name=table_name,
            action_name=action_name,
            match_keys=tuple(match_keys),
            action_params=tuple(action_params),
        ))

        self.new_config.table_add_match_only.add(TableAdd(
            table_name=table_name,
            action_name=action_name,
            match_keys=tuple(match_keys),
            action_params=(),
        ))

    def counter_read(self, counter_name: str, index: int):
        """Read the counter value"""
        return self.api.counter_read(counter_name, index)

    def apply_table_add(self):
        """Compute the difference between the old and new configuration and forward it to the switch."""
        adds: typing.Set[TableAdd] = set(self.new_config.table_add) - set(self.old_config.table_add)
        removes: typing.Set[TableAdd] = set(self.old_config.table_add_match_only) - set(
            self.new_config.table_add_match_only)

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
        """Write a register value to the switch immediately."""
        logging.info(f'[register_mod][{self.name}] setting {register_name}[{index}] -> {value}')
        self.api.register_write(
            register_name=register_name,
            index=index,
            value=value,
        )

    def apply(self):
        """Apply the difference between the old and new configuration to the switch and start a new configuration."""
        self.apply_table_add()
        self.old_config = self.new_config
        self.new_config = Configuration()
