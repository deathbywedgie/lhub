import json
import os
import shutil
from copy import deepcopy
from pathlib import Path

import time

from lhub.common.dicts_and_lists import sort_dicts_and_lists
from lhub.common.shell import query_yes_no

# Static/configurable vars
DEFAULT_CONFIG_DIR = "~/.logichub"
DEFAULT_CONFIG_FILE_NAME = "servers.json"


class ConfigFile:
    __config_dir = None
    __config_file_name = DEFAULT_CONFIG_FILE_NAME
    __config_schema = {
        'hostname': {
            'type': str,
            'required': True,
        },
        'api_key': {
            'type': str,
            'required': True,
        },
        'verify_ssl': {
            'type': bool,
            'default': 'yes',
        },
        'aliases': {
            'type': list,
            'required': False,
        }
    }
    instance_name = None

    def __init__(self, config_dir=None, config_file_name=None):
        self.config_dir = config_dir
        if config_file_name and config_file_name.strip():
            self.config_file_name = config_file_name
        self.__verify_config()

    @property
    def config_dir(self):
        if not self.__config_dir:
            self.config_dir = DEFAULT_CONFIG_DIR
        return self.__config_dir

    @config_dir.setter
    def config_dir(self, val: str):
        if not val or not val.strip():
            val = DEFAULT_CONFIG_DIR
        if '~' in val:
            val = os.path.expanduser(val)
        self.__config_dir = val
        # Ensure that the path to the config file exists
        Path(self.__config_dir).mkdir(parents=True, exist_ok=True)

    @property
    def config_file_name(self):
        return self.__config_file_name

    @config_file_name.setter
    def config_file_name(self, val: str):
        assert val and val.strip(), "Config file name cannot be blank"
        self.__config_file_name = val.strip()
        if not os.path.exists(self.config_file_path):
            self.__update_config_file({})

    @property
    def config_file_path(self):
        return os.path.join(self.config_dir, self.config_file_name)

    def __update_config_file(self, new_config):
        if not new_config:
            new_config = {}

        backup_file_name = f"{self.config_file_path}.{time.strftime('%Y-%m-%d')}.bak"
        if not os.path.exists(backup_file_name):
            shutil.copyfile(self.config_file_path, backup_file_name)

        with open(self.config_file_path, 'w') as _f:
            _f.write(json.dumps(sort_dicts_and_lists(new_config), indent=2))

    def __verify_config(self):
        with open(self.config_file_path, "r") as _f:
            config = _f.read()
        self.config = sort_dicts_and_lists(json.loads(config))

    def get_instance_config(self, name):
        assert name and name.strip(), "Instance name cannot be blank"
        name = name.strip()
        starting_config = deepcopy(self.config)
        instance_config = self.config.get(name, {})
        if not instance_config:
            if not query_yes_no(f"No config found for instance name \"{name}.\"\nAdd new config? "):
                print('Aborted.')
                exit(1)

        if not instance_config.get('aliases'):
            # ToDo Add an option for this eventually
            instance_config['aliases'] = []

        for k, v in self.__config_schema.items():
            if not instance_config.get(k):
                if v['type'] is str:
                    while not instance_config.get(k):
                        value = input(f'\nEnter value for {k}: ')
                        instance_config[k] = value.strip()
                        if instance_config[k] or v.get('required'):
                            break
                elif v['type'] is bool:
                    instance_config[k] = query_yes_no(f'\nValue for {k}? ', default=v.get('default'))
                # elif v['type'] is list:
                #     if v.get('required') is not True:
                #         if query_yes_no(f'\nAdd Value for {k}? ', default=v.get('default'))

        self.config[name] = instance_config
        if starting_config != self.config:
            self.__update_config_file(self.config)

        return instance_config

    def delete_instance_config(self, instance_name):
        _ = self.config.pop(instance_name)
