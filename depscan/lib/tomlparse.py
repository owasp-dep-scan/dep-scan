"""
Module for parsing command line arguments and TOML configuration files.

This module provides a class, `ArgumentParser`, which extends the functionality
of `argparse.ArgumentParser` by allowing users to specify default values for
arguments in a TOML file, in addition to the command line.
"""
# Based on https://github.com/florianmahner/tomlparse/blob/main/tomlparse/argparse.py
# MIT license
import argparse
import os
from typing import Any, Dict, List, MutableMapping, Optional, Tuple

try:
    import tomllib
except ImportError:
    import tomli as tomllib


class ArgumentParser(argparse.ArgumentParser):
    """A wrapper of the argparse.ArgumentParser class that adds the ability to
    specify the values for arguments using a TOML file.

    This class extends the functionality of the standard argparse.ArgumentParser by allowing
    users to specify default values for arguments in a TOML file, in addition to the command line.
    We can use all functionalities from the argument parser as usual:

    Example:
        >>> from depscan.lib.tomlparse import argparse
        >>> parser = argparse.ArgumentParser(description='Example argparse-toml app')
        >>> parser.add_argument('--foo', type=int, help='An example argument')
        >>> args = parser.parse_args()

    The above code will work as with the standard argparse.ArgumentParser class. We can also
    specify the default values for the arguments in a TOML file. For this the TOML ArgumentParser
    has one additional argument: `--config`. The `--config` argument is used
    to specify the path to the TOML file.

    We have the following hierarchy of arguments:
        1. Arguments passed through the command line are selected over TOML
           arguments, even if both are passed
        2. Arguments from the TOML file are preferred over the default arguments
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        default_config = os.path.join(os.getcwd(), ".config", "depscan.toml")
        self.add_argument("--config", help="Path to the configuration file. Default: $PWD/.config/depscan.toml",
                          default=os.getenv("DEPSCAN_CONFIG", default_config))

    def extract_args(
        self, args: Optional[List[str]] = None, namespace: Optional[object] = None
    ) -> Tuple[argparse.Namespace, argparse.Namespace]:
        """Find the default arguments of the argument parser if any and the
        ones that are passed through the command line"""
        default_args = super().parse_args([])
        cmdl_args = super().parse_args(args, namespace)

        return default_args, cmdl_args

    def find_changed_args(
        self, default_args: argparse.Namespace, sys_args: argparse.Namespace
    ) -> List[str]:
        """Find the arguments that have been changed from the command
        line to replace the .toml arguments"""
        default_dict = vars(default_args)
        sys_dict = vars(sys_args)
        changed_dict = []
        for key, value in default_dict.items():
            sys_value = sys_dict[key]
            if sys_value != value:
                changed_dict.append(key)
        return changed_dict

    def load_toml(self, path: str) -> MutableMapping[str, Any]:
        try:
            with open(path, "rb") as f:
                config = tomllib.load(f)
        except FileNotFoundError:
            self.error(f'Configuration file "{path}" doesn\'t exist')
        return config

    def remove_nested_keys(self, dictionary: Dict[str, Any]) -> Dict[str, Any]:
        new_dict = {}
        for key, value in dictionary.items():
            if not isinstance(value, dict):
                new_dict[key] = value
        return new_dict

    def parse_args(
        self, args: Optional[List[str]] = None, namespace: Optional[object] = None
    ) -> argparse.Namespace:
        """Parse the arguments from the command line and the TOML file
        and return the updated arguments. Same functionality as the
        `argparse.ArgumentParser.parse_args` method."""
        default_args, sys_args = self.extract_args(args, namespace)
        config = sys_args.config
        # These are the default arguments options updated by the command line
        if not config or not os.path.exists(config):
            return sys_args

        # If a config file is passed, update the cmdl args with the config file unless
        # the argument is already specified in the command line
        toml_data = self.load_toml(config)
        changed_args = self.find_changed_args(default_args, sys_args)
        toml_args = self.remove_nested_keys(toml_data)

        # Replaced unchanged command line arguments with arguments from
        # the TOML file.
        for key, value in toml_args.items():
            if key not in changed_args:
                setattr(sys_args, key, value)
                # Support both hyphen and underscore representations
                setattr(sys_args, key.replace("-", "_"), value)

        return sys_args
