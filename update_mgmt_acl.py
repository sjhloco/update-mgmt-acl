import ipaddress
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List

import yaml
from rich.console import Console
from rich.theme import Theme

from nornir_orion import orion_inv
from nornir_tasks import NornirTask

# ----------------------------------------------------------------------------
# User defined Variables
# ----------------------------------------------------------------------------
# ORION ON/OFF: Use to toggle off orion and use static inventory of inventory/hosts.yml and inventory/groups.yml
no_orion = True
# Location where the ACL variable file is stored, by default current directory
directory = os.path.dirname(__file__)


# ----------------------------------------------------------------------------
# 1. Addition of input arguments and Failfast methods used to stop script early if an error
# ----------------------------------------------------------------------------
class InputValidate:
    def __init__(self, directory: str) -> Dict[str, Any]:
        my_theme = {"repr.ipv4": "none", "repr.number": "none", "repr.call": "none"}
        self.rc = Console(theme=Theme(my_theme))
        self.directory = directory

    # ----------------------------------------------------------------------------
    # ASSERT: Functions used by the 'validate_file' method to validate the file contents format
    # ----------------------------------------------------------------------------
    # IPv4: Asserts that it is a valid IP address or network address (correct mask and within it)
    def _assert_ipv4(
        self, errors: List[str], variable: str, error_message: List[str]
    ) -> None:
        try:
            ipaddress.IPv4Interface(variable)
        except ipaddress.AddressValueError:
            errors.append(error_message)
        except ipaddress.NetmaskValueError:
            errors.append(error_message)

    # FILE: Checks that the input file exists
    def _assert_file_exist(self, acl_file: str) -> str:
        if os.path.exists(acl_file):
            acl_variable_file = acl_file
        elif not os.path.exists(acl_file):
            acl_variable_file = os.path.join(self.directory, acl_file)
            if not os.path.exists(acl_variable_file):
                self.rc.print(
                    f":x: [red]FileError[/red]: Cannot find file [i]'{acl_file}'[/i] or [i]'{acl_variable_file}'[/i], check that it exists"
                )
            sys.exit(1)
        return acl_variable_file

    # ACE: Creates a list of errors from iteration through each ACE
    def _assert_ace(self, each_ace: Dict[str, Any]) -> List:
        ace_errors = []
        if isinstance(each_ace, dict) == False:
            ace_errors.append(f"-ACE entry [i]'{each_ace}'[/i] is not a dictionary")
        # Dont check remarks
        elif list(each_ace.keys())[0] == "remark":
            pass
        elif list(each_ace.keys())[0] == "permit" or list(each_ace.keys())[0] == "deny":
            # Only non IP allowed is any
            if list(each_ace.values())[0] == "any":
                pass
            else:
                ip_addr = list(each_ace.values())[0]
                self._assert_ipv4(
                    ace_errors, ip_addr, f"-[i]{ip_addr}[/i] is not a valid IP address"
                )
        else:
            ace_errors.append(
                f"-[i]{list(each_ace.keys())[0]}[/i] is not valid, options are 'remark', 'permit' or 'deny'"
            )
        return ace_errors

    # ACL: Ensures each ACL has a name and ACE is a list
    def _assert_acl(self, each_acl: Dict[str, Any]) -> Dict[str, Any]:
        acl_errors = defaultdict(list)
        try:
            acl_name = each_acl.get("name", "")
            assert isinstance(each_acl["name"], str)
            assert isinstance(each_acl["ace"], list)
            for each_ace in each_acl["ace"]:
                acl_errors[acl_name].extend(self._assert_ace(each_ace))
            return acl_errors
        except Exception:
            self.rc.print(
                f":x: [b]AclError:[/b] ACL name is missing or the {acl_name} ACE dictionary is not a list"
            )
            return acl_errors

    # ----------------------------------------------------------------------------
    # 1a. Adds additional arguments to the OrionInventory parser arguments
    # ----------------------------------------------------------------------------
    def add_arg_parser(self, orion) -> Dict[str, Any]:
        args = orion.add_arg_parser()

        args.add_argument(
            "-f", "--filename", help="Name of the Yaml file containing ACL variables"
        )
        args.add_argument(
            "-a",
            "--apply",
            action="store_false",
            help="Apply changes to devices, by default only 'dry run'",
        )
        return args

    # ----------------------------------------------------------------------------
    # 1b. ACL_VAL: Validates the formatting inside the YAML variable input file is correct
    # ----------------------------------------------------------------------------
    def validate_file(self, args) -> Dict[str, Any]:
        errors = {}
        # Checks that the input file exists, if so loads it
        acl_variable_file = self._assert_file_exist(args["filename"])
        with open(acl_variable_file, "r") as file_content:
            acl_vars = yaml.load(file_content, Loader=yaml.FullLoader)
        # Checks file contents
        try:  # Ensures ACL dict exists and is a list
            assert isinstance(acl_vars["acl"], list)
            for each_acl in acl_vars["acl"]:
                errors.update(self._assert_acl(each_acl))
        except Exception:
            self.rc.print(
                ":x: [b]AclError:[/b] Top level dict [i]'acl'[/i] does not exist or is not a list"
            )
        # Print any ACE errors and exit
        for acl_name, err in errors.items():
            if len(err) != 0:
                self.rc.print(
                    f":x: [b]AceError:[/b] [i]'{acl_name}'[/i] has the following ACE errors:"
                )
                for each_err in err:
                    self.rc.print(each_err)
                sys.exit(1)

        return acl_vars

    # ----------------------------------------------------------------------------
    # 2. ACL_FMT: Creates show and delete cmds as well as VARs for wildcard ACLs (convert prefix to wildcard)
    # ----------------------------------------------------------------------------
    def format_input_vars(self, acl_vars: Dict[str, Any]) -> Dict[str, Any]:
        acl_name: List = []
        mask_acl_vars: Dict[str, List] = dict(acl=[])
        wcard_acl_vars: Dict[str, List] = dict(acl=[])

        for each_acl in acl_vars["acl"]:
            acl_name.append(each_acl["name"])
            mask_ace = []  # uses subnet rather than prefix
            wcard_ace = []  # uses wildcards rather than prefix
            for each_ace in each_acl["ace"]:
                if list(each_ace.keys())[0] == "remark":
                    wcard_ace.append(each_ace)
                    mask_ace.append(each_ace)
                else:
                    try:
                        # 2a. If no mask is defined this line makes it a /32
                        each_ace[list(each_ace.keys())[0]] = str(
                            ipaddress.IPv4Interface(list(each_ace.values())[0])
                        )
                        # 2b. Prepare IP, MASK and WCARD to then build acl_vars from
                        ip_mask: str = ipaddress.IPv4Interface(
                            list(each_ace.values())[0]
                        ).with_netmask
                        ip_wcard: str = ipaddress.IPv4Interface(
                            list(each_ace.values())[0]
                        ).with_hostmask
                        ip: str = ip_mask.split("/")[0]
                        mask: str = ip_mask.split("/")[1]
                        wcard: str = ip_wcard.split("/")[1]
                        # 2c. Formats the subnet mask
                        if mask == "255.255.255.255":
                            mask_ace.append({list(each_ace.keys())[0]: ip + " " + mask})
                            wcard_ace.append({list(each_ace.keys())[0]: "host " + ip})
                        else:
                            mask_ace.append({list(each_ace.keys())[0]: ip + " " + mask})
                            wcard_ace.append(
                                {list(each_ace.keys())[0]: ip + " " + wcard}
                            )
                    except:
                        mask_ace.append(each_ace)
                        wcard_ace.append(each_ace)
            mask_acl_vars["acl"].append(dict(name=each_acl["name"], ace=mask_ace))
            wcard_acl_vars["acl"].append(dict(name=each_acl["name"], ace=wcard_ace))
        return dict(
            name=acl_name,
            wcard=wcard_acl_vars,
            mask=mask_acl_vars,
            prefix=acl_vars,
        )


# ----------------------------------------------------------------------------
# ENGINE: Runs the methods from the script
# ----------------------------------------------------------------------------
def main(inv_settings: str, no_orion: bool = no_orion) -> None:
    orion = orion_inv.OrionInventory()
    input_val = InputValidate(directory)
    inv_validate = orion_inv.LoadValInventorySettings()

    # 1. Gets info input by user by calling local method that calls remote method
    tmp_args = input_val.add_arg_parser(orion)
    args = vars(tmp_args.parse_args())
    # 2. Load and validates the orion inventory settings, adds any runtime usernames
    inv_settings = inv_validate.load_inv_settings(args, inv_settings)

    # 3. Initialise the Validate Class to check input file
    if args.get("filename") != None:
        acl_vars = input_val.validate_file(args)
        acl = input_val.format_input_vars(acl_vars)

    # 3a. Tests username and password against orion
    if no_orion == False:
        orion.test_npm_creds(inv_settings["npm"])
        # 3b. Initialise Nornir inventory
        nr_inv = orion.load_inventory(inv_settings["npm"], inv_settings["groups"])
    # 3c. Uses static inventory instead of Orion
    elif no_orion == True:
        nr_inv = orion.load_static_inventory(
            "inventory/hosts.yml", "inventory/groups.yml"
        )
    # 4. Filter the inventory based on the runtime flags
    nr_inv = orion.filter_inventory(args, nr_inv)
    # 5. add username and password to defaults
    nr_inv = orion.inventory_defaults(nr_inv, inv_settings["device"])

    # 6. Render the config and adds as a group_var
    nr_task = NornirTask()
    nr_inv = nr_task.generate_acl_engine(nr_inv, acl)

    # 7. Apply the config
    nr_task.config_engine(nr_inv, args.get("apply"))


if __name__ == "__main__":
    main("inv_settings.yml")
