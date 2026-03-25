import getpass
import ipaddress
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.theme import Theme

import nornir_inv
from nornir_tasks import NornirTask

# ----------------------------------------------------------------------------
# User defined hardcoded variables and env vars (fallback to defaults)
# ----------------------------------------------------------------------------
# Location of the nornir inventory file
inventory = (
    Path(os.getenv("BASE_DIRECTORY") or Path(__file__).parent.resolve()) / "inventory"
)
# Location where the ACL variable file is stored, by default current directory
BASE_DIRECTORY = Path(os.getenv("BASE_DIRECTORY") or Path(__file__).parent.resolve())
# Default device username (-u >> env_var >> admin)
DEVICE_USER = os.environ.get("DEVICE_USER", "admin")
# Default device password (env_var >> get_pass)
DEVICE_PWORD = os.environ.get("DEVICE_PWORD", None)
# Default SSH ACL name (env_var >> SSH_ACCESS)
SSH_ACLNAME = os.environ.get("SSH_ACLNAME", "SSH_ACCESS")
# Default SSH ACL name (env_var >> SNMP_ACCESS)
SNMP_ACLNAME = os.environ.get("SNMP_ACLNAME", "SNMP_ACCESS")
# Default source security zone (env_var >> mgmt)
SEC_ZONE = os.environ.get("SEC_ZONE", "mgmt")


# ----------------------------------------------------------------------------
# Addition of input arguments and Failfast methods used to stop script early if an error
# ----------------------------------------------------------------------------
class InputValidate:
    def __init__(self, directory: Path, rc: Console) -> None:
        self.rc = rc
        self.directory = directory

    # ----------------------------------------------------------------------------
    # ASSERT: Functions used by the 'validate_file' method to validate the file contents format
    # ----------------------------------------------------------------------------
    # IPv4: Asserts that it is a valid IP address or network address (correct mask and within it)
    def _assert_ipv4(self, errors: list, variable: str, error_message: str) -> None:
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
    def _assert_ace(self, each_ace: dict[str, str]) -> list:
        ace_errors: list = []
        if not isinstance(each_ace, dict):
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
                    ace_errors,
                    ip_addr,
                    f" -[i]'{ip_addr}'[/i] is not a valid IP address",
                )
        else:
            ace_errors.append(
                f" -[i]'{list(each_ace.keys())[0]}'[/i] is not valid, options are 'remark', 'permit' or 'deny'"
            )
        return ace_errors

    # ACL: Ensures each ACL has a name and ACE is a list
    def _assert_acl(self, acl_type: str, acl: list[dict[str, str]]) -> dict[str, Any]:
        acl_errors = defaultdict(list)
        try:
            assert isinstance(acl, list)
            for each_ace in acl:
                acl_errors[acl_type].extend(self._assert_ace(each_ace))
            return acl_errors
        except Exception:
            self.rc.print(
                f":x: [b]AclError:[/b] ACL '{acl_type}' is dictionary is not a list"
            )
            return acl_errors

    # ----------------------------------------------------------------------------
    # 1. Processes run time flags and arguments, adds these additional args to those from nornir_inv.py.
    # ----------------------------------------------------------------------------
    def add_arg_parser(self, nr_inv_args: nornir_inv.BuildInventory) -> dict[str, Any]:
        args = nr_inv_args.add_arg_parser()
        args.add_argument(
            "-u",
            "--username",
            help="Device username, overrides environment variables and hardcoded script variable",
        )
        args.add_argument(
            "-f",
            "--filename",
            nargs=1,
            help="Name of the Yaml file containing ACL variables",
        )
        args.add_argument(
            "-a",
            "--apply",
            action="store_false",
            help="Apply changes to devices, by default only 'dry run'",
        )
        return vars(args.parse_args())

    # ----------------------------------------------------------------------------
    # 2a. ACL_VAL: Validates the formatting inside the YAML variable input file is correct
    # ----------------------------------------------------------------------------
    def validate_file(self, filename: str) -> dict[str, Any]:
        errors = {}
        # Checks that the input file exists, if so loads it
        acl_variable_file = self._assert_file_exist(filename)
        with open(acl_variable_file) as file_content:
            acls = yaml.load(file_content, Loader=yaml.FullLoader)
        # Checks file contents, ensures ACL is a dict has ssh and/or snmp key
        try:
            assert isinstance(acls, dict), (
                f"[i]'{filename}'[/i] contents are not a dictionary"
            )
            assert {"ssh", "snmp"} & set(acls), (
                f"Must have either [i]'ssh'[/i] or [i]'snmp'[/i] dict key in '{filename}'"
            )
            # Verifies ACL contents
            for acl_type, acl in acls.items():
                if acl_type in ("ssh", "snmp"):
                    errors.update(self._assert_acl(acl_type, acl))
        except Exception as e:
            self.rc.print(f":x: [b]AclError:[/b] {e}")
            exit(1)
        # Print any ACE errors and exit
        for acl_type, err in errors.items():
            exit_script = False
            if len(err) != 0:
                self.rc.print(
                    f":x: [b]AceError:[/b] [i]'{acl_type}'[/i] has the following ACE errors:"
                )
                for each_err in err:
                    self.rc.print(each_err)
        if exit_script:
            sys.exit(1)
        else:
            return acls

    # ----------------------------------------------------------------------------
    # 2b. ACL_FMT: Adds ACL names to each ACL type and creates extra vars wcard and mask (created from prefix)
    # ----------------------------------------------------------------------------
    def format_acl_vars(
        self, acl_vars: dict[str, list[dict[str, str]]]
    ) -> dict[str, Any]:
        acl_name = []
        mask_acl_vars: dict[str, list] = dict(acl=[])
        wcard_acl_vars: dict[str, list] = dict(acl=[])
        pfx_acl_vars: dict[str, list] = dict(acl=[])
        for acl_type, each_acl in acl_vars.items():
            # Set ACL name, no need to catch errors as wouldnt get this far if ssh ro snmp didn't exist
            if acl_type == "ssh":
                aclname = SSH_ACLNAME
            elif acl_type == "snmp":
                aclname = SNMP_ACLNAME
            acl_name.append(aclname)
            mask_ace = []  # uses subnet rather than prefix
            wcard_ace = []  # uses wildcards rather than prefix
            for each_ace in each_acl:
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
                    except Exception as e:
                        print(f"!! What is this exception '{e}' in 'format_acl_vars'")
                        breakpoint()
                        mask_ace.append(each_ace)
                        wcard_ace.append(each_ace)
            mask_acl_vars["acl"].append(dict(name=aclname, type=acl_type, ace=mask_ace))
            wcard_acl_vars["acl"].append(
                dict(name=aclname, type=acl_type, ace=wcard_ace)
            )
            pfx_acl_vars["acl"].append(dict(name=aclname, type=acl_type, ace=each_acl))
        return dict(
            name=acl_name,
            zone=SEC_ZONE,
            wcard=wcard_acl_vars,
            mask=mask_acl_vars,
            prefix=pfx_acl_vars,
        )

    # ----------------------------------------------------------------------------
    # 3. USER_PASS: Gathers username/password checking various input options.
    # ----------------------------------------------------------------------------
    def get_user_pass(self, args: dict[str, Any]) -> dict[str, Any]:
        # USER: Check for username in this order: args (-u), env var, default_username (admin)
        device = {}
        if args.get("username") is not None:
            device["user"] = args["username"]
        else:
            device["user"] = DEVICE_USER
        # PWORD: Check for password in this order: env var, prompt
        if os.environ.get("DEVICE_PWORD") is not None:
            device["pword"] = os.environ["DEVICE_PWORD"]
        else:
            device["pword"] = getpass.getpass("Enter device password: ")
        return device


# ----------------------------------------------------------------------------
# ENGINE: Runs the methods from the script
# ----------------------------------------------------------------------------
def main() -> None:
    # Setup inventory and rich print
    build_inv = nornir_inv.BuildInventory()  # parsers in nor_inv script
    my_theme = {"repr.ipv4": "none", "repr.number": "none", "repr.call": "none"}
    rc = Console(theme=Theme(my_theme))

    # Initialise the Validate Class for user args and validating input file
    input_val = InputValidate(BASE_DIRECTORY, rc)
    # 1. Gets info input by user by calling local method that calls remote nor_inv method
    args = input_val.add_arg_parser(build_inv)

    # Loads inventory and filters it based on the runtime flags
    nr_inv = build_inv.load_inventory(
        os.path.join(inventory, "hosts.yml"),
        os.path.join(inventory, "groups.yml"),
    )
    nr_inv = build_inv.filter_inventory(args, nr_inv)

    # 2a. Validate
    if args.get("filename") is None:
        rc.print(
            f":x: [b]ArgError:[/b] No input filename has been defined, use the runtime argument [i]-f <filename>[/i]"
        )
        sys.exit(1)
    else:
        acls = input_val.validate_file(args["filename"][0])
    # 2b. Formats ACL dict to support prefix, wcard and mask (due to differing OS types)
    acl_vars = input_val.format_acl_vars(acls)

    # 3. Get device credentials based on runtime flags and env vars, then adds these creds to inventory defaults
    device = input_val.get_user_pass(args)
    nr_inv = build_inv.inventory_defaults(nr_inv, device)

    # 4. Render the config and adds as a group_var
    nr_task = NornirTask()
    nr_inv = nr_task.generate_acl_engine(nr_inv, acl_vars)

    # 5. Apply the config
    nr_task.config_engine(nr_inv, args.get("apply"))


if __name__ == "__main__":
    main()
