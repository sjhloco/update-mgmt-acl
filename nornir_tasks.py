import difflib
import ipaddress
import logging
import socket
import sys
from typing import Any, Dict, List

from nornir.core.filter import F
from nornir.core.task import Result, Task
from nornir_jinja2.plugins.tasks import template_file
from nornir_netmiko.tasks import netmiko_send_command, netmiko_send_config
from nornir_rich.functions import print_result
from rich.console import Console
from rich.theme import Theme

# from nornir_validate.nr_val import validate_task


class NornirTask:
    def __init__(self):
        my_theme = {"repr.ipv4": "none", "repr.number": "none", "repr.call": "none"}
        self.rc = Console(theme=Theme(my_theme))

    # ----------------------------------------------------------------------------
    # TMPL: Nornir task to renders the template and ACL_VAR input to produce the config
    # ----------------------------------------------------------------------------
    def template_config(self, task: Task, os_type: str, acl: Dict[str, Any]) -> Result:
        task.run(
            task=template_file,
            name=f"Generating {os_type.upper()} configuration",
            template="cfg_acl_tmpl.j2",
            path="templates/",
            os_type=os_type,
            acl_vars=acl,
        )

    # ----------------------------------------------------------------------------
    # BACKUP: Gets backup of ACLs, summary message rather than the result is printed
    # ----------------------------------------------------------------------------
    def backup_acl(self, task: Task, show_cmd: List) -> str:
        for each_cmd in show_cmd:
            task.run(
                task=netmiko_send_command,
                command_string=each_cmd,
                severity_level=logging.DEBUG,
            )
        return "Backing up current ACL configurations"

    # ----------------------------------------------------------------------------
    # FORMAT_CFG: Formats config cmds as well as the ASA show cmds
    # ----------------------------------------------------------------------------
    # SHOW_DEL: Creates the show and delete ACLs (except for ASA del as needs to be done once got backup)
    def show_del_cmd(self, os_type, acl_name):
        show_cmds, del_cmds = ([] for i in range(2))
        if os_type == "asa":
            show_cmds = ["show run ssh", "show run http"]
            del_cmds = None
        elif os_type == "ios/iosxe":
            for each_name in acl_name:
                show_cmds.append(f"show run | sec access-list extended {each_name}_")
                del_cmds.append(f"no ip access-list extended {each_name}")
        elif os_type == "nxos":
            for each_name in acl_name:
                show_cmds.append(f"show run | sec 'ip access-list {each_name}'")
                del_cmds.append(f"no ip access-list {each_name}")
        return {"show": show_cmds, "del": del_cmds}

    # FMT_ASA: Removes all now access lines from the SSH and HTTP cmds
    def format_asa(self, backup_acl_config):
        tmp_backup_acl_config = []
        for each_type in backup_acl_config:
            tmp_type = []
            for each_line in each_type.splitlines():
                try:
                    ipaddress.IPv4Interface(each_line.split()[1])
                    tmp_type.append(each_line)
                except:
                    pass
            tmp_backup_acl_config.append("\n".join(tmp_type))
        return tmp_backup_acl_config

    # ASA: Creates delete SSH and HTTP cmds for ASAs as doesn't use ACLs
    def asa_del(self, config):
        del_cmds = []
        for ssh_or_http in config:
            for each_cmd in ssh_or_http.splitlines():
                del_cmds.append("no " + each_cmd)
        return del_cmds

    # ACL: Converts ACLs into list of commands
    def list_of_cmds(self, acl_config):
        cmds = []
        for each_acl in acl_config:
            cmds.extend(each_acl.splitlines())
        return cmds

    # CFG: Joins delete cmds to config or backup_config ready to apply
    def format_config(self, task, config1, config2):
        # ASA needs to create delete command list from backup config
        if task.host["delete_cmd"] == None:
            task.host["delete_cmd"] = self.asa_del(config1).copy()
        config = task.host["delete_cmd"].copy()
        config.extend(self.list_of_cmds(config2))
        return config

    # ----------------------------------------------------------------------------
    # GENERATE: Creates config, show cmds, delete cmds and adds validate input data
    # ----------------------------------------------------------------------------
    def generate_acl_config(
        self,
        nr_inv: "Nornir",
        os_type: str,
        acl_name: str,
        acl: Dict[str, Any],
        val_acl: Dict[str, Any],
    ) -> None:
        nr_inv = nr_inv.filter(F(name=list(nr_inv.inventory.hosts.keys())[0]))
        config = nr_inv.run(
            task=self.template_config,
            os_type=os_type,
            acl=acl,
        )
        # Prints the per-group config (what was rendered by template)
        print_result(config, vars=["result"])
        # Creates host_vars for config (list of each ACL) and commands for show and delete ACLs
        for grp in os_type.split("/"):
            nr_inv.inventory.groups[grp]["config"] = (
                config[list(config.keys())[0]][1].result.rstrip().split("\n\n")
            )
            cmds = self.show_del_cmd(os_type, acl_name)
            nr_inv.inventory.groups[grp]["show_cmd"] = cmds["show"]
            nr_inv.inventory.groups[grp]["delete_cmd"] = cmds["del"]
            # VAL: Adds prefix ACL to be used for the nornir-validate file
            nr_inv.inventory.groups[grp]["acl_val"] = {"groups": {grp: val_acl}}

    # ----------------------------------------------------------------------------
    # DIFF: Finds the differences between current device ACLs and templated ACLs (- is removed, + is added)
    # ----------------------------------------------------------------------------
    def get_difference(self, task: Task, sw_acl: List, tmpl_acl: List) -> Result:
        acl_diff: List = []

        for each_sw_acl, each_tmpl_acl in zip(sw_acl, tmpl_acl):
            # Creates a new ACL with just the ACL name to hold the differences
            if "access-list" in each_tmpl_acl.splitlines()[0]:
                tmp_diff_list = [each_tmpl_acl.splitlines()[0]]
            else:  # ASAs dont have ACL name
                tmp_diff_list = [""]
            # Creates a list of common elements between and differences between the ACLs (replace removes '  ' after deny in ACLs)
            diff = difflib.ndiff(
                each_sw_acl.lstrip()
                .replace("   ", " ")
                .replace(" \n", "\n")
                .splitlines(),
                each_tmpl_acl.lstrip().splitlines(),
            )
            diff = list(diff)
            # Removes duplicate if ACL does not already exist
            if "+ " + "".join(tmp_diff_list) == diff[0]:
                del tmp_diff_list[0]
            # Only takes the differences (- or +, separate loops so can group them) and removes new lines (n)
            for each_diff in diff:
                if each_diff.startswith("- "):
                    tmp_diff_list.append(each_diff.replace("\n", ""))
            for each_diff in diff:
                if each_diff.startswith("+ "):
                    tmp_diff_list.append(each_diff.replace("\n", ""))
            if len(tmp_diff_list) != 1:
                acl_diff.append(("\n").join(tmp_diff_list) + "\n")
        if len(acl_diff) == 0:
            return Result(
                host=task.host, result="✅  No differences between configurations"
            )
        elif len(acl_diff) != 0:
            return Result(host=task.host, result="\n".join(acl_diff))

    # ----------------------------------------------------------------------------
    # APPLY: Applies config, possible rollback is dependant on if it fails.
    # ----------------------------------------------------------------------------
    def apply_acl(self, task: Task, acl_config: List, backup_config: List) -> Result:
        # Manually open the connection, all tasks are run under this open connection so can rollback in same conn
        task.run(
            task=netmiko_send_config,
            dry_run=False,
            config_commands=acl_config,
            severity_level=logging.DEBUG,
        )
        # Test if can still connect over SSH, if cant rollback the change
        try:
            test_ssh = socket.socket()
            test_ssh.connect((task.host.hostname, 22))
            return Result(
                host=task.host, changed=True, result="✅  ACLs successfully updated"
            )
        except:
            task.run(
                task=netmiko_send_config,
                dry_run=False,
                config_commands=backup_config,
                severity_level=logging.DEBUG,
            )
            return Result(
                host=task.host,
                failed=True,
                result="❌  ACL update rolled back as it broke SSH access",
            )

    # ----------------------------------------------------------------------------
    # 1. TMPL_ENGINE: Engine to create device configs from templates
    # ----------------------------------------------------------------------------
    def generate_acl_engine(self, nr_inv: "Nornir", acl: Dict[str, Any]) -> "Nornir":
        # Get all the members (hosts) of each group
        iosxe_nr = nr_inv.filter(F(groups__any=["ios", "iosxe"]))
        nxos_nr = nr_inv.filter(F(groups__any=["nxos"]))
        asa_nr = nr_inv.filter(F(groups__any=["asa"]))

        # 1a. IOS: Create config (runs against first host in group), print to screen and assign as a group_var
        if len(iosxe_nr.inventory.hosts) != 0:
            self.generate_acl_config(
                iosxe_nr, "ios/iosxe", acl["name"], acl["wcard"], acl["prefix"]
            )
        # 1b. NXOS: Create config (runs against first host in group), print to screen and assign as a group_var
        if len(nxos_nr.inventory.hosts) != 0:
            self.generate_acl_config(
                nxos_nr, "nxos", acl["name"], acl["prefix"], acl["prefix"]
            )
        # 1c. ASA: Create config (runs against first host in group), print to screen and assign as a group_var
        if len(asa_nr.inventory.hosts) != 0:
            self.generate_acl_config(
                asa_nr, "asa", acl["name"], acl["mask"], acl["prefix"]
            )
        # 1d. FAILFAST: If no config generated is nothing to configure on devices
        if (
            len(iosxe_nr.inventory.hosts) == 0
            and len(nxos_nr.inventory.hosts) == 0
            and len(asa_nr.inventory.hosts) == 0
        ):
            self.rc.print(
                ":x: Error: No config generated as are no objects in groups [i]ios, iosxe, nxos[/i] or [i]asa[/i]"
            )
            sys.exit(1)
        else:
            return nr_inv

    # ----------------------------------------------------------------------------
    # 2. TASK_ENGINE: Engine to call and run nornir sub-tasks
    # ----------------------------------------------------------------------------
    def task_engine(self, task: Task, dry_run: bool) -> Result:
        # 2a. BACKUP: Gathers a backup of the current ACL configuration (ASA doesn't use ACLs so change cmd)
        result = task.run(task=self.backup_acl, show_cmd=task.host["show_cmd"])
        # Creates a list with each element being an ACL
        backup_acl_config = []
        for each_acl in result[1:]:
            backup_acl_config.append(each_acl.result)
        # ASA needs to remove non access based info from ssh and http cmds
        if task.host.dict()["groups"][0] == "asa":
            backup_acl_config = self.format_asa(backup_acl_config)

        # 2b. DIFF: Splits into a list of ACLs and uses them to gather differences
        acl_diff = task.run(
            name="ACL differences (- remove, + add)",
            task=self.get_difference,
            sw_acl=backup_acl_config,
            tmpl_acl=task.host["config"],
        )

        # 2c. APPLY: If Not a dry run and are differences apply the config
        if (
            dry_run == False
            and acl_diff.result != "✅  No differences between configurations"
        ):
            # Adds delete cmds before acl and backup cfg (ASA changes delete cmds as no ACLs)
            acl_config = self.format_config(
                task, backup_acl_config, task.host["config"]
            )
            backup_config = self.format_config(
                task, task.host["config"], backup_acl_config
            )
            task.run(
                task=self.apply_acl,
                acl_config=acl_config,
                backup_config=backup_config,
            )
            # 2d. VALIDATE: Runs nornir-validate to validate the ACL
            #! Putback with proper nornir-validate
            # task.run(task=validate_task, input_data=task.host["acl_val"])

    # ----------------------------------------------------------------------------
    # 3. CFG ENGINE: Engine to run main-task to apply config
    # ----------------------------------------------------------------------------
    def config_engine(self, nr_inv: "Nornir", dry_run: bool) -> Result:
        if dry_run == True:
            self.rc.print(
                "[dark_blue][b] **** ⚠️  DRY_RUN=TRUE:[/b] This is the configuration that would have been applied [b]****[/b][/dark_blue]"
            )
        elif dry_run == False:
            self.rc.print(
                "[dark_blue][b] **** ⚠️  DRY_RUN=FALSE:[/b] If there are ACL differences the configuration will be applied [b]****[/b][/dark_blue]"
            )
        result = nr_inv.run(task=self.task_engine, dry_run=dry_run)
        print_result(result, vars=["result"])
