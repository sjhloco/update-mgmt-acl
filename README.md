# Network Device management (SSH, SNMP) ACL update

**!! BROKE - am in the process or reworking it to use PyPI published version or nornir-validate !!**

The idea behind this script is to apply SSH and/or SNMP management ACLs at scale across different device types without fear of locking yourself out.

- Supports Cisco ASA, NXOS and IOS-XE. For the later you must use extended ACLs as [Cisco IOS changes the order of standard ACLs](https://community.cisco.com/t5/switching/access-list-wrong-order/td-p/3070419/highlight/true/page/2) which breaks the validation
- Takes an input YAML file of *ssh* and/or *snmp* dictionaries that hold the ACL entries (permit/deny/remark and source address, destination is implicitly any)
- The script only updates the ACLs entries, these ACLs must already be assigned for their purpose (for example ssh ACL to the VTY lines)
- After ACL application the configuration is validated (just reports, does not rollback) and SSH access tested before closing the SSH connection (if SSH fails rollback is invoked)

## Installation and Variables

Clone the repository and install the required python packages, the easiest way to do this is with [uv](https://docs.astral.sh/uv/) as it automatically creates and activates the virtual environment.

```python
git clone https://github.com/sjhloco/update_mgmt_acl.git
cd update-mgmt-acl

uv sync
```

If you are using [pip](https://pypi.org/project/pip/) first create and activate the virtual environment before installing the packages.

```python
python -m venv .venv
.\.venv\Scripts\Activate
pip install -r requirements.txt
```

The below table lists the changeable elements of the script, if an element is set via multiple methods the order of preference is ***runtime flag >> environment variable >> script variable***.

| Element | Runtime flag | Environment variable | Default | Information |
| ------- | ------------ | -------------------- | ------- | ----------- |
| Base directory | n/a | BASE_DIRECTORY | working directory | Location where the input file can be found |
| Username | -u/--username | DEVICE_USER | admin | Username for all devices |
| Password | n/a | DEVICE_PWORD | n/a | Password for all devices, if the env var is not set prompts for a password at runtime |
| SSH ACL | n/a | SSH_ACLNAME | SSH_ACCESS | Name of the SSH ACL (IOS-XE, NXOS) |
| SNMP ACL | n/a | SNMP_ACLNAME | SNMP_ACCESS | Name of the SNMP ACL (IOS-XE, NXOS) |
| Zone name | n/a | SEC_ZONE | mgmt | Name of the security zone this traffic comes in on (ASA) |

## Filtering the inventory

The first thing to do is refine the filters to limit the inventory to only the required hosts, the filters are based on pre-defined groups (*inventory/group.yml*) and host variables (*inventory/hosts.yml*). Use `-s` (***show***) or `-sd` (***show detail***) and the appropriate filters to display what hosts the filtered inventory holds. ***You are not running any actions against devices at this stage, just the filtering the inventory***.

| Filter | Description |
| ------ | ----------- | ------- |
| `-n` | Match ***hostname*** containing this string (OR logic upto 10 hosts encased in "" separated by a space) |
| `-g` | Match a ***group*** or combination of groups *(ios, iosxe, nxos, wlc, asa (includes ftd))* |
| `-l` | Match a ***physical location*** or combination of them *(DC1, DC2, etc)* |
| `-ll` | Match a ***logical location*** or combination of them *(WAN, WAN Edge, Core, Access, etc)* |
| `-t` | Match a ***device type*** or combination of them *(firewall, router, dc_switch, switch, etc)* |
| `-v` | Match any ***Cisco OS version*** that contains this string |

```python
$ python update_mgmt_acl.py -g ios -s
======================================================================
2 hosts have matched the filters 'ios, HME':
-Host: HME-SWI-VSS01      -Hostname: 10.10.20.1
-Host: HME-SWI-ACC01      -Hostname: 10.10.10.104
```

## Input File

The input file has a ***ssh*** and/or ***snmp*** dictionary with the keys being the permissions (*remark*, *permit* or *deny*) and the values the source addresses (*x.x.x.x* (a /32), *x.x.x.x/x* or *any*). The destination is implicitly the device as the ACL is for SNMP or SSH access to the device the ACL is applied on.

```yaml
ssh:
  - { remark: MGMT Access - VLAN810 }
  - { permit: 172.17.10.0/24 }
  - { remark: Citrix Access }
  - { permit: 10.10.109.10/32 }
  - { deny: any }
snmp:
  - { deny: 10.10.209.11 }
  - { remark: any }
```

Environment variables *SSH_ACLNAME*, *SNMP_ACLNAME* and *ASA_ZONE* define the ACL names (IOS-XE and NXOS) and source security zone (ASA), the default values for these are *SSH_ACCESS*, *SNMP_ACCESS* and *mgmt*.

## Running the script

Environment variables are optional as all have default values, the one exception is the password which you'll be prompted for if not set.

```bash
export BASE_DIRECTORY="my_folder"
export DEVICE_USER="admin"
export DEVICE_PWORD="blah"
export SSH_ACLNAME="SSH_ACCESS"
export SNMP_ACLNAME="SNMP_ACCESS"
export SEC_ZONE="mgmt"
```

First run the script in ***dry_run*** mode to print the templated configuration and show what changes would have been applied. If the input ACL (yaml) file does not exist in the current location it then looks for it in the *BASE_DIRECTORY*.

| flag | Description |
| ---- | ----------- |
| `-f` | Specify the name of the input ACL file |
| `-a` | Disables *dry_run* mode so that the changes are applied |
| `-u` | Define username for all devices, overrides *DEVICE_USER* |

```bash
python update_mgmt_acl.py -u test_user -g asa -f acl_input_data.yml
python update_mgmt_acl.py -du test_user -g asa -f acl_input_data.yml -a
```

To guard against locking oneself out of the devices (as we are changing the SSH ACL) once the ACL is applied the the connection to the device is kept open whilst a telnet on port 22 is done and the changes reverted if this fails. A further post-test validation is done on task completion using *nornir-validate* to produce a compliance report if the *actual_state* and *desired_state* do not match (only reports, does not revert the config).

![example](https://user-images.githubusercontent.com/33333983/204497062-10c959cd-1d10-408e-946e-699a0922a4f2.gif)

## Templates

The *nornir-template* plugin creates *device_type* specific configuration (based on group membership) from the input variable file and adds this as a data variable (called *config*) under the relevant Nornir inventory group. If there is a member of that group in the inventory the configuration is rendered once against the first member of that group (rather than for every member) and the result printed to screen.

The template syntax for all device types is in the one file with conditional rendering done based on the *os_type* (platform) variable. At present the following device types (groups) are supported.

| Groups | Jinja os_type | Information |
| ------------- | ----- | ------ |
| ios and ios-xe | `ios` | Wildcard based ACLs (SSH and SNMP) |
| nxos | `nxos` | Prefix based ACLs (SSH and SNMP) |
| asa | `asa` | Subnet mask based management interface access (SSH and HTTP) |

## Unit testing

*Pytest* unit testing is split into 2 separate scripts.

**test_update_mgmt_acl.py:** Test the *update_mgmt_acl.py* *InputValidate* class which does the input formatting, validation and is the engine that calls the other scripts. The majority of testing is done against input from the files in the *test_inputs* directory. *test_acl_input_data.yml* holds all the variables used to create the ACLs, it is in the same format as what would be used when running script for real.

```python
pytest test/test_update_mgmt_acl.py -vv
```

**test_nornir_tasks.py:** The script is split into 3 classes to test the different elements within *nornir_tasks.py*

- *TestNornirTemplate:* Uses a nornir inventory (in fixture *setup_nr_inv*) to test templating and the creation of nornir *group_vars*
- *TestFormatAcl:* Uses dotmap and *acl_config* (in fixture *load_vars*) to test all the formatting of python objects used by *nornir_tasks*
- *TestNornirCfg:* Uses the the fixture *setup_test_env* (with *nr_create_test_env_tasks* and *nr_delete_test_env_tasks*) to create and delete the test environment (adds ACLs and associate to vty) on a test device (in *hosts.yml*) at start and finish of the script to setup the environment to test against. This tests the application of the configuration including rollback on a failure (only tests IOS device).

```python
pytest test/test_nornir_tasks.py::TestNornirTemplate -vv
pytest test/test_nornir_tasks.py::TestFormatAcl -vv
pytest test/test_nornir_tasks.py::TestNornirCfg -vv
pytest test/test_nornir_tasks.py -vv
```
