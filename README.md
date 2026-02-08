# Network Device management (SSH, SNMP) ACL update

**!! BROKE - am in the process or reworking it to use PyPI published version or nornir-validate !!**

The idea behind this script is to apply SSH and SNMP management ACLs at scale across different device types without fear of locking yourself out.

- Takes an input YAML file of variables for the ACLs such as name, permit/deny and source address
- Only supports extended ACLs as [Cisco IOS changes the order of standard ACLs](https://community.cisco.com/t5/switching/access-list-wrong-order/td-p/3070419/highlight/true/page/2) which breaks the validation
- The SSH ACL must already be assigned to the VTY lines, if not the ACL will only updated
- The inventory can be defined manually or created dynamically (from Solarwinds NPM) with devices grouped by device type (*platform*). Runtime flags allow for filtering of the inventory based on these groups or device attributes
- Nornir-template builds the ACL configs based on device types (*groups*) allowing for multi-vendor device type configuration
- After ACL application the configuration is validated (just reports, does not rollback) and SSH access tested before closing the SSH connection (if SSH fails rollback is invoked)

## Installation and Prerequisites

Clone the repository, *--recurse-submodules* is needed to also clone the repos *nornir_orion* and *nornir_validate* that are used by this project.

```bash
git clone --recurse-submodules -j8 https://github.com/sjhloco/update_mgmt_acl.git
```

Create a virtual environment and install the packages (nornir, rich, orionsdk, etc).

```bash
python -m venv ~/venv/mgmt_acl_update
source ~/venv/mgmt_acl_update/bin/activate
pip install -r mgmt_acl_update/requirements.txt
```

## Input File

The input file is list of ACLs with each ACL having a name and an ACE list of dictionaries. The ACE dictionary keys are the permissions (*remark*, *permit* or *deny*) and the values the source addresses (*x.x.x.x* (a /32), *x.x.x.x/x* or *any*). The destination is implicitly the device as the ACL is for SNMP or SSH access to the device the ACL is applied on.

```yaml
acl:
  - name: SSH_ACCESS
    ace:
      - { remark: MGMT Access - VLAN810 }
      - { permit: 172.17.10.0/24 }
      - { remark: Citrix Access }
      - { permit: 10.10.109.10/32 }
      - { deny: any }
  - name: SNMP_ACCESS
    ace:
      - { deny: 10.10.209.11 }
      - { remark: any }
```

## Templates

The *nornir-template* plugin creates *device_type* specific configuration (based on group membership) from the input variable file and adds this as a data variable (called *config*) under the relevant Nornir inventory group. If there is a member of that group in the inventory the configuration is rendered once against the first member of that group (rather than for every member) and the result printed to screen. 

The template sytnax for all device types is in the one file with conditional rendering done based on the *os_type* (platform) variable. At present the following device types (groups) are supported.

| Groups | Jinja os_type | Information
| ------------- | ----- | ------ |
| ios and ios-xe | `ios` | Wildcard based ACLs (SSH and SNMP) |
| nxos | `nxos` | Prefix based ACLs (SSH and SNMP) |
| asa | `asa` | Subnet mask based management interface (*nameif* must be ***mgmt***) access (SSH and HTTP) |

## Filtering the inventory

The filters used to limit which devices the script is run against are got from custom or default Orion attributes.

| Filter   | Description |
| ------- | -------------|
| `-n` | Match any ***hostnames*** that contains this string (OR logic with upto 10 host names encased in "" separated by space)
| `-g` | Match a ***group*** or combination of groups *(ios, iosxe, nxos, wlc, asa (includes ftd))* |
| `-l` | Match a ***physical location*** or combination of them *(DC1, DC2, etc)* |
| `-ll` | Match a ***logical location*** or combination of them *(WAN, WAN Edge, Core, Access, etc)* |
| `-t` | Match a ***device type*** or combination of them *(firewall, router, dc_switch, switch, etc)* |
| `-v` | Match any ***Cisco OS version*** that contains this string |

Alternatively if using a static rather than the dynamic (Orion) inventory these attributes can be defined as *data dictionaries* in the hosts file (*hosts.yml*).

```yaml
HME-SWI-VSS01:
  hostname: 10.10.10.1
  groups: [ios]
  data:
    Infra_Location: HME
    Infra_Logical_Location: Core
    MachineType: Catalyst 65xx Virtual Switch
    IOSVersion: 15.1(2)SY7, RELEASE SOFTWARE (fc4)
    type: switch
```

***`-s`*** and ***`-sd`*** runtime flags can be used to print hosts (*show*) or hosts and their attributes (*show detail*) that match the filters. No connections are made to devices, these are used purley for viewing the inventory contents.

```python
$ python update_mgmt_acl.py -g ios -s
======================================================================
2 hosts have matched the filters 'ios, HME':
-Host: HME-SWI-VSS01      -Hostname: 10.10.20.1
-Host: HME-SWI-ACC01      -Hostname: 10.10.10.104
```

## Running the script

First run the script in ***dry_run*** mode to print the templated configuration and show what changes would have been applied. If the input yaml file does not exist in the current location the *directory* variable (default is the current working directory) from *update_mgmt_acl.py* is added to the path.

| flag           | Description |
| -------------- | ----------- |
| `-f` | Specify the input variable file, if it doesn't exist looks for it in the home directory
| `-a` | Disables *dry_run* mode so that the changes are applied
| `-nu` | By specifying an Orion username uses dynamic (orion) rather than static inventory
| `-du` | Define username for all devices and prompt for a password at runtime

The device credentials can be set in *inv_settings.yml* (only username) or environment variables rather than at runtime. If the username is set in multiple places the runtime value will always override them.

- `DEVICE_USERNAME`
- `DEVICE_PASSWORD`

```text
$ python update_mgmt_acl.py -du test_user -g asa -f acl_input_data.yml
$ python update_mgmt_acl.py -du test_user -g asa -f acl_input_data.yml -a
```

To guard against locking oneself out of the devices (as we are changing the SSH ACL) once the ACL is applied the the connection to the device is kept open whilst a telnet on port 22 is done and the changes reverted if this fails. A further post-test validation is done on task completion using *nornir-validate* to produce a compliance report if the *actual_state* and *desired_state* do not match (only reports, does not revert the config).

![example](https://user-images.githubusercontent.com/33333983/204497062-10c959cd-1d10-408e-946e-699a0922a4f2.gif)

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
