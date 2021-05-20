# Firewall Policy Report

Connects to the firewalls and gathers the access-lists to produce an Excel worksheet report of the policy rules and their usage (hits).

The idea behind this project is to have a framework built in a modular manner to create the report based on a standard input data model. By building it in this manner the specific firewall type configuration is abstracted from the main script making it easier to add different firewall types in the future. Each firewall type has a separate python script to log into the device, scrape the data and do the number crunching to return the data model.

- Supports ASA (9.xx), Checkpoint (R80.20). ASAs use SSH (*Netmiko*) and Checkpoints API (*Requests*) to gather the information
- The input yaml file contains dictionaries of the firewall types with hierarchical username and passwords
- Each device has an XL tab for the ACL and expanded ACL (expands group objects)
- Colourisation of rules (XL rows) that have been hit in the last day, last 7 days and last 30 days as well as inactive ACEs
- Total hit counts for each ACE and the last time the rule was hit (see Checkpoint caveat)
- XL header filters to aid with drilling down further in larger rule bases
- Supports IPv4 only

<img width="1324" alt="Screenshot 2021-05-20 at 18 42 25" src="https://user-images.githubusercontent.com/33333983/119028192-15b42c00-b99f-11eb-9129-c9a4c6f4706b.png">

## Output

Two worksheets are created per device, a standard ACL and expanded ACL. Each XL cell only contains one object, an object (host, network, service, etc) or group of objects.

The size of the standard ACL worksheet will depend on the policy configuration. If groups are not used then every entry needs for all the different 5 tuple permutations.
The expanded ACL expands groups and replaces object names for the actual IP addresses. For example, on an ASA standard ACL is `show run access-list` and expanded is `show access-list`

## Installation and Prerequisites

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/sjhloco/firewall_policy_report.git
python -m venv mkdir ~/venv/acl_report/
source ~/venv/acl_report/bin/activate
```

Install the packages required to run this script (netmiko, requests, rich, openpyxl and pytest).

```bash
pip install -r firewall_policy_report/requirements.txt
```

### ASA

Enable SSH access over the interface and from networks that the script will be run
`ssh xxxxx`

### Checkpoint

Enable the API on the manger under *Manage & Settings >> Blades >> Management API*, allow *'All IP addresses'* and push the policy. Finally from the manager CLI restart the API process `api restart`

## Input File

Each firewall IP address or hostname is defined in a list under a dictionary for that firewall type.\
The username and/or password are hierarchical and can be set globally for all firewalls, for each type of firewall or for each individual firewall.\
Username and/or password only need defining once and are completely independent of each other meaning they can be defined in different locations.\
Individual firewall settings override firewall type settings and firewall type settings overrides global settings.

```yaml
user: global_username
pword: global_password

asa:
  user: asa_username
  pword: asa_password
  fw:
  - ip_name: dc1_asa
  - ip_name: 10.10.20.1
    user: fw_username
    pword: fw_password
ckp:
  fw:
  - ip_name: 10.10.30.1
  - ip_name: dc1_ckp
```

## Usage

If the script is run without any arguments it uses the default settings that are variables set at the start of *main.py* script.

```python
python main.py
```

- ***input_file:*** Uses an input file called **input.yml**
- ***report_name:*** Creates a report called **ACLreport_yyyymmdd**
- ***directory:*** It looks for the input file and saves the report in the current directory the script is run from

The script can be run with any or all of these flags to override the default settings. It is possible to specify global username at runtime which causes the script to prompt the user for a global password.

```python
-i or --input = Input file holding firewall IPs/hostnames and credentials
-u or --user = Global username for all devices, overrides input file and prompts user for password
-l or --location = Location of the source input file and destination to save the report
-n or --name = Name for the ACL report
```

```python
python3 main.py -i dc1_fws.yml -u onfly_global_username -n custom_report_name -l /location/for/input_file/and/report/
```

!!! video of running the report !!!

During runtime if any of the connections to a firewall fails all other firewall connections will be closed and the script stopped.

## Caveats

The *Rich* package is used to colourise the CLI output. Windows classic terminal is limited to 16 colors so Windows users would be better off using the new Windows Terminal if you want  full colorised CLI output. It is purely cosmetic, not essential.

### ASA

Only extended ACLs are supported. Including standard ACLs wont break the script, they will just be ignored like remark statements.

### Checkpoint

Does not support individual ACE hit counts for expanded objects so the value for each ACE from an expanded group is the hit count for the overall rule.\
The expanded ACL negated source and destination range produce a blank output in the API call so the standard ACL values are used for these cells.
The expanded ACL does not expand application groups

## Unit testing

The unit testing is performed only on the parts of the script that require no remote device interaction using dummy files in the directory test/outputs. There is a separate test function for the user input data and one for formatting the ACL into XL ready format and adding the hit count timestamp.

```bash
pytest -v
pytest test/test_acl_report.py::test_data_mode -v
pytest test/test_acl_report.py::test_asa_format_data -v
pytest test/test_acl_report.py::test_ckp_format_data -v
```

## Customization

The first section of the script is the customisable default values. Can change the default directory location (where to looks for the input file and saves the report), the input file name, the report name and the XL sheet header names (including column widths).

```json
directory = expanduser("~")
report_name = 'ACLreport_' + date.today().strftime('%Y%m%d')
header = {'Policy/ACL Name':45, 'Line Number':17, 'Access':11, 'Protocol':16, 'Source Address':31, 'Source Service':14, 'Destination Address':31, 'Destination Service':35, 'Hit Count':14, 'Date Last Hit':17, 'Time Last Hit':17, 'State':10}
```

## Adding new Firewall Types

The firewall types are in individual python files that are dynamically imported into the *main.py* using ***__import__***. The beauty of this is that if you do add another firewall type the only thing that needs changing in *main.py* is adding it to the list `fw_types = ['asa', 'ckp']`, everything else is taken care of automatically.

The new firewall type python file has to have the following functions and arguments with each function returning data in the desired format.

***login(fw, user, pword)***/
Uses try/except to open a connection to the firewall using the defined arguments either. If the connection is successful returns a tuple of (True, SID) with the SID (session ID) used for future operations to run commands on the firewall. If the connection fails it returns a tuple of (False, err_msg) with the message being a description of the error. `True` and `False` are used by the *main.py* script determine whether it was successful (True) or not (False). Any connection failure causes all other connections to be closed and the script to fail.
*Return: (True, sid) or (False, error_message)*

***logoff(fw, sid)***/
Gracefully closes connections either at the end of the script or to close all connections if any firewall connection fails.
*Return: Nothing*

***get_acls(fw, sid)***/
Uses the SID (session ID) to connect to the device and run commands to get the ACL content returning back two lists to *main.py*, *acl_brief* and *acl_expanded*. What is in these lists depends on the firewall type capabilities. For example, ASA is ACL hashes and the extended ACl whereas Checkpoint is standard ACL and ACL with expanded ranges. These are firewall type specific at this point as are only used in next function.
*Return: acl_brief, acl_expanded*

***format_acl(fw, acl_brief, acl_expanded)***/
Takes the ACL data gathered from the devices and runs it through various other functions to normalise it and produce two lists, ACL and Expanded_ACL (object/group names converted to IP addresses/networks). Each each list element is an ACE in the following format ready to be made into columns in the XL sheet.
`[name, num, permit/deny, protocol, src_ip/pfx, src_port, dst_ip/pfx, dst_port, hitcnt, last_hit_date, last_hit_time, state]`
*Return: {fwip_acl: [non_expanded_acl], fw_ip_exp_acl: [expanded_acl]}*

*new_fw_type_template.py* is a skelton template of these functions for creating new firewall types.


## Future

Should probably the unit tests so doing more indvidual functions rather than the overall function
Add firepower report. Need to decide if using API or SSH to get
