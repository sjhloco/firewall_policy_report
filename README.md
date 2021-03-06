# Firewall Policy Report

Connects to the firewalls and gathers the access-lists to produce an Excel worksheet report of the policy rules and their usage (hits).

The idea behind this project is to have a framework built in a modular manner to create the report based on a standard input data model. By building it in this manner the specific firewall type configuration is abstracted from the main script making it easier to add different firewall types in the future. Each firewall type has a separate python script consisting of functions to log into the device, scrape the data and do the number crunching to create the data model that is returned.

- Supports ASA (9.xx), Checkpoint (R80.20). ASAs use SSH (*Netmiko*) and Checkpoints API (*Requests*) to gather the information
- The input yaml file contains dictionaries of the firewall types with hierarchical username and passwords
- Each device has an XL tab for the ACL and expanded ACL (expands group objects)
- Colourisation of rules (XL rows) that have been hit in the last day, last 7 days and last 30 days as well as inactive ACEs
- Total hit counts for each ACE and the last time the rule was hit (see Checkpoint caveat)
- XL header filters to aid with drilling down further in larger rule bases
- Supports IPv4 only

## Output

Two worksheets are created per device, a standard ACL and expanded ACL. Each XL cell only contains one element, an object (host, network, service, etc) or group of objects. The size of the standard ACL worksheet will depend on the policy configuration. If groups are not used or there are multiple groups or objects in a rule then every entry needs expanding for all the different 5 tuple permutations. 

The expanded ACL expands the groups and replaces the object names for the actual IP addresses. For example, on an ASA the standard ACL is `show run access-list` and the expanded ACL is `show access-list`.

<img width="1322" alt="Screenshot 2021-05-20 at 20 08 54" src="https://user-images.githubusercontent.com/33333983/119035236-426c4180-b9a7-11eb-8e1c-cc37d7097ac7.png">

## Installation and Prerequisites

Clone the repository and create a virtual environment

```bash
git clone https://github.com/sjhloco/firewall_policy_report.git
python -m venv ~/venv/acl_report/
source ~/venv/acl_report/bin/activate
```

Install the packages (netmiko, requests, rich, openpyxl and pytest)

```bash
pip install -r firewall_policy_report/requirements.txt
```

#### ASA

Enable SSH access over the interface and from networks that the script will be run\
`ssh <network> <mask> <interface>`

#### Checkpoint
Under *Manage & Settings >> Blades >> Management API* enable the API, allow *'All IP addresses'* and push the policy. Finally from the manager CLI restart the API process `api restart`

## Input File

Each firewall IP address or hostname is defined in a list under a dictionary for that firewall type. The username and/or password are hierarchical and can be set globally for all firewalls, for each type of firewall or for each individual firewall. They only need defining once and are completely independent of each other. Individual firewall username and/or password override firewall type and firewall type override global.

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
  user: ckp_username
  pword: ckp_password
  fw:
  - ip_name: 10.10.30.1
    user: fw_username
    pword: fw_password
  - ip_name: dc1_ckp
```

## Usage

If the script is run without any arguments it uses the default settings (variables) defined at the start of *main.py*.

- ***input_file:*** Uses an input file called **input.yml**
- ***report_name:*** Creates a report called **ACLreport_yyyymmdd**
- ***directory:*** It looks for the input file and saves the report in the current directory the script is run from

```python
python main.py
```

![demo](https://user-images.githubusercontent.com/33333983/119037187-8eb88100-b9a9-11eb-9417-106d21eb7591.gif)

Any or all of these default settings can be overiden at run time using flags. If the global username is specified (-u or --user) the global password will be prompted for.

```python
-i or --input = Input file holding firewall IPs/hostnames and credentials
-u or --user = Global username for all devices, overrides input file and prompts user for password
-l or --location = Location of the source input file and destination to save the report
-n or --name = Name for the ACL report
```

```python
python3 main.py -i dc1_fws.yml -u onfly_global_username -n custom_report_name -l /location/for/input_file/and/report/
```

During runtime if any of the connections to a firewall fails all other firewall connections will be closed and the script stopped.

## Caveats

The *Rich* package is used to colourise the CLI output. Windows classic terminal is limited to 16 colors so Windows users would be better off using the new Windows Terminal if you want full colorised CLI output. It is purely cosmetic, not essential.

#### ASA

Only extended ACLs are supported. Including standard ACLs wont break the script but will just be ignored.

#### Checkpoint

Does not support individual ACE hit counts for expanded groups so the value for each ACE from an expanded group is the hit count for the overall rule. The expanded ACL negated source and destination range produce a blank output in the API call so the standard ACL values are used for these cells. The expanded ACL does not expand application groups

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

```yaml
directory = os.path.dirname(__file__)
report_name = 'ACLreport_' + date.today().strftime('%Y%m%d')
input_file = 'input.yml'
header = {'Policy/ACL Name':25, 'Line Number':17, 'Access':18, 'Protocol':12, 'Source Address':23, 'Source Service':14, 'Destination Address':23,
          'Destination Service':26, 'Hit Count':14, 'Date Last Hit':17, 'Time Last Hit':17, 'State':10}
```

## Adding new Firewall Types

The firewall types are in individual python files that are dynamically imported into the *main.py* using `__import__`. The beauty of doing it this way is that if you do add another firewall type the only thing that needs changing in *main.py* is adding it to the list `fw_types = ['asa', 'ckp']`, everything else is taken care of automatically.

The new firewall type python file has to have the following functions and arguments with each function returning data in the desired format.

**login(fw, user, pword)**\
Uses `try/except` to open a connection to the firewall. If the connection is successful it returns the tuple *(True, SID)* with the SID (session ID) used for future operations to run commands on the firewall. If the connection fails it returns the tuple *(False, err_msg)* with the message being a description of the error. `True` and `False` are used by *main.py* to determine whether the connection was successful (True) or not (False). Any connection failure causes all other connections to be closed and the script to gracefully fail.\
***return:*** *(True, sid) or (False, error_message)*

**logoff(fw, sid)**\
Gracefully closes connections either at the end of the script or to close all connections if any firewall connection fails.\
***return:*** *nothing*

**get_acls(fw, sid)**\
Uses the SID to connect to the device and gather the firewall rules returning back two lists, *acl_brief* and *acl_expanded*. What is in these lists depends on the capabilities of the firewall type. For example, ASA is the ACL hashes and extended ACl whereas Checkpoint is the standard ACL and ACL with expanded ranges.\
***return:*** *acl_brief, acl_expanded*

**format_acl(fw, acl_brief, acl_expanded)**\
Takes the ACL data gathered from the devices and runs it through various other functions to normalise it and produce two lists, *standard_acl* and *expanded_acl* (object/group names converted to IP addresses/networks). Each list element is an ACE in the following format (ready to be made into XL columns) `[name, num, permit/deny, protocol, src_ip/pfx, src_port, dst_ip/pfx, dst_port, hitcnt, last_hit_date, last_hit_time, state]`\
***return:*** *{fwip_acl: [standard_acl], fw_ip_exp_acl: [expanded_acl]}*

*new_fw_type_template.py* is a skelton template containing these functions that can be used for creating new firewall types.

## Future Plans

Add firepower report to the report. Need to decide whether to use SSH or API to gather the information, hopefully the formatting will be simialr to ASAs.\
Should probably redo the the unit tests to test the indvidual functions rather than the overall outcome.
