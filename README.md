# Firewall Access Rules Report

Produces an XL sheet report of firewall access policy rules and their usage

- Supports ASA (9.xx), Checkpoint (R80.20), Firepower (6.3)
- Uses an input yaml file containing dictionaries of firewalls with hierarchical username and password
- Each device has an XL tab for the ACL and expanded ACL (expands group objects)
- Colourisation of rules (XL rows) that have been hit in the last day, 7 days and 30 days as well as inactive ACEs
- Total hit counts for each ACE and the last time the rule was hit
- XL header filters to aid with drilling down further in larger rule bases
- Supports IPv4 only and the majority of rule combinations

ADD IMAGE

ASAs and firepower use SSH (*Netmiko*) and Checkpoints API (*Requests*) to gather the information. I don't have sufficient knowledge of other firewall platforms to expand this further at present, however it has been built in a modular manner to allow for easy expansion. I will be looking to add Palo Altos at some point dependant on the API capabilities fo them.

## Installation and Prerequisites

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/sjhloco/firewall_access_rule_report.git
python -m venv mkdir ~/venv/acl_report/
source ~/venv/acl_report/bin/activate
```

Install the packages required to run this script (netmiko, requests, rich, openpyxl and pytest).

```bash
pip install -r asa_acl_report/requirements.txt
```

## Input File

Each firewall IP address or hostname are defined in a list under a dictionary for that firewall type (asa covers as and firepower).\
The username and/or password are hierarchical and can be set globally for all firewalls, for each type of firewall or for each individual firewall.\
They only need defining once and are completely independent of each other so can be defined in different locations.\
Individual firewall settings override firewall type settings and firewall type settings  overrides global settings.

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

- Uses an input file called ***input.yml*** (defined in the variable `input_file`)
- Creates a report called ***ACLreport_yyyymmdd*** (defined in the variable `report_name`)
- It looks for the input file and saves the report to the home directory (defined in the variable `report_name`)
- output report file name of ACLreport_date
- input file got from and report saved to home directory

The script can be run with any or all of these flags to override these settings. It is also possible to specify global username at runtime which causes  the script to prompt for the global password.

```python
-i or --input = Input file holding firewall IPs/hostnames and credentials
-u or --user = Global username for all devices, overrides input file and prompts user for password
-l or --location = Location of the source input file and destination to the report
-n or --name = Name for the ACL report
```

```python
python3 main.py -i dc1_fws.yml -u onfly_global_username -n custom_report_name -l /location/for/input_file/and/report/
```

!!! video of running the report !!!

If any of the connections to a firewall fails all other firewall connections will be closed and the script stopped.

## Caveats

The script has been tested against the different ACE entry patterns I can think of and have come across. There maybe other patterns that I haven't thought about and missed, to fix any of these exceptions they would need to be added to section 3 (*Sanitize the data*) of the firewall type scripts

If using Windows Rich true colour and emojis work only with new Windows Terminal the classic terminal is limited to 16 colors so the the onscreen output will differ slightly.

**ASA/Firepower:** Only extended ACLs are supported, including standard ACLs wont break it they will just be ignored like remark statements.\
**Checkpoint:** Does not support individual ACE hit counts for expanded objects so the value for each ACE from an expanded group is the hit count for the overall rule.

## Unit testing

The unit testing is performed only on the parts of the script that require no remote device interaction using dummy files in the directory test/outputs. There is a separate test function for the user input data and one for formatting the ACL into XL ready format and adding the hit count timestamp.

```bash
pytest -v
pytest test/test_acl_report.py::test_data_mode -v
pytest test/test_acl_report.py::test_format_data -v
```

## Customization

The first section of the script is the customisable default values. There is the option to change the default directory location (where to looks for the input file and saves the report), the input file name, the report name and the XL sheet header names (including column widths).

```json
directory = expanduser("~")
report_name = 'ACLreport_' + date.today().strftime('%Y%m%d')
header = {'ACL Name':45, 'Line Number':17, 'Access':11, 'Protocol':16, 'Source Address':31, 'Source Service':14, 'Destination Address':31,
          'Destination Service':35, 'Hit Count':14, 'Date Last Hit':17, 'Time Last Hit':17, 'State':10}
```

## Adding new Firewall Types

The firewall types are in individual python files that are dynamically imported into the *main.py* using ***__import__***. The beauty of this is that if you do add another firewall type the only thing that needs changing in *main.py* is adding it to the list `fw_types = ['asa', 'ckp']`, everything else is taken care of automatically.

The new firewall type python file has to have the following functions and arguments and return the ACL back in a specific data model format. As long as it is in this format the data can automatically be transposed into and XL sheet.

***login(fw, user, pword)***/
Opens a connection to the firewall using the defined arguments either. If the connection is successful returns a tuple of (True, SID) with the SID (session ID) used for future operations to run commands on the firewall. If the connection fails it returns a tuple of (False, err_msg) with the message being a description of the error. `True` and `False` are used by the *main.py* script determine whether it was successful (True) or not (False). Any connection failure causes all other connections to be closed and the script to fail.
*Return: (True, sid) or (False, error_message)*

***logoff(fw, sid)***/
Gracefully closes connections either at the end of the script or to close all connections if any firewall connection fails.
*Return: Nothing*

***get_acls(fw, sid)***/
Using the SID (session ID) to connect to the device and run commands to get the ACL contents. It returns back two lists to *main.py*, *acl_brief* and *acl_expanded* with the difference been the object group members (IP or service) are expanded rules in the later.
*Return: acl_brief, acl_expanded*

***format_acl(fw, acl_brief, acl_expanded)***/
Takes the ACL data gathered from the devices and runs them through various other functions to normalise the data produce an ACL and Expanded_ACL list where each list element is an ACE in the following format ready to be made into columns in the XL sheet.
`[name, num, permit/deny, protocol, src_ip/pfx, src_port, dst_ip/pfx, dst_port, hitcnt, last_hit_date, last_hit_time, state]`
*Return: {fwip_acl: [non_expanded_acl], fw_ip_exp_acl: [expanded_acl]}*
