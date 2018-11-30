# Get SFP Stats

### Overview
This script reads the interface description, SFP type and Tx/Rx power stats  
from ports unit-11/port-1, unit-11/port-2, unit-13/port-1 and unit-13/port-2,  
for all devices listed in the `inventory.yml` file.

It expects a YAML formatted inventory file in the same format that is used by  
[NAPALM](https://github.com/napalm-automation/napalm). Each device in the 
inventory file **MUST** have these two fields as a  
minimum: `hostname`, `os`.

The `os` field **MUST** be set to `km`. The hostname field can be either a  
hostname or IP address that is reachable.

The inventory file this script uses is in the same format used by 
[NAPALM](https://github.com/napalm-automation/napalm) so  
that a dump of devices can be taken from CMDB/DCIM for example, which may  
include Cisco, Juniper and KeyMile devices, and this script will only connect  
to the KeyMile devices. However, the same inventory list can be used with  
NAPALM to pull similar stats from the Cisco and Juniper devices.

[Area1_Switches.yml](get_sfp_stats/Area1_Switches.yml) is an example 
inventory file.  

### Install
`sudo -H pip3 install prettytable PyYAML`

### Inventory File
Mandatory fields in the inventory file are `hostname` and  `os`.  
Optional fields are:
* `username` - per device username
* `password` - per device password (bad idea!)
* `cmd_prompt` - the CLI prompt to look for when sending a command
* `exit_cmd` - the command to run to log out of the device
* `login_prompt` - the CLI prompt to look for to send the username
* `pass_prompt` - the CLI prompt to look for to send the password

The script will always prompt for a password when run so that there is no  
need to save the password in the inventory file (that is handy for testing).  

The inventory file format is as follows, AHP01 shows the optional fields and  
the defaults already defined in the script. ALD01 shows the minimum required:

```yml
AHP01:
  hostname: 172.16.1.72
  os: km
  cmd_prompt: '/> '
  exit_cmd: exit
  login_prompt: 'login as: '
  pass_prompt: 'password: '
  timeout: 10
AHP02:
  hostname: 172.16.1.81
  os: km
  username: james
  password: p4ssw0rd
ALD01:
  hostname: 172.16.7.132
  os: km
```

All settings can also be set via the CLI, see `-h` for more info.  
Settings in the inventory if defined take precedence over any CLI args. 


### Example Output
The following is example output:
```bash
bensley@LT-10383(KeyMile)$./get_sfp_stats.py -i Area1_Switches.yml -u testuser
Default password:
Checking AHP01...
Checking AHP02...
Checking ALD01...
Checking ALW01...
...
+--------+----------------+------------------------------------+-------------+-----------------+----------+----------+
| Device |      Port      |            Description             |   SPF Type  |     Part No.    | Tx Power | Rx Power |
+--------+----------------+------------------------------------+-------------+-----------------+----------+----------+
| AHP01  | unit-11/port-1 |        Link to YAT01 U13/p1        | 10G BASE-LR |  APSP31B33CDL20 |    -2    |    -9    |
| AHP01  | unit-11/port-2 |    Link to AHP02 unit 11 port 1    | 10G BASE-LR |  PT7420-81-1D+  |    -2    |    -3    |
| AHP01  | unit-13/port-1 |   Link to BAS01 Unit 11/ port 1    | 10G BASE-LR |  APSP31B33CDL20 |    -2    |    -3    |
| AHP01  | unit-13/port-2 |    link to SLY01 unit 11 port 1    | 10G BASE-LR |  PT7420-81-1D+  |    -4    |    -6    |
| AHP02  | unit-11/port-1 |    Link to AHP01 unit 11 port 2    | 10G BASE-LR |  APSP31B33CDL20 |    -2    |    -3    |
| AHP02  | unit-11/port-2 |                                    |   Unknown   |                 |   -50    |   -50    |
| AHP02  | unit-13/port-1 |                                    | 10G BASE-LR |  APSP31B33CDL20 |    -2    |   -40    |
| AHP02  | unit-13/port-2 |                                    |   Unknown   |                 |   -50    |   -50    |
| ALD01  | unit-11/port-1 |       Link to ALW01 u13pp01        | 10G BASE-LR |  PT7420-81-1D+  |    -2    |    -7    |
| ALD01  | unit-11/port-2 |    Link to BIN01 unit 11 port 1    | 10G BASE-LR |  APSP31B33CDL20 |    -2    |    -3    |
| ALD01  | unit-13/port-1 |       Link to UFT01 U11/pp1        | 10G BASE-LR |  PT7420-81-1D+  |    -3    |    -7    |
| ALD01  | unit-13/port-2 |                                    |   Unknown   |                 |   -50    |   -50    |
| ALW01  | unit-11/port-1 |        Link to WOL01 u13p01        | 10G BASE-LR |  APSP31B33CDL20 |    -3    |    -5    |
| ALW01  | unit-11/port-2 |                                    |   Unknown   |                 |   -50    |   -50    |
| ALW01  | unit-13/port-1 |        Link to ALD01 u11p1         | 10G BASE-LR |  APSP31B33CDL20 |    -2    |    -4    |
| ALW01  | unit-13/port-2 |      Link to BEE01 U11/port 1      | 10G BASE-LR |  PT7420-81-1D+  |    -3    |    -4    |
...
+--------+----------------+------------------------------------+-------------+-----------------+----------+----------+
```
