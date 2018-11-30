# Run Commands

### Overview
This script will run a list of commands stored in the `commands.txt` file  
(one per line) against a list of devices stored in the `inventory.yml` file.  
See the CLI options for more details.

It expects a YAML formatted inventory file in the same format that is used by  
[NAPALM](https://github.com/napalm-automation/napalm). Each device in the 
inventory file **MUST** have these two fields as a  
minimum: `hostname`, `os`.

The `os` field **MUST** be set to `km` to match KeyMile devices.  
The hostname field can be either a hostname or IP address that is reachable.  

The inventory file this script uses is in the same format used by  
[NAPALM](https://github.com/napalm-automation/napalm) so  
that the same inventory file may be used with NAPALM to manage the other  
devices in the inventory. This script will only connect to the KeyMile  
devices.

[Area1_Switches.yml](Area1_Switches.yml) is an example inventory file.  
[commands.txt](commands.txt) is an example command file.

### Install
`sudo -H pip3 install PyYAML`

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
bensley@LT-10383(run_commands)$./run_commands.py -u testuser -i Area1_Switches.yml
Default password:
BRD01: get unit-11/main/status
                                                                   \ # Status
"coge4_r1c19.esw"                                                  \ # AssignedSoftware
"coge4_r1c19.esw"                                                  \ # RunningSoftware
/>
BRD01: get unit-13/main/status
                                                                   \ # Status
"coge4_r1c19.esw"                                                  \ # AssignedSoftware
"coge4_r1c19.esw"                                                  \ # RunningSoftware
/>
BIN01: get unit-11/main/status
                                                                   \ # Status
"coge4_r1e28_02.esw"                                               \ # AssignedSoftware
"coge4_r1e28_02.esw"                                               \ # RunningSoftware
/>
BIN01: get unit-13/main/status
                                                                   \ # Status
"coge4_r1e28_02.esw"                                               \ # AssignedSoftware
"coge4_r1e28_02.esw"                                               \ # RunningSoftware
/>
```
