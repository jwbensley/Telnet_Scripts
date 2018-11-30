# Telnet (telnetlib) Scripts

### Overview

This repo contains various scripts that can be used for working with KeyMile  
MileGate devices. These are network devices which support telnet meaning that  
the scripts serve as examples of how to interact with legacy devices which  
don't support SSH, an API or are supported by other libraries such as NAPALM.  
The scripts show how to use Python `telnetlib` for interacting with these  
devices.

* [run_commands](run_commands) - This script is a generic script that will run a list of commands against a list of devices
* [get_sfp_stats](get_sfp_stats) - This script is a variation of the [run_commands](run_commands) script that runs some specific commands, parse the output using regex, and print it in a PrettyTable
