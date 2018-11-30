#!/usr/bin/python3
'''
Loop over a list of devices in a YAML file and get the uplinks SFP stats.
Specifically, the SFP type, Tx power and Rx power.

sudo -H pip3 install prettytable PyYAML

Test with: sudo nc -vvv -k -l 23


Example KeyMile command output:

/> ls unit-11/port-1/
Infos of AP: /unit-11/port-1
  Name                      : 1000BASE-X/10000BASE-R SFP
  Main Mode                 : VLAN Trunk
  Equipment State           :
  Alarm Severity            : Cleared
  Propagated Alarm Severity : Cleared
  User Label                : EDD01
  Service Label             :
  Description               :

MF List:
  main
  cfgm
  fm
  pm
  status
  ifMIB
  rmonMIB
  hcRmonMIB

AP List:
/> get unit-11/port-1/main/EquipmentInventory
                                                                   \ # EquipmentInventory
Ok                                                                 \ # EquipmentState
"10G BASE-LR"                                                      \ # TransceiverComplianceCodes
"A0515109321"                                                      \ # VendorSerialNumber
"NEOPHOTONICS"                                                     \ # VendorName
"PT7420-81-1D+"                                                    \ # VendorPartNumber
"2015.05.27"                                                       \ # VendorDateCode
"000"                                                              \ # VendorRevision
/> get unit-11/port-1/status/DdmStatus
                                                                   \ # DdmStatus
Supported                                                          \ # DdmInterfaceSupport
23                                                                 \ # ModuleTemperature
3.3655E0                                                           \ # SupplyVoltage
2.694E1                                                            \ # TxBiasCurrent
-2                                                                 \ # TxOutputPower
-8                                                                 \ # RxInputPower
/> 
'''


import argparse
import collections
from getpass import getpass
from prettytable import PrettyTable
import re
from socket import timeout as SocketTimeout
import sys
import telnetlib
import time
import yaml


def get_sfp_stats(dev, opt, results, tn):

    ports = ['unit-11/port-1', 'unit-11/port-2', 'unit-13/port-1', 'unit-13/port-2']

    try:
        ret = tn.read_until(opt['cmd_prompt'].encode('ascii'), timeout=opt['timeout'])
    except EOFError as e:
        print("Lost connection to {}: {}".format(dev, e))
        return False

    if opt['cmd_prompt'] not in ret.decode('ascii'):
        print("Command prompt not found for {}".format(dev))
        return False

    for port in ports:

        cmd = 'ls '+port+'\n'
        tn.write(cmd.encode('ascii'))

        try:
            ret = tn.read_until(opt['cmd_prompt'].encode('ascii'), timeout=opt['timeout'])
        except EOFError as e:
            print("Lost connection to {}: {}".format(dev, e))
            return False

        if opt['cmd_prompt'] not in ret.decode('ascii'):
            print("Command prompt not found for {}".format(dev))
            return False
        
        try:
            int_descr = re.search('User Label.*\n', ret.decode('ascii')).group(0)
            int_descr = int_descr.split(":")[1].strip()
        except AttributeError:
            int_descr = ""
            pass
        
        time.sleep(0.3)


        cmd = 'get '+port+'/main/EquipmentInventory\n'
        tn.write(cmd.encode('ascii'))

        try:
            ret = tn.read_until(opt['cmd_prompt'].encode('ascii'), timeout=opt['timeout'])
        except EOFError as e:
            print("Lost connection to {}: {}".format(dev, e))
            return False

        if opt['cmd_prompt'] not in ret.decode('ascii'):
            print("Command prompt not found for {}".format(dev))
            return False
        
        try:
            sfp_type = re.search('10G BASE-..', ret.decode('ascii')).group(0)
        except AttributeError:
            sfp_type = "Unknown"
            pass

        try:
            sfp_part = ret.decode('ascii').split("\n")[6].split("\"")[1]
        except Exception:
            sfp_part = "Unknown"
            pass

        # Sometimes the above "try" doesn't fail and a blank value is matched
        if sfp_part == "":
            sfp_part = "Unknown"
        
        time.sleep(0.3)
        

        cmd = 'get '+port+'/status/DdmStatus\n'
        tn.write(cmd.encode('ascii'))

        try:
            ret = tn.read_until(opt['cmd_prompt'].encode('ascii'), timeout=opt['timeout'])
        except EOFError as e:
            print("Lost connection to {}: {}".format(dev, e))
            return False

        if opt['cmd_prompt'] not in ret.decode('ascii'):
            print("Command prompt not found for {}".format(dev))
            return False


        sfp_stats = ret.decode('ascii').split()

        try:
            tx_power = re.search('\n.*TxOutputPower', ret.decode('ascii')).group(0)
            tx_power = tx_power.split()[0].strip()
        except AttributeError:
            tx_power = None
            pass

        try:
            rx_power = re.search('\n.*RxInputPower', ret.decode('ascii')).group(0)
            rx_power = rx_power.split()[0].strip()
        except AttributeError:
            rx_power = None
            pass

        time.sleep(0.3)


        results.add_row([dev, port, int_descr, sfp_type, sfp_part, tx_power, rx_power])


    return True


def load_inventory(filename):

    try:
        inventory_file = open(filename)
    except Exception:
        print('Couldn\'t open inventory file {}'.format(filename))
        sys.exit()

    try:
        inventory = yaml.load(inventory_file)
    except Exception as e:
        print("Failed to load YAML: {}".format(e))
        sys.exit()

    inventory_file.close()

    return inventory


def login(dev, opt, tn):
    
    try:
        ret = tn.read_until(opt['login_prompt'].encode('ascii'), timeout=opt['timeout'])
    except EOFError as e:
        print("Lost connection to {}: {}".format(dev, e))
        return False

    if opt['login_prompt'] not in ret.decode('ascii'):
        print("Login prompt not found for {}".format(dev))
        return False

    tn.write(opt['username'].encode('ascii') + b"\n")

    try:
        ret = tn.read_until(opt['password_prompt'].encode('ascii'), timeout=opt['timeout'])
    except EOFError as e:
        print("Lost connection to {}: {}".format(dev, e))
        return False

    if opt['password_prompt'] not in ret.decode('ascii'):
        print("Password prompt not found for {}".format(dev))
        return False

    tn.write(opt['password'].encode('ascii') + b"\n")

    return True


def open_device(dev, hostname, timeout):

    try:
        tn = telnetlib.Telnet(hostname, timeout=timeout)
    except ConnectionRefusedError:
        print("Connection refused to {}".format(dev))
        return False
    except SocketTimeout:
        print("Connection timeout to {}".format(dev))
        return False

    return tn


def parse_cli_args():

    parser = argparse.ArgumentParser(
        description='Run a list of commands against a list of KeyMile MileGate devices over Telnet',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        '-c', '--cmd-prompt',
        help='Command prompt to expect',
        type=str,
        default='/> ',
    )
    parser.add_argument(
        '-d', '--debug',
        help='Set Telnet debug level',
        type=int,
        default=0,
    )
    parser.add_argument(
        '-e', '--exit-cmd',
        help='Command used to logout',
        type=str,
        default='exit',
    )
    parser.add_argument(
        '-i', '--inventory-file',
        help='Input YAML inventory file',
        type=str,
        default='inventory.yml',
    )
    parser.add_argument(
        '-l', '--login-prompt',
        help='Login prompt to expect',
        type=str,
        default='login as: ',
    )
    parser.add_argument(
        '-p', '--password-prompt',
        help='Password prompt to expect',
        type=str,
        default='password: ',
    )
    parser.add_argument(
        '-t', '--timeout',
        help='Timeout in second for login and command execution',
        type=int,
        default=10,
    )
    parser.add_argument(
        '-u', '--username',
        help='Default username for device access',
        type=str,
        default=None,
    )

    return vars(parser.parse_args())


def set_dev_opts(dev, opt, args):

    if opt['os'] != 'km':
        print("Skipping {}, wrong OS type".format(dev))
        return False

    if 'hostname' not in opt:
        print("Skipping {}, no hostname defined".format(dev))
        return False

    if 'cmd_prompt' not in opt:
        opt['cmd_prompt'] = args['cmd_prompt']

    if 'exit_cmd' not in opt:
        opt['exit_cmd'] = args['exit_cmd']

    if 'login_prompt' not in opt:
        opt['login_prompt'] = args['login_prompt']

    if 'password' not in opt:
        opt['password'] = args['password']

    if 'password_prompt' not in opt:
        opt['password_prompt'] = args['password_prompt']

    if 'timeout' not in opt:
        opt['timeout'] = args['timeout']

    if 'username' not in opt:
        if not args['username']:
            print ('No username specified')
            return False
        else:   
            opt['username'] = args['username']

    return True


def main():

    args = parse_cli_args()
    args['password'] = getpass("Default password:")

    inventory = load_inventory(args['inventory_file'])

    results = PrettyTable(["Device", "Port", "Description", "SPF Type",
                           "Part No.", "Tx Power", "Rx Power"])


    success = 0
    failed = []
    # Loop over devices in order
    ordered_inventory = collections.OrderedDict(sorted(inventory.items()))
    for dev, opt in ordered_inventory.items():

        if not set_dev_opts(dev, opt, args):
            failed.append(dev)
            continue

        print("Checking {}...".format(dev))

        tn = open_device(dev, opt['hostname'], opt['timeout'])
        if not tn:
            failed.append(dev)
            continue

        tn.set_debuglevel(args['debug'])

        if not login(dev, opt, tn):
            failed.append(dev)
            continue

        if not get_sfp_stats(dev, opt, results, tn):
            failed.append(dev)
            continue

        success += 1;
        tn.write(opt['exit_cmd'].encode('ascii') + b"\n")
        tn.close()


    if len(results._rows) > 0:
        results.sortby = "Device"
        print(results)

    print("Got stats from {} of {} devices".format(success, len(inventory)))

    if len(failed) > 0:
        print("Failed to get stats from these {} devices: {}".
              format(len(failed), failed))

    return


if __name__ == '__main__':
    sys.exit(main())
