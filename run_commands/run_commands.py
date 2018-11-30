#!/usr/bin/python3
'''
Loop over a list of devices in a YAML file and commands in a text file and run
the commands against each device.

sudo -H pip3 install PyYAML

Test with: sudo nc -vvv -k -l 23
'''


import argparse
from getpass import getpass
import re
from socket import timeout as SocketTimeout
import sys
import telnetlib
import time
import yaml


def load_cmds(filename):

    try:
        cmd_file = open(filename)
    except Exception:
        print('Couldn\'t open commands file {}'.format(filename))
        sys.exit()

    try:
        cmds = cmd_file.readlines()
    except Exception as e:
        print("Failed to load commands: {}".format(e))
        sys.exit()

    cmd_file.close()

    return cmds


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
        '-r', '--run-cmds',
        help='File with a list of commands to run, one per line',
        type=str,
        default='commands.txt',
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


def run_cmds(cmds, dev, opt, tn):

    try:
        ret = tn.read_until(opt['cmd_prompt'].encode('ascii'), timeout=opt['timeout'])
    except EOFError as e:
        print("Lost connection to {}: {}".format(dev, e))
        return False

    if opt['cmd_prompt'] not in ret.decode('ascii'):
        print("Command prompt not found for {}".format(dev))
        return False

    for cmd in cmds:

        # Ensure command ends with a new line character
        nl = re.search('\n$', cmd)
        if not nl:
            cmd = cmd + "\n"

        tn.write(cmd.encode('ascii'))

        try:
            ret = tn.read_until(opt['cmd_prompt'].encode('ascii'), timeout=opt['timeout'])
        except EOFError as e:
            print("Lost connection to {}: {}".format(dev, e))
            return False

        if opt['cmd_prompt'] not in ret.decode('ascii'):
            print("Command prompt not found for {}".format(dev))
            return False
        
        print("{}: {}".format(dev, ret.decode('ascii')))
        time.sleep(0.5)


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
    cmds = load_cmds(args['run_cmds'])


    for dev, opt in inventory.items():

        if not set_dev_opts(dev, opt, args):
            continue

        tn = open_device(dev, opt['hostname'], opt['timeout'])
        if not tn:
            continue

        tn.set_debuglevel(args['debug'])

        if not login(dev, opt, tn):
            continue

        if not run_cmds(cmds, dev, opt, tn):
            continue

        tn.write(opt['exit_cmd'].encode('ascii') + b"\n")
        tn.close()

    return


if __name__ == '__main__':
    sys.exit(main())
