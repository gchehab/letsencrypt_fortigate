import os
import sys
import sqlite3
import argparse
import yaml
import keyring
from keyring.errors import NoKeyringError
from fortigate_api import FortigateAPI
from datetime import datetime
from pprint import pprint as pp
#import win32crypt

DEBUG=True
RECREATE_CRED=False

parser = argparse.ArgumentParser(
                    prog=__name__,
                    description='Importa certificados letsencrypt no fortigate',
                    epilog='bla bla')

parser.add_argument(
    '-u',
    '--username', 
    default=None, 
    required=False, 
    help='Username a ser usado, se omitido será procurado no Windows Store e perguntado, caso não exista')

parser.add_argument(
    '-p',
    '--password',
    default=None,
    required=False,
    help='Password a ser usada, se omitido será usada a do Windows storage e perguntado, caso não exista')

parser.add_argument(
    'servers', 
    type=str, 
    nargs="?", 
    help='Lista de servidores')

try:
    args = parser.parse_args()
except:
    args = None


def get_chrome(): 
    data_path = os.path.expanduser('~') + r'AppData\Local\Google\Chrome\User Data\Default\Login Data'

def get_or_set_credentials(server=None, username=None, secret=None):
    if server != None:
        try:
            keyring.get_password(server,'username')
        except NoKeyringError as E:
            return { 'username': username, 'secret':secret }

        if (keyring.get_password(server,'username') is None or
            keyring.get_password(server,'secret') is None or 
            RECREATE_CRED == True):

            keyring.set_password(server, 'username', username if username is not None else input("Enter the username: "))
            keyring.set_password(server, "secret", secret if secret is not None else input("Enter the password: "))   

        secret = keyring.get_password(server, username) 
        return { 'username': username, 'secret': secret }

if args.servers is None:
    args = yaml.safe_load(open('config.yml'))
else:
    new_args = {}
    for server in args.servers:
        new_args[server] = get_or_set_credentials(server=server, username=args.username, secret=args.password )
    args = new_args


for server in args.keys():
    print ("Analisando certificados no servidor", server)
    with FortigateAPI(host=server, username=args[server]['username'], password=args[server]['secret']) as fgt_global:
        fgt_global.login()
        certs = fgt_global.fgt.get('api/v2/monitor/system/available-certificates?scope=global&with_remote=1&with_ca=1&with_crl=1')
        certs = [ (x['name'], datetime.fromtimestamp(x['valid_to']).strftime("%d/%m/%Y") ) for x in certs if 'issuer_raw' in x and x['issuer_raw']=="C = US, O = Let's Encrypt, CN = R3" ]
        print ("Certificados no escopo global")
        pp (certs)
        vdoms = [ vdom['name'] for vdom in fgt_global.fgt.get("api/v2/cmdb/system/vdom") ]
        for vdom in vdoms:
            with FortigateAPI(host=server, username=args[server]['username'], password=args[server]['secret'], vdom=vdom) as fgt:
                certs = fgt.fgt.get('api/v2/monitor/system/available-certificates?scope=vdom&with_remote=1&with_ca=1&with_crl=1')
                print ("Certificados na vdom", vdom)
                certs = [ (x['name'], datetime.fromtimestamp(x['valid_to']).strftime("%d/%m/%Y") ) for x in certs if 'issuer_raw' in x and x['issuer_raw']=="C = US, O = Let's Encrypt, CN = R3" ]
                pp (certs)

