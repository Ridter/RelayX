#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import logging
import sys
class ImpacketFormatter(logging.Formatter):
    def __init__(self):
        logging.Formatter.__init__(self, '%(bullet)s %(message)s \033[0m', None)

    def format(self, record):
        if record.levelno == logging.INFO:
            record.bullet = '\033[90m[*]'
        elif record.levelno == logging.CRITICAL:
            record.bullet = '\033[92m[+]\033[0m'
        elif record.levelno == logging.WARNING:
            record.bullet = '\033[1;31;m[!]'
        elif record.levelno == logging.DEBUG:
            record.bullet = "[*]"
        else:
            record.bullet = '\033[1;31;m[-]'
        return logging.Formatter.format(self, record)

class ImpacketFormatterTimeStamp(ImpacketFormatter):
    '''
    Prefixing logged messages through the custom attribute 'bullet'.
    '''
    def __init__(self):
        logging.Formatter.__init__(self,'%(bullet)s [%(asctime)-15s]  %(message)s', None)

    def formatTime(self, record, datefmt=None):
        return ImpacketFormatter.formatTime(self, record, datefmt="%Y-%m-%d %H:%M:%S")


def init(ts=False):
    # We add a StreamHandler and formatter to the root logger
    handler = logging.StreamHandler(sys.stdout)
    if not ts:
        handler.setFormatter(ImpacketFormatter())
    else:
        handler.setFormatter(ImpacketFormatterTimeStamp())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)
