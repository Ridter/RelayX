# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Protocol Attack Base Class definition
#   Defines a base class for all attacks + loads all available modules
#
# Author:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
import os, sys
import pkg_resources
from impacket import LOG
from threading import Thread

PROTOCOL_ATTACKS = {}
if getattr(sys, 'frozen', False):
    # 如果是打包的可执行文件，修改资源目录路径
    base_path = os.path.join(sys._MEIPASS, 'comm', 'ntlmrelayx', 'attacks')
else:
    # 否则，使用默认的资源目录路径
    base_path = os.path.join('comm', 'ntlmrelayx', 'attacks')

for file in os.listdir(base_path):
    if file.find('__') >= 0 or file.endswith('.py') is False:
        continue
    # This seems to be None in some case (py3 only)
    # __spec__ is py3 only though, but I haven't seen this being None on py2
    # so it should cover all cases.
    try:
        package = __spec__.name  # Python 3
    except NameError:
        package = __package__    # Python 2
    __import__(package + '.' + os.path.splitext(file)[0])
    module = sys.modules[package + '.' + os.path.splitext(file)[0]]
    try:
        pluginClasses = set()
        try:
            if hasattr(module, 'PROTOCOL_ATTACK_CLASSES'):
                # Multiple classes
                for pluginClass in module.PROTOCOL_ATTACK_CLASSES:
                    pluginClasses.add(getattr(module, pluginClass))
            else:
                # Single class
                pluginClasses.add(getattr(module, getattr(module, 'PROTOCOL_ATTACK_CLASS')))
        except Exception as e:
            LOG.debug(e)
            pass

        for pluginClass in pluginClasses:
            for pluginName in pluginClass.PLUGIN_NAMES:
                LOG.debug('Protocol Attack %s loaded..' % pluginName)
                PROTOCOL_ATTACKS[pluginName] = pluginClass
    except Exception as e:
        LOG.debug(str(e))
