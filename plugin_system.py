#! /usr/bin/env python
# -*- coding: utf-8 -*-

# standard library imports
import imp
import sys
import os

# third party imports

# application/library imports
from logging import log, STD_OUT, STD_ERR


class PluginSystem():

    def __init__(self, plugin_path=r"plugins"):
        self._plugin_path = os.path.join(os.path.dirname(os.path.abspath(__file__.decode(sys.getfilesystemencoding()))), plugin_path)
        log(u"Plugin path: %s" % self._plugin_path, STD_OUT)

    def _get_plugins(self, file_extension):
        plugins = self._plugins
        suffix_len = len(file_extension)
        for plugin_file_name in os.listdir(self._plugin_path):
            plugin_file_name = plugin_file_name.decode(sys.getfilesystemencoding())
            if not plugin_file_name.endswith(file_extension):
                continue
            plugin_name = plugin_file_name[:-suffix_len]
            plugin_path = os.path.join(self._plugin_path, plugin_file_name)
            #plugin = imp.find_module(plugin_name, [self._plugin_path])
            #print plugin_name, plugin_path
            plugins[plugin_name] = (plugin_name.encode(sys.getfilesystemencoding()), plugin_path.encode(sys.getfilesystemencoding()))

    def get_plugins(self):
        self._plugins = {}
        self._get_plugins('.pyc')
        self._get_plugins('.py')
        self._get_plugins('.pyd')
        self._get_plugins('.so')
        return self._plugins

    def load_plugin(self, plugin):
        plugin_path = plugin[1]
        head, tail = os.path.split(plugin_path)
        if tail.endswith('.py'):
            plugin = imp.load_source(*plugin)
        elif tail.endswith('.pyd') or (tail.endswith('.so') and not tail.startswith('lib')):
            try:
                plugin = imp.load_dynamic(*plugin)
            except ImportError, err:
                print plugin_path, err
        elif tail.endswith('.pyc'):
            plugin = imp.load_compiled(*plugin)
        return plugin

    def load_plugins(self):
        plugins = []
        for plugin in self.get_plugins().values():
            plugins.append(self.load_plugin(plugin))
        return plugins