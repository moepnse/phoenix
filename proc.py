#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os

def is_running(pid):
    pid = str(pid)
    if os.path.exists(os.path.join("/proc", pid)):
        return True
    return False
