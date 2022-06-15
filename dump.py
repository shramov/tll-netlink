#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import os

import time

from tll.channel import Context
from tll.error import TLLError

ctx = Context()
ctx.load(os.path.join(os.environ.get("BUILD_DIR", "build"), "tll-netlink"), 'channel_module')

c = ctx.Channel(f'netlink://', name='netlink', dump='scheme')
c.open()

while True:
    c.process()
    time.sleep(0.001)
