#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import os

import time

from tll.channel import Context
from tll.processor import Loop
from tll.error import TLLError

ctx = Context()
ctx.load(os.path.join(os.environ.get("BUILD_DIR", "build"), "tll-netlink"), 'channel_module')

loop = Loop()

c = ctx.Channel(f'netlink://', name='netlink', dump='scheme')
c.open()
loop.add(c)

while True:
    loop.step(1)
