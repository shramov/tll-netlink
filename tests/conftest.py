#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import pytest

import decorator
import os

from tll import asynctll
from tll.channel import Context
import tll.logger

tll.logger.init()

@pytest.fixture
def context():
    ctx = Context()
    ctx.load(os.path.join(os.environ.get("BUILD_DIR", "build"), "tll-netlink"))
    return ctx

@pytest.fixture
def asyncloop(context):
    loop = asynctll.Loop(context)
    yield loop
    loop.destroy()
    loop = None
