#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import decorator
import pytest
import enum
from errno import ENOENT

from tll.chrono import Duration
from tll.test_util import ports

@decorator.decorator
def asyncloop_run(f, asyncloop, *a, **kw):
    asyncloop.run(f(asyncloop, *a, **kw))

@asyncloop_run
async def test_single_tcp4(asyncloop):
    s = asyncloop.Channel(f'tcp://127.0.0.1:{ports.TCP4};mode=server;name=server')
    c = asyncloop.Channel(f'tcp://127.0.0.1:{ports.TCP4};mode=client;name=client;bind=127.0.0.1:5555')
    diag = asyncloop.Channel(f'sock-diag://;dump=yes;name=netlink')
    diag.open()

    EOD = diag.scheme_control['EndOfData'].msgid
    TcpState = diag.scheme.enums['TcpState'].klass

    s.open()

    # Request for something that don't exist
    diag.post({'dport': ports.TCP4, 'state': {'TCP_LISTEN'}}, name='DumpTcp4', type=diag.Type.Control)
    m = await diag.recv()
    assert (m.type, m.msgid) == (m.Type.Control, EOD)

    # Listening socket
    diag.post({'saddr': 0x0100007f, 'sport': ports.TCP4, 'state': {'TCP_LISTEN'}}, name='DumpTcp4', type=diag.Type.Control)
    m = await diag.recv()
    assert diag.unpack(m).as_dict() == {'saddr': 0x0100007f, 'sport': ports.TCP4, 'daddr': 0, 'dport': 0, 'state': TcpState.TCP_LISTEN, 'rtt': Duration(0)}
    m = await diag.recv()
    assert (m.type, m.msgid) == (m.Type.Control, EOD)

    # Listening socket
    diag.post({'mode': 'Single', 'saddr': 0x0100007f, 'sport': ports.TCP4, 'state': {'TCP_LISTEN'}}, name='DumpTcp4', type=diag.Type.Control)
    m = await diag.recv()
    assert diag.unpack(m).as_dict() == {'saddr': 0x0100007f, 'sport': ports.TCP4, 'daddr': 0, 'dport': 0, 'state': TcpState.TCP_LISTEN, 'rtt': Duration(0)}

    # Incorrect address
    diag.post({'mode': 'Single', 'saddr': 0x0200007f, 'sport': ports.TCP4, 'state': {'TCP_LISTEN'}}, name='DumpTcp4', type=diag.Type.Control)
    assert diag.unpack(await diag.recv()).code == ENOENT

    # No connection yet
    #diag.post({'dport': ports.TCP4, 'state': {'TCP_ESTABLISHED'}}, name='DumpTcp4', type=diag.Type.Control)
    diag.post({'mode': 'Single', 'saddr': 0x0100007f, 'sport': 5555, 'daddr': 0x0100007f,'dport': ports.TCP4, 'state': {'TCP_ESTABLISHED'}}, name='DumpTcp4', type=diag.Type.Control)
    m = diag.unpack(await diag.recv())
    assert m.SCHEME.name == 'Error'
    assert m.code == ENOENT

    c.open()
    assert (await c.recv_state()) == c.State.Active
    await s.recv()

    #diag.post({'dport': ports.TCP4, 'state': {'TCP_ESTABLISHED'}}, name='DumpTcp4', type=diag.Type.Control)
    diag.post({'mode': 'Single', 'saddr': 0x0100007f, 'sport': 5555, 'daddr': 0x0100007f,'dport': ports.TCP4, 'state': {'TCP_ESTABLISHED'}}, name='DumpTcp4', type=diag.Type.Control)
    m = diag.unpack(await diag.recv())
    assert m.saddr == 0x0100007f
    assert m.daddr == 0x0100007f
    assert m.dport == ports.TCP4
    assert m.sport == 5555
    assert m.state == m.state.TCP_ESTABLISHED
    #m = await diag.recv()
    #assert (m.type, m.msgid) == (m.Type.Control, EOD)

@asyncloop_run
async def test_single_tcp6(asyncloop):
    s = asyncloop.Channel(f'tcp://::1:{ports.TCP6};mode=server;name=server')
    c = asyncloop.Channel(f'tcp://::1:{ports.TCP6};mode=client;name=client;bind=::1:5555')
    diag = asyncloop.Channel(f'sock-diag://;dump=yes;name=netlink')
    diag.open()

    EOD = diag.scheme_control['EndOfData'].msgid
    TcpState = diag.scheme.enums['TcpState'].klass

    s.open()

    LO = b'\x00' * 15 + b'\x01'
    ZERO = b'\x00' * 16
    # Request for something that don't exist
    diag.post({'dport': ports.TCP6, 'state': {'TCP_LISTEN'}}, name='DumpTcp6', type=diag.Type.Control)
    m = await diag.recv()
    assert (m.type, m.msgid) == (m.Type.Control, EOD)

    # Listening socket
    diag.post({'saddr': LO, 'sport': ports.TCP6, 'state': {'TCP_LISTEN'}}, name='DumpTcp6', type=diag.Type.Control)
    m = await diag.recv()
    assert diag.unpack(m).as_dict() == {'saddr': LO, 'sport': ports.TCP6, 'daddr': ZERO, 'dport': 0, 'state': TcpState.TCP_LISTEN, 'rtt': Duration(0)}
    m = await diag.recv()
    assert (m.type, m.msgid) == (m.Type.Control, EOD)

    # Listening socket
    diag.post({'mode': 'Single', 'saddr': LO, 'sport': ports.TCP6, 'state': {'TCP_LISTEN'}}, name='DumpTcp6', type=diag.Type.Control)
    m = await diag.recv()
    assert diag.unpack(m).as_dict() == {'saddr': LO, 'sport': ports.TCP6, 'daddr': ZERO, 'dport': 0, 'state': TcpState.TCP_LISTEN, 'rtt': Duration(0)}

    # Incorrect address
    diag.post({'mode': 'Single', 'saddr': LO[:-1] + b'\x02', 'sport': ports.TCP6, 'state': {'TCP_LISTEN'}}, name='DumpTcp6', type=diag.Type.Control)
    assert diag.unpack(await diag.recv()).code == ENOENT

    # No connection yet
    #diag.post({'dport': ports.TCP6, 'state': {'TCP_ESTABLISHED'}}, name='DumpTcp6', type=diag.Type.Control)
    diag.post({'mode': 'Single', 'saddr': LO, 'sport': 5555, 'daddr': LO,'dport': ports.TCP6, 'state': {'TCP_ESTABLISHED'}}, name='DumpTcp6', type=diag.Type.Control)
    m = diag.unpack(await diag.recv())
    assert m.SCHEME.name == 'Error'
    assert m.code == ENOENT

    c.open()
    assert (await c.recv_state()) == c.State.Active
    await s.recv()

    #diag.post({'dport': ports.TCP6, 'state': {'TCP_ESTABLISHED'}}, name='DumpTcp6', type=diag.Type.Control)
    diag.post({'mode': 'Single', 'saddr': LO, 'sport': 5555, 'daddr': LO,'dport': ports.TCP6, 'state': {'TCP_ESTABLISHED'}}, name='DumpTcp6', type=diag.Type.Control)
    m = diag.unpack(await diag.recv())
    assert m.saddr == LO
    assert m.daddr == LO
    assert m.dport == ports.TCP6
    assert m.sport == 5555
    assert m.state == m.state.TCP_ESTABLISHED
    #m = await diag.recv()
    #assert (m.type, m.msgid) == (m.Type.Control, EOD)
