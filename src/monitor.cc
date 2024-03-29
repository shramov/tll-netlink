/*
 * Copyright (c) 2022 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "monitor.h"

#include "netlink.h"
#include "netlink-control.h"

using namespace tll;

int Monitor::_open(const tll::ConstConfig &params)
{
	if (_master->state() != tll::state::Active)
		return 0;
	std::array<unsigned char, netlink_control_scheme::Dump::meta_size()> buf;
	auto dump = netlink_control_scheme::Dump::bind(buf);
	auto v = dump.get_request();
	v.Link(true);
	v.Addr(true);
	dump.set_request(v);
	tll_msg_t msg = { TLL_MESSAGE_CONTROL };
	msg.msgid = dump.meta_id();
	msg.data = dump.view().data();
	msg.size = dump.view().size();
	if (_master->post(&msg))
		return _log.fail(EINVAL, "Failed to post Dump request");
	return 0;
}

int Monitor::_on_data(const tll_msg_t *msg)
{
	if (msg->msgid == netlink_scheme::Link::meta_id()) {
		auto data = netlink_scheme::Link::bind(*msg);
		if (data.get_name() != _interface)
			return 0;
		if (data.get_action() == netlink_scheme::Action::Delete) {
			_log.info("Device deleted");
			_lladdr = std::nullopt;
			_addr.clear();
			return 0;
		}
		_log.info("Device added {}", _interface);
		if (data.has_lladdr()) {
			_lladdr = *(const ether_addr *) data.get_lladdr().data();
			_log.debug("Interface {} lladdr: {}", _interface, *_lladdr);
		}
	} else if (msg->msgid == netlink_scheme::Addr::meta_id()) {
		auto data = netlink_scheme::Addr::bind(*msg);
		if (data.get_name() != _interface)
			return 0;
		auto addr = data.get_addr();
		int af = AF_UNSPEC;
		if (addr.union_type() == addr.index_ipv4)
			af = AF_INET;
		else if (addr.union_type() == addr.index_ipv6)
			af = AF_INET6;

		if (data.get_action() == netlink_scheme::Action::Delete) {
			_log.info("Remove address from {}", _interface);
			for (auto it = _addr.begin(); it != _addr.end(); it++) {
				if (std::holds_alternative<in_addr>(*it)) {
					if (af != AF_INET)
						continue;
					auto & v = std::get<in_addr>(*it);
					if (v.s_addr == addr.unchecked_ipv4()) {
						_log.debug("Remove inet address from {}: {}", _interface, v);
						_addr.erase(it);
						return 0;
					}
				} else if (std::holds_alternative<in6_addr>(*it)) {
					if (af != AF_INET6)
						continue;
					auto & v = std::get<in6_addr>(*it);
					if (memcmp(v.s6_addr, addr.unchecked_ipv6().data(), sizeof(v))) {
						_log.debug("Remove inet6 address from {}: {}", _interface, v);
						_addr.erase(it);
						return 0;
					}
				}
			}
			return 0;
		}
		if (af == AF_INET) {
			in_addr v = { addr.unchecked_ipv4() };
			_log.info("Add address for {}: {}", _interface, v);
			_addr.emplace_back(v);
		} else if (af == AF_INET6) {
			in6_addr v = {};
			memcpy(v.s6_addr, addr.unchecked_ipv6().data(), sizeof(v));
			_log.info("Add address for {}: {}", _interface, v);
			_addr.emplace_back(v);
		}
	}
	return 0;
}

int Monitor::_on_state(const tll_msg_t *msg)
{
	auto s = (tll_state_t) msg->msgid;
	switch (s) {
	case tll::state::Active:
		break;
	case tll::state::Error:
		_log.info("Master channel failed");
		if (state() != tll::state::Closed || state() != tll::state::Closing)
			state(tll::state::Error);
		break;
	case tll::state::Closing:
		break;
	case tll::state::Closed:
		_log.info("Master channel closed");
		if (state() != tll::state::Error)
			close();
		break;
	case tll::state::Destroy:
		_log.info("Master channel destroyed");
		_master = nullptr;
		break;
	default:
		break;
	}
	return 0;
}
