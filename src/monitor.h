/*
 * Copyright (c) 2022 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _MONITOR_H
#define _MONITOR_H

#include <tll/channel/base.h>
#include <tll/util/sockaddr.h>

class Monitor : public tll::channel::Base<Monitor>
{
	tll::Channel * _master = nullptr;
	std::string _interface;
	bool _up = false;
	std::optional<ether_addr> _lladdr;
	using addr_t = std::variant<in_addr, in6_addr>;
	std::list<addr_t> _addr;

public:
	static constexpr auto open_policy() { return OpenPolicy::Manual; }
	static constexpr auto process_policy() { return ProcessPolicy::Never; }

	static constexpr std::string_view channel_protocol() { return "netlink-monitor"; }

	int _init(const tll::Channel::Url &url, tll::Channel *master)
	{
		std::string_view host = url.host();
		if (!host.size())
			return _log.fail(EINVAL, "Empty interface name");
		_interface = host;
		_log.info("Monitor interface '{}'", _interface);

		if (!master)
			return _log.fail(EINVAL, "Need master channel");
		_master = master;
		_master->callback_add(this);
		return Base::_init(url, master);
	}

	void _free()
	{
		if (_master)
			_master->callback_del(this);
		_master = nullptr;
		return Base::_free();
	}

	int _open(const tll::ConstConfig &params);

	int _close()
	{
		return 0;
	}

	int callback(const tll::Channel * c, const tll_msg_t *msg)
	{
		if (msg->type == TLL_MESSAGE_DATA)
			return _on_data(msg);
		else if (msg->type == TLL_MESSAGE_STATE)
			return _on_state(msg);
		return 0;
	}

	int _on_data(const tll_msg_t *msg);
	int _on_state(const tll_msg_t *msg);
};

#endif//_MONITOR_H
