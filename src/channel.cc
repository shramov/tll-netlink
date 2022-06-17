/*
 * Copyright (c) 2021 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <net/if.h>
#include <netinet/in.h>
#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "tll/channel/base.h"
#include "tll/channel/module.h"

#include "netlink.h"

// clang-format off
struct mnl_socket_delete { void operator ()(struct mnl_socket *ptr) const { mnl_socket_close(ptr); } };
// clang-format on

using mnl_ptr_t = std::unique_ptr<struct mnl_socket, mnl_socket_delete>;

namespace {
netlink_scheme::Action action_new(bool v)
{
	if (v)
		return netlink_scheme::Action::New;
	else
		return netlink_scheme::Action::Delete;
}
}

using namespace tll;

class NetLink : public tll::channel::Base<NetLink>
{
	mnl_ptr_t _socket;
	std::vector<char> _buf;
	std::vector<char> _buf_send;
	std::map<int, std::string> _ifmap;

	enum class Dump { Init, Link, Route, Addr, Done } _dump = Dump::Init;
	bool _request_addr:1;
	bool _request_route:1;
	int _af = AF_UNSPEC;

	int _request();

 public:
	static constexpr std::string_view channel_protocol() { return "netlink"; }
	static constexpr auto scheme_policy() { return Base::SchemePolicy::Manual; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);
	int _close();
	void _destroy();

	//int _post(const tll_msg_t *msg, int flags);
	int _process(long timeout, int flags);

 private:

	int _netlink_cb(const struct nlmsghdr *nlh);
	int _link(const struct nlmsghdr *nlh);
	int _addr(const struct nlmsghdr *nlh);

	template <template <typename B> typename T>
	int _route(const struct nlmsghdr *nlh, const struct rtmsg * rm);

	template <typename T>
	int _route_attr(const struct nlattr *attr, T & msg);
};

int NetLink::_init(const Channel::Url &url, Channel * master)
{
	_buf.resize(MNL_SOCKET_BUFFER_SIZE);

	if (_scheme_url)
		return _log.fail(EINVAL, "Netlink channel has it's own scheme, conflicts with init parameter");
	_scheme.reset(context().scheme_load(netlink_scheme::scheme_string));
	if (!_scheme.get())
		return _log.fail(EINVAL, "Failed to load netlink scheme");

	//if ((internal.caps & (caps::Input | caps::Output)) == caps::Input)
	//	return _log.fail(EINVAL, "NetLink channel is write-only");

	//if (!_scheme_url)
		//return _log.fail(EINVAL, "Channel needs scheme");

	auto reader = channel_props_reader(url);

	_request_addr = reader.getT("addr", true);
	_request_route = reader.getT("route", true);
	_af = reader.getT("af", AF_UNSPEC, {{"ipv4", AF_INET}, {"ipv6", AF_INET6}, {"any", AF_UNSPEC}});

	if (!reader)
		return _log.fail(EINVAL, "Invalid url: {}", reader.error());

	return 0;
}

int NetLink::_open(const tll::ConstConfig &s)
{
	_socket.reset(mnl_socket_open2(NETLINK_ROUTE, SOCK_NONBLOCK));
	if (!_socket)
		return _log.fail(EINVAL, "Failed to open netlink socket: {}", strerror(errno));

	unsigned groups = RTMGRP_LINK;
	if (_request_addr) {
		if (_af == AF_UNSPEC || _af == AF_INET)  groups |= RTMGRP_IPV4_IFADDR;
		if (_af == AF_UNSPEC || _af == AF_INET6) groups |= RTMGRP_IPV6_IFADDR;
	}
	if (_request_route) {
		if (_af == AF_UNSPEC || _af == AF_INET)  groups |= RTMGRP_IPV4_ROUTE;
		if (_af == AF_UNSPEC || _af == AF_INET6) groups |= RTMGRP_IPV6_ROUTE;
	}

	if (mnl_socket_bind(_socket.get(), groups, MNL_SOCKET_AUTOPID) < 0)
		return _log.fail(EINVAL, "Failed to bind netlink socket: {}", strerror(errno));

	_update_fd(mnl_socket_get_fd(_socket.get()));

	/*
	auto ifindex = if_nameindex();
	if (!ifindex)
		return _log.fail(EINVAL, "Failed to get interface index: {}", strerror(errno));
	for (auto ptr = ifindex; ptr->if_name; ptr++) {
		_log.info("Interface {}: {}", ptr->if_index, ptr->if_name);
		_ifmap[ptr->if_index] = ptr->if_name;
	}
	if_freenameindex(ifindex);
	*/

	_dump = Dump::Init;
	if (_request())
		return _log.fail(EINVAL, "Failed to request link dump");

	_update_dcaps(dcaps::CPOLLIN);

	return 0;
}

int NetLink::_request()
{
	switch (_dump) {
	case Dump::Done:
		return 0;
	case Dump::Init:
		_dump = Dump::Link; break;
	case Dump::Link:
		_dump = Dump::Addr;
		if (_request_addr) break;
	case Dump::Addr:
		_dump = Dump::Route;
		if (_request_route) break;
	case Dump::Route:
		_dump = Dump::Done;
	default:
		return 0;
	}

	auto req = mnl_nlmsg_put_header(_buf.data());
	req->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->nlmsg_seq = 0;

	if (_dump == Dump::Link) {
		req->nlmsg_type = RTM_GETLINK;
		mnl_nlmsg_put_extra_header(req, sizeof(struct ifinfomsg));
	} else if (_dump == Dump::Addr) {
		req->nlmsg_type = RTM_GETADDR;
		auto ifi = (struct ifaddrmsg *) mnl_nlmsg_put_extra_header(req, sizeof(struct ifaddrmsg));
		ifi->ifa_family = _af;
	} else if (_dump == Dump::Route) {
		req->nlmsg_type = RTM_GETROUTE;
		auto rtm = (struct rtmsg *) mnl_nlmsg_put_extra_header(req, sizeof(struct rtmsg));
		rtm->rtm_family = _af;
	}

	if (mnl_socket_sendto(_socket.get(), req, req->nlmsg_len) < 0)
		return _log.fail(EINVAL, "Failed to send route request: {}", strerror(errno));
	return 0;
}

int NetLink::_close()
{
	_update_fd(-1);
	_socket.reset();
	return 0;
}

int NetLink::_netlink_cb(const struct nlmsghdr * nlh)
{
	_log.trace("Netlink message: {}", nlh->nlmsg_type);
	switch (nlh->nlmsg_type) {
	case NLMSG_DONE:
		return MNL_CB_STOP;
	case NLMSG_ERROR: {
		auto error = static_cast<const struct nlmsgerr *>(mnl_nlmsg_get_payload(nlh));
		return _log.fail(MNL_CB_ERROR, "Netlink error message: {}", strerror(-error->error));
	}
	case RTM_NEWROUTE:
	case RTM_DELROUTE: {
		auto rm = static_cast<const struct rtmsg *>(mnl_nlmsg_get_payload(nlh));
		switch(rm->rtm_family) {
		case AF_INET:
			return _route<netlink_scheme::Route4>(nlh, rm);
		case AF_INET6:
			return _route<netlink_scheme::Route6>(nlh, rm);
		default:
			return _log.fail(MNL_CB_ERROR, "Unknown route family: {}", rm->rtm_family);
		}
	}
	case RTM_NEWADDR:
	case RTM_DELADDR:
		return _addr(nlh);

	case RTM_NEWLINK:
	case RTM_DELLINK:
		return _link(nlh);

	default:
		_log.debug("Unknown netlink message: {}", nlh->nlmsg_type);
	}
	return MNL_CB_OK;
}

int NetLink::_link(const struct nlmsghdr * nlh)
{
	auto ifi = static_cast<struct ifinfomsg *>(mnl_nlmsg_get_payload(nlh));

	std::string_view name;

	mnl_attr_parse(nlh, sizeof(*ifi), [](auto * attr, void * user) {
		if (mnl_attr_get_type(attr) != IFLA_IFNAME)
			return MNL_CB_OK;
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			return MNL_CB_ERROR;
		*static_cast<std::string_view *>(user) = mnl_attr_get_str(attr);
		return MNL_CB_OK;
	}, &name);

	/*
	if (nlh->nlmsg_type == RTM_NEWLINK)
		printf("[LINK] [NEW] ");
	else
		printf("[LINK] [DEL] ");

	printf("family=%u ", ifi->ifi_family);
	printf("type=%u ", ifi->ifi_type);
	printf("index=%d ", ifi->ifi_index);
	printf("flags=0x%x ", ifi->ifi_flags);
	printf("name=%s ", name.data());
	printf("\n");
	*/

	auto link = tll::scheme::make_binder<netlink_scheme::Link>(_buf_send);
	link.view().resize(link.meta_size());

	//netlink_scheme::Link link = {};
	link.set_index(ifi->ifi_index);
	link.set_name(name);
	link.set_action(action_new(nlh->nlmsg_type == RTM_NEWLINK));
	link.set_up((ifi->ifi_flags & IFF_UP) ? 1 : 0);

	auto it = _ifmap.find(ifi->ifi_index);
	if (nlh->nlmsg_type == RTM_NEWLINK) {
		if (it == _ifmap.end()) {
			_log.debug("New interface {}: {}", ifi->ifi_index, name);
			_ifmap[ifi->ifi_index] = name;
		} else {
			_log.debug("Update interface {}: {} {:x}", ifi->ifi_index, name, ifi->ifi_flags);
			it->second = name;
		}
	} else if (it != _ifmap.end()) {
		_log.debug("Delete interface {}: {}", ifi->ifi_index, name);
		_ifmap.erase(it);
	}

	tll_msg_t msg = {};
	msg.msgid = link.meta_id();
	msg.data = link.view().data();
	msg.size = link.view().size();

	_callback_data(&msg);

	return MNL_CB_OK;
}

template <template <typename B> typename T>
int NetLink::_route(const struct nlmsghdr * nlh, const struct rtmsg * rm)
{
	auto msg = tll::scheme::make_binder<T>(_buf_send);
	msg.view().resize(msg.meta_size());

	msg.set_action(action_new(nlh->nlmsg_type == RTM_NEWROUTE));
	msg.set_table(rm->rtm_table);
	msg.set_type(static_cast<netlink_scheme::RType>(rm->rtm_type));
	msg.set_dst_mask(rm->rtm_dst_len);
	msg.set_src_mask(rm->rtm_src_len);

	auto data = std::make_pair(this, &msg);
	mnl_attr_parse(nlh, sizeof(*rm), [](auto * attr, void * data) {
		auto pair = static_cast<std::pair<NetLink *, decltype(msg) *> *>(data);
		return pair->first->_route_attr(attr, *pair->second);
	}, &data);

	tll_msg_t message = {};
	message.msgid = msg.meta_id();
	message.data = msg.view().data();
	message.size = msg.view().size();

	_callback_data(&message);

	return MNL_CB_OK;
}

template <typename T>
int NetLink::_route_attr(const struct nlattr * attr, T & msg)
{
	auto type = mnl_attr_get_type(attr);

	switch(type) {
	case RTA_OIF: {
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return _log.fail(MNL_CB_ERROR, "Invalid type for oif: not u32");
		auto oif = mnl_attr_get_u32(attr);
		auto it = _ifmap.find(oif);
		if (it == _ifmap.end())
			return _log.fail(MNL_CB_ERROR, "Unknown interface index: {}", oif);
		msg.set_oif(it->second);
		break;
	}
	case RTA_DST:
	case RTA_SRC:
		if constexpr (sizeof(msg.get_dst()) == 4) {
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for ipv4 addr: not u32");
			auto addr = mnl_attr_get_u32(attr);
			if (type == RTA_DST)
				msg.set_dst(addr);
			else
				msg.set_src(addr);
		} else {
			if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for ipv6 addr: not in6_addr");
			//auto addr = static_cast<struct in6_addr *>(mnl_attr_get_payload(attr));
			std::string_view addr = {(const char *) mnl_attr_get_payload(attr), sizeof(struct in6_addr)};
			if (type == RTA_DST)
				msg.set_dst(addr);
			else
				msg.set_src(addr);
		}
		break;
	}
	return MNL_CB_OK;
}

int NetLink::_addr(const struct nlmsghdr * nlh)
{
	auto ifa = static_cast<const struct ifaddrmsg *>(mnl_nlmsg_get_payload(nlh));

	auto msg = tll::scheme::make_binder<netlink_scheme::Addr>(_buf_send);
	msg.view().resize(msg.meta_size());

	msg.set_action(action_new(nlh->nlmsg_type == RTM_NEWADDR));
	msg.set_index(ifa->ifa_index);
	msg.set_prefix(ifa->ifa_prefixlen);

	auto it = _ifmap.find(ifa->ifa_index);
	if (it == _ifmap.end())
		return _log.fail(MNL_CB_ERROR, "Unknown interface index: {}", ifa->ifa_index);
	msg.set_name(it->second);

	// Macro not C++ compatible, implicit cast from void *
	auto attr = (const struct nlattr *) mnl_nlmsg_get_payload_offset(nlh, sizeof(*ifa));
	auto tail = (const char *) mnl_nlmsg_get_payload_tail(nlh);
	for (; mnl_attr_ok(attr, tail - (char *)(attr)); attr = mnl_attr_next(attr)) {
		if (mnl_attr_get_type(attr) != IFA_ADDRESS)
			continue;
		if (ifa->ifa_family == AF_INET) {
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
				return _log.fail(EINVAL, "Invalid IFA_ADDRESS ipv4 attribute: {}", strerror(errno));
			msg.get_addr().set_ipv4(mnl_attr_get_u32(attr));
		} else if (ifa->ifa_family == AF_INET6) {
			if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) < 0)
				return _log.fail(EINVAL, "Invalid IFA_ADDRESS ipv6 attribute: {}", strerror(errno));
			std::string_view addr = {(const char *) mnl_attr_get_payload(attr), sizeof(struct in6_addr)};
			msg.get_addr().set_ipv6(addr);
		} else
			return _log.fail(EINVAL, "Unknow address family: {}", ifa->ifa_family);
		break;
	}

	tll_msg_t message = {};
	message.msgid = msg.meta_id();
	message.data = msg.view().data();
	message.size = msg.view().size();

	_callback_data(&message);

	return MNL_CB_OK;
}

int NetLink::_process(long timeout, int flags)
{
	int len = mnl_socket_recvfrom(_socket.get(), _buf.data(), _buf.size());
	if (len < 0) {
		if (errno == EAGAIN)
			return EAGAIN;
		return _log.fail(EINVAL, "Failed to recv netlink message: {}", strerror(errno));
	}

	auto nlh = static_cast<const struct nlmsghdr *>((void *) _buf.data());

	int r = 0;
	bool done = false;
	while (mnl_nlmsg_ok(nlh, len)) {
		if (nlh->nlmsg_flags & NLM_F_DUMP_INTR)
			return _log.fail(EINTR, "Netlink dump was interrupted");

		r = _netlink_cb(nlh);
		if (r == MNL_CB_ERROR)
			return _log.fail(EINVAL, "Failed to handle netlink message {}", nlh->nlmsg_type);
		else if (r == MNL_CB_STOP) {
			_log.info("Dump completed");
			done = true;
		}

		nlh = mnl_nlmsg_next(nlh, &len);
	}

	if (done)
		return _request();
	return 0;
}

TLL_DEFINE_IMPL(NetLink);

TLL_DEFINE_MODULE(NetLink);
