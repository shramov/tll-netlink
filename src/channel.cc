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
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>

#include <deque>

#include "mnlutil.h"

#include "tll/channel/base.h"
#include "tll/channel/module.h"

#include "netlink.h"
#include "netlink-control.h"

#include "monitor.h"
#include "nl80211-channel.h"

namespace {
netlink_scheme::Action action_new(bool v)
{
	if (v)
		return netlink_scheme::Action::New;
	else
		return netlink_scheme::Action::Delete;
}

template <typename Buf>
tll::result_t<int> addr_fill(netlink_scheme::IPAny<Buf> addr, int af, const nlattr *attr)
{
	if (af == AF_INET) {
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return tll::error("Invalid ipv4 attribute");
		addr.set_ipv4(mnl_attr_get_u32(attr));
	} else if (af == AF_INET6) {
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) < 0)
			return tll::error("Invalid ipv6 attribute");
		addr.set_ipv6({mnl_attr_get_str(attr), sizeof(struct in6_addr)});
	} else
		return tll::error(fmt::format("Unknow address family: {}", af));
	return 0;
}
}

using namespace tll;

class NetLink : public tll::channel::Base<NetLink>
{
	mnl_ptr_t _socket;
	std::vector<char> _buf;
	std::vector<char> _buf_send;
	std::map<int, std::string> _ifmap;

	enum class Dump { Init, Link, Route, Addr, Neigh, Done };
	std::deque<Dump> _dump;
	bool _autoclose:1;
	bool _request_addr:1;
	bool _request_route:1;
	bool _request_neigh:1;
	int _af = AF_UNSPEC;

	int _request();

 public:
	static constexpr std::string_view channel_protocol() { return "netlink"; }
	static constexpr auto scheme_policy() { return Base::SchemePolicy::Manual; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);
	int _close();
	void _destroy();

	int _post(const tll_msg_t *msg, int flags);
	int _process(long timeout, int flags);

 private:

	int _netlink_cb(const struct nlmsghdr *nlh);
	int _link(const struct nlmsghdr *nlh);
	int _addr(const struct nlmsghdr *nlh);
	int _neigh(const struct nlmsghdr *nlh);

	template <typename Buf>
	int _bond(typename netlink_scheme::Bond::binder_type<Buf> li, const struct nlattr * nest);

	template <typename Buf>
	int _bond_slave(typename netlink_scheme::BondSlave::binder_type<Buf> li, const struct nlattr * nest);

	template <typename T>
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

	_scheme_control.reset(context().scheme_load(netlink_control_scheme::scheme_string));
	if (!_scheme_control.get())
		return _log.fail(EINVAL, "Failed to load netlink control scheme");

	//if ((internal.caps & (caps::Input | caps::Output)) == caps::Input)
	//	return _log.fail(EINVAL, "NetLink channel is write-only");

	//if (!_scheme_url)
		//return _log.fail(EINVAL, "Channel needs scheme");

	auto reader = channel_props_reader(url);

	_autoclose = reader.getT("autoclose", false);
	_request_addr = reader.getT("addr", true);
	_request_route = reader.getT("route", true);
	_request_neigh = reader.getT("neigh", true);
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

	_dump.clear();
	_dump.push_back(Dump::Link);
	unsigned groups = RTMGRP_LINK;
	if (_request_addr) {
		_dump.push_back(Dump::Addr);
		if (_af == AF_UNSPEC || _af == AF_INET)  groups |= RTMGRP_IPV4_IFADDR;
		if (_af == AF_UNSPEC || _af == AF_INET6) groups |= RTMGRP_IPV6_IFADDR;
	}
	if (_request_route) {
		_dump.push_back(Dump::Route);
		if (_af == AF_UNSPEC || _af == AF_INET)  groups |= RTMGRP_IPV4_ROUTE;
		if (_af == AF_UNSPEC || _af == AF_INET6) groups |= RTMGRP_IPV6_ROUTE;
	}
	if (_request_neigh) {
		_dump.push_back(Dump::Neigh);
		groups |= RTMGRP_NEIGH;
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

	if (_request())
		return _log.fail(EINVAL, "Failed to request link dump");

	_update_dcaps(dcaps::CPOLLIN);

	return 0;
}

int NetLink::_request()
{
	if (_dump.empty()) {
		tll_msg_t msg = { TLL_MESSAGE_CONTROL };
		msg.msgid = netlink_control_scheme::EndOfData::meta_id();
		_callback(&msg);
		if (_autoclose)
			close();
		return 0;
	}
	Dump dump = _dump.front();
	_dump.pop_front();

	auto req = mnl_nlmsg_put_header(_buf.data());
	req->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->nlmsg_seq = 0;

	if (dump == Dump::Link) {
		req->nlmsg_type = RTM_GETLINK;
		mnl_nlmsg_put_extra_header(req, sizeof(struct ifinfomsg));
	} else if (dump == Dump::Addr) {
		req->nlmsg_type = RTM_GETADDR;
		auto ifi = (struct ifaddrmsg *) mnl_nlmsg_put_extra_header(req, sizeof(struct ifaddrmsg));
		ifi->ifa_family = _af;
	} else if (dump == Dump::Route) {
		req->nlmsg_type = RTM_GETROUTE;
		auto rtm = (struct rtmsg *) mnl_nlmsg_put_extra_header(req, sizeof(struct rtmsg));
		rtm->rtm_family = _af;
	} else if (dump == Dump::Neigh) {
		req->nlmsg_type = RTM_GETNEIGH;
		auto ndm = (struct ndmsg *) mnl_nlmsg_put_extra_header(req, sizeof(struct ndmsg));
		ndm->ndm_family = _af;
	} else
		return 0;

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

	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		return _neigh(nlh);

	default:
		_log.debug("Unknown netlink message: {}", nlh->nlmsg_type);
	}
	return MNL_CB_OK;
}

int NetLink::_link(const struct nlmsghdr * nlh)
{
	using Type = netlink_scheme::Link::Type;

	auto ifi = static_cast<struct ifinfomsg *>(mnl_nlmsg_get_payload(nlh));

	std::string_view name;

	auto link = netlink_scheme::Link::bind(_buf_send);
	link.view_resize();

	//netlink_scheme::Link link = {};
	link.set_index(ifi->ifi_index);
	link.set_type_raw(ifi->ifi_type);

	switch (ifi->ifi_type) {
	case ARPHRD_ETHER: link.set_type(Type::Ether); break;
	case ARPHRD_LOOPBACK: link.set_type(Type::Loopback); break;
	case ARPHRD_TUNNEL: link.set_type(Type::Tunnel); break;
	case ARPHRD_INFINIBAND: link.set_type(Type::Infiniband); break;
	case ARPHRD_NONE: link.set_type(Type::None); break;
	case ARPHRD_VOID: link.set_type(Type::Void); break;
	default:
		link.set_type(Type::Other);
		break;
	}
	link.set_action(action_new(nlh->nlmsg_type == RTM_NEWLINK));
	link.set_flags(ifi->ifi_flags);
	link.set_up(link.get_flags().Up());

	const struct nlattr * attr;
	mnl_attr_for_each(attr, nlh, sizeof(*ifi)) {
		switch (mnl_attr_get_type(attr)) {
		case IFLA_IFNAME:
			if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
				return _log.fail(EINVAL, "Invalid IFLA_IFNAME attribute");;
			name = mnl_attr_get_str(attr);
			break;
		case IFLA_ADDRESS:
			if (mnl_attr_get_payload_len(attr) == 6)
				link.set_lladdr({mnl_attr_get_str(attr), 6});
			break;
		case IFLA_LINKINFO: {
			_log.info("Link info");
			const struct nlattr * lia;
			std::string_view kind, kind_slave;
			mnl_attr_for_each_nested(lia, attr) {
				switch (mnl_attr_get_type(lia)) {
				case IFLA_INFO_KIND:
					kind = mnl_attr_get_str(lia);
					_log.debug("Link info kind: {}", kind);
					break;
				case IFLA_INFO_SLAVE_KIND:
					kind_slave = mnl_attr_get_str(lia);
					_log.debug("Link info slave kind: {}", kind);
					break;
				case IFLA_INFO_DATA:
					_log.debug("Link info data {}", mnl_attr_get_payload_len(lia));
					if (kind == "bond" && _bond(link.get_linkinfo().set_bond(), lia))
						return _log.fail(EINVAL, "Failed to parse bond data");
					break;
				case IFLA_INFO_SLAVE_DATA:
					_log.debug("Link info slave data {}", mnl_attr_get_payload_len(lia));
					if (kind_slave == "bond" && _bond_slave(link.get_linkinfo().set_bond_slave(), lia))
						return _log.fail(EINVAL, "Failed to parse bond slave data");
					break;
				default:
					break;
				}
			}
		}
		default:
			break;
		}
	}

	if (name.empty())
		return _log.fail(EINVAL, "Empty link name");
	link.set_name(name);

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

template <typename Buf>
int NetLink::_bond(typename netlink_scheme::Bond::binder_type<Buf> li, const struct nlattr * nest)
{
	const struct nlattr * attr;
	mnl_attr_for_each_nested(attr, nest) {
		_log.debug("Bond attribute {} {}", mnl_attr_get_type(attr), mnl_attr_get_payload_len(attr));
		switch (mnl_attr_get_type(attr)) {
		case IFLA_BOND_MODE:
			if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for IFLA_BOND_MODE: not u8");
			li.set_mode(static_cast<netlink_scheme::Bond::mode>(mnl_attr_get_u8(attr)));
			break;
		case IFLA_BOND_AD_SELECT:
			if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for IFLA_BOND_AD_SELECT: not u8");
			li.set_ad_select(mnl_attr_get_u8(attr));
			break;
		case IFLA_BOND_ACTIVE_SLAVE:
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for IFLA_BOND_ACTIVE_SLAVE: not u32");
			li.set_active_slave(mnl_attr_get_u32(attr));
			break;
		case IFLA_BOND_AD_INFO: {
			const struct nlattr * ada;
			mnl_attr_for_each_nested(ada, attr) {
				_log.debug("AD info attribute {} {}", mnl_attr_get_type(ada), mnl_attr_get_payload_len(ada));
				switch (mnl_attr_get_type(ada)) {
				case IFLA_BOND_AD_INFO_PARTNER_MAC:
					if (mnl_attr_get_payload_len(ada) == 6)
						li.set_ad_partner_mac({mnl_attr_get_str(ada), 6});
					break;
				default:
					break;
				}
			}
			break;
		}
		default:
			break;
		}
	}
	return 0;
}

template <typename Buf>
int NetLink::_bond_slave(typename netlink_scheme::BondSlave::binder_type<Buf> li, const struct nlattr * nest)
{
	const struct nlattr * attr;
	mnl_attr_for_each_nested(attr, nest) {
		_log.debug("Bond slave attribute {} {}", mnl_attr_get_type(attr), mnl_attr_get_payload_len(attr));
		switch (mnl_attr_get_type(attr)) {
		case IFLA_BOND_SLAVE_STATE:
			if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for IFLA_BOND_SLAVE_STATE: not u8");
			li.set_state(static_cast<typename netlink_scheme::BondSlave::state>(mnl_attr_get_u8(attr)));
			break;
		case IFLA_BOND_SLAVE_MII_STATUS:
			if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for IFLA_BOND_SLAVE_MII_STATUS: not u8");
			li.set_mii_status(static_cast<typename netlink_scheme::BondSlave::mii_status>(mnl_attr_get_u8(attr)));
			break;
		default:
			break;
		}
	}
	return 0;
}

int NetLink::_neigh(const struct nlmsghdr * nlh)
{
	auto ndm = static_cast<struct ndmsg *>(mnl_nlmsg_get_payload(nlh));

	auto it = _ifmap.find(ndm->ndm_ifindex);
	if (it == _ifmap.end())
		return _log.fail(MNL_CB_ERROR, "Unknown interface index: {}", ndm->ndm_ifindex);

	std::string_view name = it->second;

	_log.debug("Neigh update: {} family {}", name, ndm->ndm_family);

	auto data = netlink_scheme::Neigh::bind(_buf_send);
	data.view_resize();

	data.set_index(ndm->ndm_ifindex);
	data.set_name(name);
	data.set_action(action_new(nlh->nlmsg_type == RTM_NEWNEIGH));
	data.set_state(ndm->ndm_state);

	const struct nlattr * attr;
	mnl_attr_for_each(attr, nlh, sizeof(*ndm)) {
		switch (mnl_attr_get_type(attr)) {
		case NDA_LLADDR:
			data.set_lladdr({mnl_attr_get_str(attr), 6});
			break;
		case NDA_DST:
			if (auto r = addr_fill(data.get_addr(), ndm->ndm_family, attr); !r)
				return _log.fail(EINVAL, "Failed to parse NDM_DST: {}", r.error());
			break;
		default:
			break;
		}
	}

	tll_msg_t msg = {};
	msg.msgid = data.meta_id();
	msg.data = data.view().data();
	msg.size = data.view().size();

	_callback_data(&msg);

	return MNL_CB_OK;
}

template <typename T>
int NetLink::_route(const struct nlmsghdr * nlh, const struct rtmsg * rm)
{
	auto msg = T::bind(_buf_send);
	msg.view_resize();

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

	auto msg = netlink_scheme::Addr::bind(_buf_send);
	msg.view().resize(msg.meta_size());

	msg.set_action(action_new(nlh->nlmsg_type == RTM_NEWADDR));
	msg.set_index(ifa->ifa_index);
	msg.set_prefix(ifa->ifa_prefixlen);

	auto it = _ifmap.find(ifa->ifa_index);
	if (it == _ifmap.end())
		return _log.fail(MNL_CB_ERROR, "Unknown interface index: {}", ifa->ifa_index);
	msg.set_name(it->second);

	const struct nlattr * attr;
	mnl_attr_for_each(attr, nlh, sizeof(*ifa)) {
		if (mnl_attr_get_type(attr) != IFA_ADDRESS)
			continue;
		if (auto r = addr_fill(msg.get_addr(), ifa->ifa_family, attr); !r)
			return _log.fail(EINVAL, "Failed to parse IFA_ADDRESS: {}", r.error());
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

int NetLink::_post(const tll_msg_t *msg, int flags)
{
	if (msg->type != TLL_MESSAGE_CONTROL)
		return _log.fail(EINVAL, "Data post not supported");

	if (msg->msgid != netlink_control_scheme::Dump::meta_id())
		return _log.fail(EINVAL, "Unknown control messaage {}", msg->msgid);
	auto req = netlink_control_scheme::Dump::bind(*msg);
	auto init = _dump.empty();
	if (req.get_request().Link()) _dump.push_back(Dump::Link);
	if (req.get_request().Addr()) _dump.push_back(Dump::Addr);
	if (req.get_request().Route()) _dump.push_back(Dump::Route);
	if (req.get_request().Neigh()) _dump.push_back(Dump::Neigh);
	if (init) {
		if (_request())
			return _log.fail(EINVAL, "Failed to request link dump");
	}
	return 0;
}

TLL_DEFINE_IMPL(NetLink);
TLL_DEFINE_IMPL(NL80211);
TLL_DEFINE_IMPL(Monitor);

TLL_DEFINE_MODULE(NetLink, NL80211, Monitor);
