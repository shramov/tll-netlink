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

#include "netlink.h"

// clang-format off
struct mnl_socket_delete { void operator ()(struct mnl_socket *ptr) const { mnl_socket_close(ptr); } };
// clang-format on

using mnl_ptr_t = std::unique_ptr<struct mnl_socket, mnl_socket_delete>;

using namespace tll;

class NetLink : public tll::channel::Base<NetLink>
{
	mnl_ptr_t _socket;
	std::vector<char> _buf;
	std::map<int, std::string> _ifmap;

 public:
	static constexpr std::string_view channel_protocol() { return "netlink"; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::PropsView &);
	int _close();
	void _destroy();

	//int _post(const tll_msg_t *msg, int flags);
	int _process(long timeout, int flags);

 private:

	int _netlink_cb(const struct nlmsghdr *nlh);
	int _link(const struct nlmsghdr *nlh);

	template <typename T>
	int _route(const struct nlmsghdr *nlh, const struct rtmsg * rm);

	template <typename T>
	int _route_attr(const struct nlattr *attr, T & msg);
};

static std::string_view sqlite_scheme = "yamls://[{name: eof, id: 10}]";

int NetLink::_init(const Channel::Url &url, Channel * master)
{
	_buf.resize(MNL_SOCKET_BUFFER_SIZE);

	_scheme_control.reset(context().scheme_load(sqlite_scheme));
	if (!_scheme_control.get())
		return _log.fail(EINVAL, "Failed to load control scheme");

	//if ((internal.caps & (caps::Input | caps::Output)) == caps::Input)
	//	return _log.fail(EINVAL, "NetLink channel is write-only");

	//if (!_scheme_url)
		//return _log.fail(EINVAL, "Channel needs scheme");

	auto reader = channel_props_reader(url);

	/*
	_replace = reader.getT("replace", false);
	_seq_index = reader.getT("seq-index", Index::Unique, {{"no", Index::No}, {"yes", Index::Yes}, {"unique", Index::Unique}});
	_journal = reader.getT("journal", Journal::Wal, {{"wal", Journal::Wal}, {"default", Journal::Default}});
	_bulk_size = reader.getT("bulk-size", 0u);
	*/
	if (!reader)
		return _log.fail(EINVAL, "Invalid url: {}", reader.error());

	return 0;
}

int NetLink::_open(const PropsView &s)
{
	//unsigned int seq, portid;

	_socket.reset(mnl_socket_open2(NETLINK_ROUTE, SOCK_NONBLOCK));
	if (!_socket)
		return _log.fail(EINVAL, "Failed to open netlink socket: {}", strerror(errno));

	if (mnl_socket_bind(_socket.get(), RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE, MNL_SOCKET_AUTOPID) < 0)
		return _log.fail(EINVAL, "Failed to bind netlink socket: {}", strerror(errno));

	_update_fd(mnl_socket_get_fd(_socket.get()));

	auto ifindex = if_nameindex();
	if (!ifindex)
		return _log.fail(EINVAL, "Failed to get interface index: {}", strerror(errno));
	for (auto ptr = ifindex; ptr->if_name; ptr++) {
		_log.info("Interface {}: {}", ptr->if_index, ptr->if_name);
		_ifmap[ptr->if_index] = ptr->if_name;
	}

	/*
	auto nlh = mnl_nlmsg_put_header(_buf.data());
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = 0;
	auto ifi = (struct ifinfomsg *) mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_family = AF_UNSPEC;

	if (mnl_socket_sendto(_socket.get(), nlh, nlh->nlmsg_len) < 0)
		return _log.fail(EINVAL, "Failed to send link request: {}", strerror(errno));
	*/

	auto nlh = mnl_nlmsg_put_header(_buf.data());
	nlh->nlmsg_type = RTM_GETROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = 0;
	auto rtm = (struct rtmsg *) mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
	rtm->rtm_family = AF_INET;

	if (mnl_socket_sendto(_socket.get(), nlh, nlh->nlmsg_len) < 0)
		return _log.fail(EINVAL, "Failed to send route request: {}", strerror(errno));

	//portid = mnl_socket_get_portid(nl);

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
	switch(nlh->nlmsg_type) {
	case NLMSG_DONE:
		return MNL_CB_STOP;
	case NLMSG_ERROR:
		return _log.fail(MNL_CB_ERROR, "Netlink error message");
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

	return MNL_CB_OK;
}

template <typename T>
int NetLink::_route(const struct nlmsghdr * nlh, const struct rtmsg * rm)
{
	T msg = {};

	if (nlh->nlmsg_type == RTM_NEWROUTE) {
		msg.action = netlink_scheme::Action::New;
	} else {
		msg.action = netlink_scheme::Action::Delete;
	}

	msg.table = rm->rtm_table;
	msg.type = static_cast<netlink_scheme::RType>(rm->rtm_type);
	msg.dst_mask = rm->rtm_dst_len;
	msg.src_mask = rm->rtm_src_len;

	std::pair<NetLink *, T *> data = { this, &msg };
	mnl_attr_parse(nlh, sizeof(*rm), [](auto * attr, void * data) {
		auto pair = static_cast<std::pair<NetLink *, T *> *>(data);
		return pair->first->_route_attr(attr, *pair->second);
	}, &data);

	tll_msg_t message = {};
	message.msgid = T::msgid;
	message.data = &msg;
	message.size = sizeof(msg);

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
		memcpy(msg.oif.data(), it->second.data(), sizeof(msg.oif));
		break;
	}
	case RTA_DST:
	case RTA_SRC:
		if constexpr (sizeof(msg.dst) == 4) {
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for ipv4 addr: not u32");
			auto addr = mnl_attr_get_u32(attr);
			if (type == RTA_DST)
				msg.dst = addr;
			else
				msg.src = addr;
		} else {
			if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) < 0)
				return _log.fail(MNL_CB_ERROR, "Invalid type for ipv6 addr: not in6_addr");
			auto addr = static_cast<struct in6_addr *>(mnl_attr_get_payload(attr));
			if (type == RTA_DST)
				memcpy(msg.dst.data(), addr, sizeof(*addr));
			else
				memcpy(msg.src.data(), addr, sizeof(*addr));
		}
		break;
	}
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

	//r = mnl_cb_run(_buf.data(), r, 0, 0, [](auto * hdr, void * user) { return static_cast<NetLink *>(user)->_netlink_cb(hdr); }, this);

	auto nlh = static_cast<const struct nlmsghdr *>((void *) _buf.data());

	int r = 0;
	while (mnl_nlmsg_ok(nlh, len)) {
		if (nlh->nlmsg_flags & NLM_F_DUMP_INTR)
			return _log.fail(EINTR, "Netlink dump was interrupted");

		r = _netlink_cb(nlh);
		if (r == MNL_CB_ERROR)
			return _log.fail(EINVAL, "Failed to handle netlink message {}", nlh->nlmsg_type);
		else if (r == MNL_CB_STOP)
			_log.info("Dump completed");

		nlh = mnl_nlmsg_next(nlh, &len);
	}

	/*
	if (r == MNL_CB_ERROR) {
		return _log.fail(EINVAL, "Failed to run netlink callbacks: {}", strerror(errno));
	} else if (r == MNL_CB_STOP) {
		_log.debug("Data processed, close channel");
		//close();
	}
	*/

	return 0;
}

TLL_DEFINE_IMPL(NetLink);

auto channel_module = tll::make_channel_module<NetLink>();
