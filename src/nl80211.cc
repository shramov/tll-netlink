/*
 * Copyright (c) 2021 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <net/if.h>
#include <netinet/in.h>
#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/nl80211.h>

#include "tll/channel/base.h"
#include "tll/channel/module.h"
#include "tll/util/sockaddr.h"

#include "mnlutil.h"
#include "nl80211-channel.h"
#include "nl80211-enums.h"
#include "nl80211.h"

using namespace tll;

int NL80211::_init(const Channel::Url &url, Channel * master)
{
	_buf.resize(MNL_SOCKET_BUFFER_SIZE);

	if (_scheme_url)
		return _log.fail(EINVAL, "Netlink channel has it's own scheme, conflicts with init parameter");
	_scheme.reset(context().scheme_load(nl80211_scheme::scheme_string));
	if (!_scheme.get())
		return _log.fail(EINVAL, "Failed to load netlink scheme");

	auto reader = channel_props_reader(url);

	if (!reader)
		return _log.fail(EINVAL, "Invalid url: {}", reader.error());

	return 0;
}

int NL80211::_open(const tll::ConstConfig &s)
{
	_family_id = 0;
	_mcast_id = 0;

	_ifmap.clear();

	_socket.reset(mnl_socket_open2(NETLINK_GENERIC, SOCK_NONBLOCK));
	if (!_socket)
		return _log.fail(EINVAL, "Failed to open netlink socket: {}", strerror(errno));

	_update_fd(mnl_socket_get_fd(_socket.get()));

	if (_request_family_id())
		return _log.fail(EINVAL, "Failed to request link dump");

	_update_dcaps(dcaps::CPOLLIN);

	return 0;
}

int NL80211::_request_family_id()
{
	auto req = mnl_nlmsg_put_header(_buf.data());
	req->nlmsg_type = GENL_ID_CTRL;
	req->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req->nlmsg_seq = 0;

	auto genreq = (struct genlmsghdr*) mnl_nlmsg_put_extra_header(req, sizeof(struct genlmsghdr));
	genreq->cmd = CTRL_CMD_GETFAMILY; 
	genreq->version = 1;

	mnl_attr_put_strz(req, CTRL_ATTR_FAMILY_NAME, NL80211_GENL_NAME);

	if (mnl_socket_sendto(_socket.get(), req, req->nlmsg_len) < 0)
		return _log.fail(EINVAL, "Failed to send family request: {}", strerror(errno));
	return 0;
}

int NL80211::_request_dump()
{
	auto req = mnl_nlmsg_put_header(_buf.data());
	req->nlmsg_type = _family_id;
	req->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	req->nlmsg_seq = 0;

	auto genreq = (struct genlmsghdr*) mnl_nlmsg_put_extra_header(req, sizeof(struct genlmsghdr));
	genreq->cmd = NL80211_CMD_GET_INTERFACE; 
	//genreq->cmd = NL80211_CMD_GET_WIPHY; 
	//genreq->cmd = NL80211_CMD_GET_SCAN; 
	genreq->version = 1;

	mnl_attr_put_u32(req, NL80211_ATTR_IFINDEX, 3);

	if (mnl_socket_sendto(_socket.get(), req, req->nlmsg_len) < 0)
		return _log.fail(EINVAL, "Failed to send interface request: {}", strerror(errno));
	return 0;
}

int NL80211::_subscribe()
{
	if (mnl_socket_setsockopt(_socket.get(), NETLINK_ADD_MEMBERSHIP, &_mcast_id, sizeof(_mcast_id)))
		return _log.fail(EINVAL, "Failed to subscribe to nl80211 updates");
	return 0;
}

int NL80211::_close()
{
	_update_fd(-1);
	_socket.reset();
	return 0;
}

int NL80211::_netlink_cb(const struct nlmsghdr * nlh)
{
	_log.info("Netlink message: {}", nlh->nlmsg_type);
	if (_family_id && nlh->nlmsg_type == _family_id)
		return _on_family(nlh);

	switch (nlh->nlmsg_type) {
	case NLMSG_DONE:
		return MNL_CB_STOP;
	case NLMSG_ERROR: {
		auto error = static_cast<const struct nlmsgerr *>(mnl_nlmsg_get_payload(nlh));
		if (!error->error) {
			_log.info("Got genl ACK");
			return MNL_CB_OK;
		}
		return _log.fail(MNL_CB_ERROR, "Netlink error message: {}", strerror(-error->error));
	}
	case GENL_ID_CTRL:
		return _on_id_ctrl(nlh);

	default:
		_log.debug("Unknown netlink message: {}", nlh->nlmsg_type);
	}
	return MNL_CB_OK;
}

int NL80211::_on_id_ctrl(const struct nlmsghdr * nlh)
{
	auto genl = static_cast<const struct genlmsghdr *>(mnl_nlmsg_get_payload(nlh));

	_log.info("Got GENL_ID_CTRL: {} ({})", genl->cmd, CTRL_CMD_NEWFAMILY);
	if (state() == tll::state::Active) {
		_log.info("Skip control message, already active");
		return 0;
	}

	const struct nlattr * attr;
	mnl_attr_for_each(attr, nlh, sizeof(*genl)) {
		_log.debug("Attribute {}: {}", mnl_attr_get_type(attr), mnl_attr_get_len(attr));
		switch (mnl_attr_get_type(attr)) {
		case CTRL_ATTR_FAMILY_NAME:
			_log.debug("Family name: {}", mnl_attr_get_str(attr));
			break;
		case CTRL_ATTR_FAMILY_ID:
			_family_id = mnl_attr_get_u32(attr);
			_log.debug("Family id: {}", _family_id);
			break;
		case CTRL_ATTR_MCAST_GROUPS: {
			_log.debug("Dump multicast groups");
			const struct nlattr * mattr;
			mnl_attr_for_each_nested(mattr, attr) {
				const struct nlattr * grp;
				std::string_view name;
				uint32_t id = 0;
				mnl_attr_for_each_nested(grp, mattr) {
					_log.trace("Multicast group attribute {}: {}", mnl_attr_get_type(grp), mnl_attr_get_len(grp));
					switch (mnl_attr_get_type(grp)) {
					case CTRL_ATTR_MCAST_GRP_NAME:
						name = mnl_attr_get_str(grp);
						break;
					case CTRL_ATTR_MCAST_GRP_ID:
						id = mnl_attr_get_u32(grp);
						break;
					}
				}
				_log.debug("Multicast group {}: {}", name, id);
				if (name == NL80211_MULTICAST_GROUP_MLME)
					_mcast_id = id;
			}
			break;
		}
		}
	}

	if (_family_id == 0)
		return _log.fail(MNL_CB_ERROR, "Family ID not set");
	if (_mcast_id == 0)
		return _log.fail(MNL_CB_ERROR, "Multicast id not found for config group");
	if (_request_dump())
		return _log.fail(MNL_CB_ERROR, "Failed to request dump");
	state(tll::state::Active);

	return MNL_CB_OK;
}

struct __attribute__((packed)) IEHeader {
	uint8_t type;
	uint8_t size;
};

std::string printable(std::string_view src)
{
	std::string r(src);
	for (auto i = r.begin(); i != r.end(); i++) {
		if (!tll::util::printable(*i))
			*i = '.';
	}
	return r;
}

std::string_view parse_ie_ssid(const nlattr * attr)
{
	tll::memory data = {mnl_attr_get_payload(attr), mnl_attr_get_payload_len(attr) };
	auto view = tll::make_view(data);
	while (view.size()) {
		auto hdr = view.dataT<IEHeader>();
		//fmt::print("IE type: {}, size: {}, offset: {}\n", hdr->type, hdr->size, view.offset());
		if (hdr->type != 0) { // SSID id is 0
			view = view.view(sizeof(*hdr) + hdr->size);
			continue;
		}
		return std::string_view((const char *) (hdr + 1), hdr->size);
	}
	return "";
}

int NL80211::_on_family(const struct nlmsghdr * nlh)
{
	auto genl = static_cast<const struct genlmsghdr *>(mnl_nlmsg_get_payload(nlh));

	auto command = (nl80211_commands) genl->cmd;
	_log.debug("Got NL80211_GENL_NAME: {} ({})", nl80211_command_string(command), genl->cmd);

	auto msg = nl80211_scheme::Interface::bind_reset(_buf_send);

	const struct nlattr * attr;
	mnl_attr_for_each(attr, nlh, sizeof(*genl)) {
		auto type = mnl_attr_get_type(attr);
		auto data = printable({(const char *) mnl_attr_get_payload(attr), mnl_attr_get_payload_len(attr)});
		_log.debug("Attribute {} ({}): {}, data: '{}'", nl80211_attr_string((nl80211_attrs) type), type, mnl_attr_get_len(attr), data);
		switch (type) {
		case NL80211_ATTR_MAC: {
			auto ether = (const ether_addr *) mnl_attr_get_str(attr);
			_log.debug("NL80211_ATTR_MAC: {}", *ether);
			//msg.set_mac(std::string_view { (const char *) ether, 6 });
			break;
		}
		case NL80211_ATTR_WIPHY: _log.debug("NL80211_ATTR_WIPHY: {:x}", mnl_attr_get_u32(attr)); break;
		case NL80211_ATTR_IFINDEX:
			_log.debug("NL80211_ATTR_IFINDEX: {}", mnl_attr_get_u32(attr));
			msg.set_index(mnl_attr_get_u32(attr));
			break;
		case NL80211_ATTR_IFNAME:
			_log.debug("NL80211_ATTR_IFNAME: {}", mnl_attr_get_str(attr));
			msg.set_name(mnl_attr_get_str(attr));
			break;
		case NL80211_ATTR_SSID:
			_log.debug("NL80211_ATTR_SSID: {}", mnl_attr_get_str(attr));
			msg.set_ssid(mnl_attr_get_str(attr));
			break;
		case NL80211_ATTR_BSS: {
			_log.debug("Dump NL80211_ATTR_BSS");
			const struct nlattr * mattr;
			std::string_view ssid;
			mnl_attr_for_each_nested(mattr, attr) {
				type = mnl_attr_get_type(mattr);
				_log.debug("BSS Attribute {} ({}): {}", nl80211_bss_string((nl80211_bss) type), type, mnl_attr_get_len(mattr));
				if (type == NL80211_BSS_INFORMATION_ELEMENTS) {
					if (auto ssid = parse_ie_ssid(attr); ssid.size())
						msg.set_ssid(ssid);
				}
			}
			break;
		}
		case NL80211_ATTR_REQ_IE:
		case NL80211_ATTR_RESP_IE:
			if (auto ssid = parse_ie_ssid(attr); ssid.size())
				msg.set_ssid(ssid);
			break;
		}
	}

	auto name = msg.get_name();
	auto index = msg.get_index();
	msg.set_action(nl80211_scheme::Interface::Action::Update);

	if (command == NL80211_CMD_NEW_INTERFACE) {
		if (name.empty())
			return MNL_CB_OK;
		_log.info("New interface {}, index {}", name, msg.get_index());
		_ifmap[msg.get_index()] = name;
		msg.set_action(nl80211_scheme::Interface::Action::New);
	} else if (index) {
		auto it = _ifmap.find(index);
		if (it != _ifmap.end())
			msg.set_name(it->second);
	}

	switch (command) {
	case NL80211_CMD_NEW_INTERFACE:
	case NL80211_CMD_DISCONNECT:
	case NL80211_CMD_CONNECT:
		break;
	default:
		return MNL_CB_OK;
	}

	tll_msg_t m = {};
	m.msgid = msg.meta_id();
	m.data = msg.view().data();
	m.size = msg.view().size();

	_callback_data(&m);

	return MNL_CB_OK;
}

int NL80211::_process(long timeout, int flags)
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
		return _subscribe();
	return 0;
}
