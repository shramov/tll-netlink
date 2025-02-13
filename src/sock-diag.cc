/*
 * Copyright (c) 2021 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <libmnl/libmnl.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>

#include <tll/util/hostport.h>

#include "sock-diag.h"
#include "scheme/sock-diag-control.h"

using namespace tll;

int SockDiag::_init(const Channel::Url &url, Channel * master)
{
	if (auto r = Base::_init(url, master); r)
		return r;

	_scheme_control.reset(context().scheme_load(sock_diag_control_scheme::scheme_string));
	if (!_scheme_control.get())
		return _log.fail(EINVAL, "Failed to load netlink control scheme");


	auto reader = channel_props_reader(url);

	if (!reader)
		return _log.fail(EINVAL, "Invalid url: {}", reader.error());

	return 0;
}

int SockDiag::_open(const tll::ConstConfig &cfg)
{
	if (auto r = Base::_netlink_open(NETLINK_SOCK_DIAG); r)
		return r;

	using AddressFamily = tll::network::AddressFamily;
	auto reader = tll::make_props_reader(cfg);
	auto af = reader.getT("af", AddressFamily::INET);
	auto src = reader.getT("src", std::optional<tll::network::hostport> {});
	auto dst = reader.getT("dst", std::optional<tll::network::hostport> {});
	auto dump = reader.getT("dump", false);
	if (!reader)
		return _log.fail(EINVAL, "Invalid open params: {}", reader.error());

	Filter filter = {};
	if (src) {
		if (src->set_af(af))
			return _log.fail(EINVAL, "Mismatched address family for src address: parameter {}, parsed {}", af, src->af);
		if (auto r = src->resolve(SOCK_STREAM); r)
			filter.src = r->front();
		else
			return _log.fail(EINVAL, "Failed to resolve {}: {}", src->host, r.error());
	}

	if (dst) {
		if (dst->set_af(af))
			return _log.fail(EINVAL, "Mismatched address family for dst address: parameter {}, parsed {}", af, dst->af);
		if (auto r = dst->resolve(SOCK_STREAM); r)
			filter.dst = r->front();
		else
			return _log.fail(EINVAL, "Failed to resolve {}: {}", dst->host, r.error());
	}

	filter.src->sa_family = filter.dst->sa_family = af;
	if (af == AF_INET)
		filter.src.size = filter.dst.size = sizeof(sockaddr_in);
	else if (af == AF_INET6)
		filter.src.size = filter.dst.size = sizeof(sockaddr_in6);
	if (dump)
		return _request(filter, true);
	return 0;
}

int SockDiag::_request(const Filter &filter, bool dump)
{
	_log.info("Filter {} -> {}", tll::conv::to_string(filter.src), tll::conv::to_string(filter.dst));

	auto req = mnl_nlmsg_put_header(_buf.data());
	req->nlmsg_flags = NLM_F_REQUEST;
	if (dump)
		req->nlmsg_flags |= NLM_F_DUMP;
	req->nlmsg_seq = 0;

	req->nlmsg_type = SOCK_DIAG_BY_FAMILY;
	auto ireq = (struct inet_diag_req_v2 *) mnl_nlmsg_put_extra_header(req, sizeof(struct inet_diag_req_v2));
	ireq->sdiag_family = filter.src->sa_family;
	ireq->sdiag_protocol = IPPROTO_TCP;
	ireq->idiag_ext |= 1 << (INET_DIAG_INFO - 1);
	ireq->idiag_states |= filter.state;
	if (ireq->idiag_states == 0)
		ireq->idiag_states = (1 << (TCP_CLOSING + 1)) - 1;
	if (filter.src->sa_family == AF_INET) {
		ireq->id.idiag_src[0] = filter.src.in()->sin_addr.s_addr;
		ireq->id.idiag_dst[0] = filter.dst.in()->sin_addr.s_addr;
	} else {
		memcpy(&ireq->id.idiag_src, &filter.src.in6()->sin6_addr, 16);
		memcpy(&ireq->id.idiag_dst, &filter.dst.in6()->sin6_addr, 16);
	}
	ireq->id.idiag_sport = filter.src.in()->sin_port;
	ireq->id.idiag_dport = filter.dst.in()->sin_port;
	ireq->id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
	ireq->id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;

	if (mnl_socket_sendto(_socket.get(), req, req->nlmsg_len) < 0)
		return _log.fail(EINVAL, "Failed to send dump request: {}", strerror(errno));
	return 0;
}

int SockDiag::_post(const tll_msg_t *msg, int flags)
{
	if (msg->type != TLL_MESSAGE_CONTROL)
		return _log.fail(EINVAL, "Data post not supported");

	Filter filter = {};
	switch (msg->msgid) {
	case sock_diag_control_scheme::DumpTcp4::meta_id(): {
		auto req = sock_diag_control_scheme::DumpTcp4::bind(*msg);
		filter.src->sa_family = filter.dst->sa_family = AF_INET;
		filter.src.size = filter.dst.size = sizeof(sockaddr_in);
		filter.src.in()->sin_addr.s_addr = req.get_saddr();
		filter.dst.in()->sin_addr.s_addr = req.get_daddr();
		filter.src.in()->sin_port = htons(req.get_sport());
		filter.dst.in()->sin_port = htons(req.get_dport());
		filter.state = req.get_state();
		return _request(filter, req.get_mode() == sock_diag_control_scheme::Mode::Dump);
	}
	case sock_diag_control_scheme::DumpTcp6::meta_id(): {
		auto req = sock_diag_control_scheme::DumpTcp6::bind(*msg);
		filter.src->sa_family = filter.dst->sa_family = AF_INET6;
		filter.src.size = filter.dst.size = sizeof(sockaddr_in6);
		memcpy(&filter.src.in6()->sin6_addr, req.get_saddr().data(), 16);
		memcpy(&filter.dst.in6()->sin6_addr, req.get_daddr().data(), 16);
		filter.src.in6()->sin6_port = htons(req.get_sport());
		filter.dst.in6()->sin6_port = htons(req.get_dport());
		filter.state = req.get_state();
		return _request(filter, req.get_mode() == sock_diag_control_scheme::Mode::Dump);
	}
	}
	return _log.fail(EINVAL, "Unknown control messaage {}", msg->msgid);
}

int SockDiag::_on_netlink_done()
{
	tll_msg_t msg = {
		.type = TLL_MESSAGE_CONTROL,
		.msgid = sock_diag_control_scheme::EndOfData::meta_id()
	};
	_callback(&msg);
	return 0;
}

int SockDiag::_on_netlink_data(const struct nlmsghdr * nlh)
{
	_log.debug("Netlink message: {}", nlh->nlmsg_type);

	switch (nlh->nlmsg_type) {
	case NLMSG_DONE:
		return MNL_CB_STOP;
	case NLMSG_ERROR: {
		auto error = static_cast<const struct nlmsgerr *>(mnl_nlmsg_get_payload(nlh));
		_log.warning("Netlink error message: {}", strerror(-error->error));
		auto data = sock_diag_control_scheme::Error::bind_reset(_buf_send);
		data.set_code(-error->error);
		data.set_text(strerror(-error->error));
		tll_msg_t msg = {
			.type = TLL_MESSAGE_CONTROL,
			.msgid = data.meta_id(),
			.data = data.view().data(),
			.size = data.view().size(),
		};
		_callback(&msg);
		return MNL_CB_OK;
	}
	case SOCK_DIAG_BY_FAMILY: {
		auto idiag = static_cast<struct inet_diag_msg *>(mnl_nlmsg_get_payload(nlh));
		if (idiag->idiag_family == AF_INET)
			return _on_diag<sock_diag_scheme::InfoTcp4>(nlh);
		else if (idiag->idiag_family == AF_INET6)
			return _on_diag<sock_diag_scheme::InfoTcp6>(nlh);
		else
			return _log.fail(MNL_CB_ERROR, "Unsupported address family: {}", idiag->idiag_family);
	}
	default:
		_log.debug("Unknown netlink message: {}", nlh->nlmsg_type);
	}
	return MNL_CB_OK;
}

template <typename T>
int SockDiag::_on_diag(const struct nlmsghdr * nlh)
{
	auto idiag = static_cast<struct inet_diag_msg *>(mnl_nlmsg_get_payload(nlh));
	auto id = &idiag->id;

	auto data = T::bind_reset(_buf_send);
	data.set_sport(ntohs(id->idiag_sport));
	data.set_dport(ntohs(id->idiag_dport));
	if constexpr (std::is_same_v<T, sock_diag_scheme::InfoTcp4>) {
		data.set_saddr(id->idiag_src[0]);
		data.set_daddr(id->idiag_dst[0]);
	} else {
		data.set_saddr(std::string_view((char *) id->idiag_src, 16));
		data.set_daddr(std::string_view((char *) id->idiag_dst, 16));
	}
	data.set_state((sock_diag_scheme::TcpState) idiag->idiag_state);

	const struct nlattr * attr;
	mnl_attr_for_each(attr, nlh, sizeof(*idiag)) {
		_log.debug("Attribute {}: {}", mnl_attr_get_type(attr), mnl_attr_get_len(attr));
		switch (mnl_attr_get_type(attr)) {
		case INET_DIAG_INFO: {
			auto info = static_cast<struct tcp_info *>(mnl_attr_get_payload(attr));
			data.set_rtt(std::chrono::microseconds(info->tcpi_rtt));
			break;
		}
		}
	}

	tll_msg_t msg = {
		.msgid = data.meta_id(),
		.data = data.view().data(),
		.size = data.view().size(),
	};
	_callback_data(&msg);
	return MNL_CB_OK;
}
