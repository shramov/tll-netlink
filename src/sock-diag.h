#ifndef _SOCK_DIAG_CHANNEL_H
#define _SOCK_DIAG_CHANNEL_H

#include "base.h"
#include "scheme/sock-diag.h"

#include <tll/util/sockaddr.h>

class SockDiag : public NLBase<SockDiag>
{
	using Base = NLBase<SockDiag>;

	struct Filter
	{
		tll::network::sockaddr_any src;
		tll::network::sockaddr_any dst;
		unsigned state = 0;
	} _filter;

 public:
	static constexpr std::string_view channel_protocol() { return "sock-diag"; }
	static constexpr std::string_view netlink_scheme_string() { return sock_diag_scheme::scheme_string; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);

	int _post(const tll_msg_t * msg, int flags);

	int _on_netlink_data(const struct nlmsghdr *nlh);
	int _on_netlink_done();

	int _on_diag(const struct nlmsghdr *nlh);
	int _request(const Filter &filter, bool dump);
};

#endif//_SOCK_DIAG_CHANNEL_H
