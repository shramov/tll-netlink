#ifndef _NL80211_CHANNEL_H
#define _NL80211_CHANNEL_H

#include "base.h"
#include "nl80211.h"

class NL80211 : public NLBase<NL80211>
{
	using Base = NLBase<NL80211>;

	uint32_t _family_id = 0;
	uint32_t _mcast_id = 0;

	std::map<int, std::string> _ifmap;

 public:
	static constexpr std::string_view channel_protocol() { return "nl80211"; }
	static constexpr auto open_policy() { return Base::OpenPolicy::Manual; }
	static constexpr std::string_view netlink_scheme_string() { return nl80211_scheme::scheme_string; }


	int _open(const tll::ConstConfig &);

	int _on_netlink_data(const struct nlmsghdr *nlh);
	int _on_netlink_done();

	int _on_id_ctrl(const struct nlmsghdr *nlh);
	int _on_family(const struct nlmsghdr *nlh);

	int _request_family_id();
	int _request_dump();
};

#endif//_NL80211_CHANNEL_H
