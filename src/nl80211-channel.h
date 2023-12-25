#ifndef _NL80211_CHANNEL_H
#define _NL80211_CHANNEL_H

#include <tll/channel/base.h>

class NL80211 : public tll::channel::Base<NL80211>
{
	mnl_ptr_t _socket;
	std::vector<char> _buf;
	std::vector<char> _buf_send;

	uint32_t _family_id = 0;
	uint32_t _mcast_id = 0;

	std::map<int, std::string> _ifmap;

 public:
	static constexpr std::string_view channel_protocol() { return "nl80211"; }
	static constexpr auto scheme_policy() { return Base::SchemePolicy::Manual; }
	static constexpr auto open_policy() { return Base::OpenPolicy::Manual; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);
	int _close();
	void _destroy();

	int _process(long timeout, int flags);

 private:

	int _netlink_cb(const struct nlmsghdr *nlh);
	int _on_id_ctrl(const struct nlmsghdr *nlh);
	int _on_family(const struct nlmsghdr *nlh);

	int _request_family_id();
	int _request_dump();
	int _subscribe();
};

#endif//_NL80211_CHANNEL_H
