#ifndef _NETLINK_BASE_H
#define _NETLINK_BASE_H

#include <tll/channel/base.h>

#include "mnlutil.h"

template <typename T>
class NLBase : public tll::channel::Base<T>
{
 protected:
	mnl_ptr_t _socket;
	std::vector<char> _buf;
	std::vector<char> _buf_send;

 public:
	using Base = tll::channel::Base<T>;
	static constexpr auto scheme_policy() { return Base::SchemePolicy::Manual; }
	static constexpr std::string_view netlink_scheme_string();

	int _init(const tll::Channel::Url &url, tll::Channel *master)
	{
		if (auto r = Base::_init(url, master); r)
			return r;
		_buf.resize(MNL_SOCKET_BUFFER_SIZE);

		if (this->_scheme_url)
			return this->_log.fail(EINVAL, "Netlink channel has it's own scheme, conflicts with init parameter");
		this->_scheme.reset(this->context().scheme_load(T::netlink_scheme_string()));
		if (!this->_scheme.get())
			return this->_log.fail(EINVAL, "Failed to load netlink scheme");
		return 0;
	}

	int _netlink_open(int family)
	{
		_socket.reset(mnl_socket_open2(family, SOCK_NONBLOCK));
		if (!_socket)
			return this->_log.fail(EINVAL, "Failed to open netlink socket: {}", strerror(errno));

		this->_update_fd(mnl_socket_get_fd(_socket.get()));
		this->_update_dcaps(tll::dcaps::CPOLLIN);
		return 0;
	}

	int _close()
	{
		this->_update_fd(-1);
		_socket.reset();
		return 0;
	}

	int _process(long timeout, int flags);

	int _on_netlink_data(const struct nlmsghdr *nlh);
	int _on_netlink_done() { return 0; }
};

template <typename T>
int NLBase<T>::_process(long timeout, int flags)
{
	int len = mnl_socket_recvfrom(_socket.get(), _buf.data(), _buf.size());
	if (len < 0) {
		if (errno == EAGAIN)
			return EAGAIN;
		return this->_log.fail(EINVAL, "Failed to recv netlink message: {}", strerror(errno));
	}

	auto nlh = static_cast<const struct nlmsghdr *>((void *) _buf.data());

	int r = 0;
	bool done = false;
	while (mnl_nlmsg_ok(nlh, len)) {
		if (nlh->nlmsg_flags & NLM_F_DUMP_INTR)
			return this->_log.fail(EINTR, "Netlink dump was interrupted");

		r = this->channelT()->_on_netlink_data(nlh);
		if (r == MNL_CB_ERROR)
			return this->_log.fail(EINVAL, "Failed to handle netlink message {}", nlh->nlmsg_type);
		else if (r == MNL_CB_STOP) {
			this->_log.info("Dump completed");
			done = true;
		}

		nlh = mnl_nlmsg_next(nlh, &len);
	}

	if (done)
		return this->channelT()->_on_netlink_done();
	return 0;
}

#endif//_NETLINK_BASE_H
