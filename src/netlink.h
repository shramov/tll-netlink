#pragma once

#include <tll/scheme/types.h>

#pragma pack(push, 1)
namespace netlink_scheme {

enum class Action : int8_t { New = 0, Delete = 1 };
enum class RType : int8_t
{
	UNSPEC = 0,
	UNICAST = 1,
	LOCAL = 2,
	BROADCAST = 3,
	ANYCAST = 4,
	MULTICAST = 5,
	BLACKHOLE = 6,
	UNREACHABLE = 7,
	PROHIBIT = 8,
	THROW = 9,
	NAT = 10,
	XRESOLVE = 11,
	MAX = 12,
};

typedef uint32_t ipv4;
typedef tll::scheme::Bytes<16> ipv6;
typedef tll::scheme::ByteString<16> interface;

struct Route4
{
	static const int msgid = 20;
	Action action;
	uint32_t table;
	RType type;
	interface oif;
	uint8_t dst_mask;
	ipv4 dst;
	uint8_t src_mask;
	ipv4 src;
};

struct Route6
{
	static const int msgid = 30;
	Action action;
	uint32_t table;
	RType type;
	interface oif;
	uint8_t dst_mask;
	ipv6 dst;
	uint8_t src_mask;
	ipv6 src;
};

} // namespace netlink_scheme
#pragma pack(pop)
