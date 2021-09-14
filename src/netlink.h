#pragma once

#include <tll/scheme/types.h>

#pragma pack(push, 1)
namespace netlink_scheme {

static constexpr std::string_view scheme_string =
    R"(yamls+gz://eJzlU01vgkAQvfdX7G0vmIhaar2tSIIpFbOitacGZW02IhBZ2hrjf+8sH1q7Gtt67Ik3zJuP9wZqKPJXrIMwvkGIRdkq7QBACJO54HGEO2grNgkQeCTaWs6AV7jHQiYYZHUN4QF7B1Tf7YpK6kHBuUIyeDbJyIN0Cyq7DjEfbNexIDZkTF3SK/NNiB3XJA7gBuBHMpXzcjh2vH5Ju5ULEIn0OsAhde1+ty9jmIo9m7pPgO8BjwdVjZ5H1CKmTbr58Lv8zWhomVIJBFNqjVxnInO6nivzQ+6nrLSnhralbzx5a2ENFVpxBmqbDbxTScaBNNsIphsqKRJsvfDnTGFqKE7kNVLpoCjcxalY8+gVw2616oYOj5byjjyQbgBYcBYGysp+cdr9lPLU6j4B+ziwTiuTj9/ue9whS47ta+MvimicCdaqNDWu1iT8WcgunitfeU8qvufvnJgvrtMdpOJl5adLVb3Cu7hwup7/qBfwTvQ6dtuo3G7+e7fP/Kh/cnvf6xMdeI6x)";

enum class Action : int8_t
{
	New = 0,
	Delete = 1,
};

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

struct Link
{
	static constexpr int msgid = 10;
	Action action;
	int32_t index;
	tll::scheme::ByteString<16> name;
	uint8_t up;
};

struct Route4
{
	static constexpr int msgid = 20;
	Action action;
	uint32_t table;
	RType type;
	tll::scheme::ByteString<16> oif;
	uint8_t dst_mask;
	uint32_t dst;
	uint8_t src_mask;
	uint32_t src;
};

struct Route6
{
	static constexpr int msgid = 30;
	Action action;
	uint32_t table;
	RType type;
	tll::scheme::ByteString<16> oif;
	uint8_t dst_mask;
	tll::scheme::Bytes<16> dst;
	uint8_t src_mask;
	tll::scheme::Bytes<16> src;
};

} // namespace netlink_scheme
#pragma pack(pop)
