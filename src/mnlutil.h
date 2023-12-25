#ifndef _MNLUTIL_H
#define _MNLUTIL_H

#include <libmnl/libmnl.h>

#include <memory>

#undef mnl_attr_for_each
#define mnl_attr_for_each(attr, nlh, offset) \
	for ((attr) = (struct nlattr *) mnl_nlmsg_get_payload_offset((nlh), (offset)); \
	     mnl_attr_ok((attr), (char *)mnl_nlmsg_get_payload_tail(nlh) - (char *)(attr)); \
	     (attr) = mnl_attr_next(attr))

#undef mnl_attr_for_each_nested
#define mnl_attr_for_each_nested(attr, nest) \
	for ((attr) = (struct nlattr *) mnl_attr_get_payload(nest); \
	     mnl_attr_ok((attr), (char *)mnl_attr_get_payload(nest) + mnl_attr_get_payload_len(nest) - (char *)(attr)); \
	     (attr) = mnl_attr_next(attr))

// clang-format off
struct mnl_socket_delete { void operator ()(struct mnl_socket *ptr) const { mnl_socket_close(ptr); } };
// clang-format on

using mnl_ptr_t = std::unique_ptr<struct mnl_socket, mnl_socket_delete>;

#endif//_MNLUTIL_H
