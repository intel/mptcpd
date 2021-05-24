// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file commands.h
 *
 * @brief mptcpd generic netlink command utilities.
 *
 * Copyright (c) 2017-2021, Intel Corporation
 */

#ifndef MPTCPD_COMMANDS_H
#define MPTCPD_COMMANDS_H

#ifdef HAVE_CONFIG_H
# include <mptcpd/private/config.h>
#endif

#include <stdbool.h>
#include <stddef.h>   // For NULL.
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>  // For NLA_* macros.

/**
 * @brief Return netlink aligned size of a variable or type.
 *
 * @param[in] v Variable or type to be aligned.
 */
#define MPTCPD_NLA_ALIGN(v) (NLA_HDRLEN + NLA_ALIGN(sizeof(v)))

/**
 * @brief Return netlink aligned size of an optional variable.
 *
 * @param[in] v Variable to be aligned.
 *
 * @return The netlink aligned size of the variable @a v or @c 0 if
 *         @a v is zero or implicitly convertible to zero (e.g.
 *         @c NULL).
 */
#define MPTCPD_NLA_ALIGN_OPT(v) ((v) == 0 ? 0 : (MPTCPD_NLA_ALIGN(v)))

/**
 * @brief Return netlink aligned size of an IP address.
 *
 * @param[in] v Pointer to @c struct @c sockaddr containing an IP address
 *              (i.e., @c struct @c in_addr or @c struct @c in6_addr )
 *              to be aligned.
 *
 * @return The netlink aligned size of the IP address contained in the
 *          @c sockaddr pointed to by @a v.
 */
#define MPTCPD_NLA_ALIGN_ADDR(v) \
        (NLA_HDRLEN + NLA_ALIGN(mptcpd_get_addr_size(v)))


#ifdef __cplusplus
extern "C" {
#endif

struct l_genl_msg;

/**
 * @brief Check for internet address family.
 *
 * @param[in] addr Network address information.
 *
 * @return @c true if the @a addr is an internet address, and @c false
 *         otherwise.
 */
inline bool mptcpd_is_inet_family(struct sockaddr const *addr)
{
        return addr->sa_family == AF_INET || addr->sa_family == AF_INET6;
}

/**
 * @brief Get the underlying internet address size.
 *
 * @param[in] addr Network address information.
 *
 * @return Size of the underlying internet address (e.g., @c struct
 *         @c in_addr6).
 */
inline size_t mptcpd_get_addr_size(struct sockaddr const *addr)
{
        assert(mptcpd_is_inet_family(addr));

        return addr->sa_family == AF_INET
                ? sizeof(struct in_addr)
                : sizeof(struct in6_addr);
}

/**
 * @brief Get network address family.
 *
 * @param[in] addr Network address information.
 *
 * Get network address family suitably typed for use in MPTCP generic
 * netlink API calls, or zero if no address was provided.
 *
 * @return Network address family, or zero if no address family was
 *         provided.
 */
inline uint16_t mptcpd_get_addr_family(struct sockaddr const *addr)
{
        sa_family_t const family = (addr == NULL ? 0 : addr->sa_family);

        return family;
}

/**
 * @brief Get IP port number.
 *
 * @param[in] addr Network address information.
 *
 * Get IP port suitably typed for use in MPTCP generic netlink API
 * calls, or zero if no address was provided.
 *
 * @return IP port number, or zero if no IP address was provided.
 */
uint16_t mptcpd_get_port_number(struct sockaddr const *addr);

/**
 * @brief Get upstream kernel MPTCP generic netlink command
 *        operations.
 */
struct mptcpd_pm_cmd_ops const *mptcpd_get_upstream_cmd_ops(void);

/**
 * @brief Get multipath-tcp.org kernel MPTCP generic netlink command
 *        operations.
 */
struct mptcpd_pm_cmd_ops const *mptcpd_get_mptcp_org_cmd_ops(void);

/**
 * @brief Check for genl operation failure.
 *
 * Check for generic netlink operation failure, and log associated
 * error message.
 *
 * @param[in] msg   Generic netlink message information.
 * @param[in] fname Name function from which the error check was
 *                  initiated.
 *
 * @return @c true if no error was found, and @c false otherwise.
 */
bool mptcpd_check_genl_error(struct l_genl_msg *msg, char const *fname);

/**
 * @brief Generic error reporting callback.
 *
 * @param[in] msg       Generic netlink message information.
 * @param[in] user_data Function name.
 */
void mptcpd_family_send_callback(struct l_genl_msg *msg, void *user_data);

#ifdef __cplusplus
}
#endif


#endif /* MPTCPD_COMMANDS_H */


/*
  Local Variables:
  c-file-style: "linux"
  End:
*/
