// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file netlink_pm_upstream.c
 *
 * @brief Upstream kernel generic netlink path manager details.
 *
 * Copyright (c) 2020-2021, Intel Corporation
 */

#ifdef HAVE_CONFIG_H
# include <mptcpd/private/config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <sys/socket.h>

#include <ell/genl.h>
#include <ell/util.h>  // For L_STRINGIFY needed by l_error(), etc.
#include <ell/log.h>

#include <mptcpd/private/mptcp_upstream.h>
#include <mptcpd/private/netlink_pm.h>
#include <mptcpd/private/path_manager.h>
#include <mptcpd/path_manager.h>
#include <mptcpd/types.h>
#include <mptcpd/addr_info.h>
#include <mptcpd/private/sockaddr.h>

#include "commands.h"
#include "path_manager.h"

// Sanity check
#if MPTCPD_ADDR_FLAG_SIGNAL != MPTCP_PM_ADDR_FLAG_SIGNAL                \
        || MPTCPD_ADDR_FLAG_SUBFLOW != MPTCP_PM_ADDR_FLAG_SUBFLOW       \
        || MPTCPD_ADDR_FLAG_BACKUP != MPTCP_PM_ADDR_FLAG_BACKUP
# error Mismatch between mptcpd and upstream kernel addr flags.
#endif

/**
 * @struct get_addr_user_callback
 *
 * @brief Convenience struct for passing addr to user callback.
 */
struct get_addr_user_callback
{
        /// User supplied get_addr/dump_addrs callback.
        mptcpd_pm_get_addr_cb get_addr;

        /// User data to be passed to one of the above callback.
        void *data;

        /// Callback is for a dump_addrs call.
        bool dump;
};

/**
 * @struct get_limits_user_callback
 *
 * @brief Convenience struct for passing limits to user callback.
 */
struct get_limits_user_callback
{
        /// User supplied callback.
        mptcpd_pm_get_limits_cb get_limits;

        /// User data to be passed to the above callback.
        void *data;
};

// -----------------------------------------------------------------------

/**
 * @brief Initialize a @c struct @c mptcpd_addr_info instance.
 *
 * Initialize a @c addr_info instance with the provided IPv4 or
 * IPv6 address.  Only one is required and used.  The @a port, @a id,
 * @a flags, and @a index are optional and may be set to @c NULL if
 * not used.
 *
 * @param[in]     addr4 IPv4 internet address.
 * @param[in]     addr6 IPv6 internet address.
 * @param[in]     port  IP port.
 * @param[in]     id    Address ID.
 * @param[in]     flags MPTCP flags.
 * @param[in]     index Network interface index.
 * @param[in,out] addr  mptcpd network address information.
 *
 * @note This function is mostly meant for internal use.
 *
 * @return @c true on success.  @c false otherwise.
 */
static bool mptcpd_addr_info_init(struct in_addr  const *addr4,
                                  struct in6_addr const *addr6,
                                  in_port_t       const *port,
                                  uint8_t         const *id,
                                  uint32_t        const *flags,
                                  int32_t         const *index,
                                  struct mptcpd_addr_info *info)
{
        if (info == NULL
            || !mptcpd_sockaddr_storage_init(addr4,
                                             addr6,
                                             port ? *port : 0,
                                             &info->addr))
                return false;

        info->id    = (id    ? *id    : 0);
        info->flags = (flags ? *flags : 0);
        info->index = (index ? *index : 0);

        return true;
}

static bool get_addr_callback_recurse(struct l_genl_attr *attr,
                                      struct mptcpd_addr_info *info)
{
        struct l_genl_attr nested;
        if (!l_genl_attr_recurse(attr, &nested)) {
                l_error("get_addr: unable to obtain nested data");
                return false;
        }

        uint16_t type;
        uint16_t len;
        void const *data = NULL;

        struct in_addr  const *addr4 = NULL;
        struct in6_addr const *addr6 = NULL;
        in_port_t       const *port  = NULL;
        uint8_t         const *id    = NULL;
        uint32_t        const *flags = NULL;
        int32_t         const *index = NULL;

        while (l_genl_attr_next(&nested, &type, &len, &data)) {
                switch (type) {
                case MPTCP_PM_ADDR_ATTR_FAMILY:
                        /*
                          Ignore.  Deduced from addr attributes
                          below.
                        */
                        break;
                case MPTCP_PM_ADDR_ATTR_ID:
                        id = data;
                        break;
                case MPTCP_PM_ADDR_ATTR_ADDR4:
                        addr4 = data;
                        break;
                case MPTCP_PM_ADDR_ATTR_ADDR6:
                        addr6 = data;
                        break;
                case MPTCP_PM_ADDR_ATTR_PORT:
                        port = data;
                        break;
                case MPTCP_PM_ADDR_ATTR_FLAGS:
                        flags = data;
                        break;
                case MPTCP_PM_ADDR_ATTR_IF_IDX:
                        index = data;
                        break;
                default:
                        l_warn("Unknown MPTCP_PM_ATTR_ADDR attribute: %d",
                               type);
                        break;
                }
        }

        mptcpd_addr_info_init(addr4, addr6, port, id, flags, index, info);

        return true;
}

static void get_addr_callback(struct l_genl_msg *msg, void *user_data)
{
        struct get_addr_user_callback const *const cb = user_data;

        if (!mptcpd_check_genl_error(msg,
                                     cb->dump
                                     ? "dump_addrs"
                                     : "get_addr"))
                return;

        struct l_genl_attr attr;
        if (!l_genl_attr_init(&attr, msg)) {
                l_error("get_addr: "
                        "Unable to initialize genl attribute");

                return;
        }

        /*
          Payload (nested):
              Network address
              Address ID
              Flags
              Network
        */

        uint16_t type;
        uint16_t len;
        void const *data = NULL;

        struct mptcpd_addr_info addr = { .id = 0 };

        while (l_genl_attr_next(&attr, &type, &len, &data)) {
                /*
                  Sanity check.  The attribute sent by the kernel
                  should always be of type MPTCP_PM_ATTR_ADDR.
                */
                if (type == MPTCP_PM_ATTR_ADDR) {
                        if (!get_addr_callback_recurse(&attr, &addr))
                                return;

                        // Only one addr is sent per get/dump.
                        break;
                } else {
                        /*
                          This should only occur if the kernel
                          get_addr/dump_addrs API changed.
                        */
                        l_error("%s: unexpected attribute of type %u",
                                cb->dump
                                ? "dump_addrs"
                                : "get_addr",
                                type);
                }
        }

        // Pass the results to the user.
        cb->get_addr(&addr, cb->data);
}

static bool append_addr_attr(struct l_genl_msg *msg,
                             struct sockaddr const *addr)
{
        assert(mptcpd_is_inet_family(addr));

        uint16_t type = 0;
        uint16_t len = 0;
        void const *data = NULL;

        if (addr->sa_family == AF_INET) {
                type = MPTCP_PM_ADDR_ATTR_ADDR4;

                struct sockaddr_in const *const addr4 =
                        (struct sockaddr_in *) addr;

                data = &addr4->sin_addr;
                len  = sizeof(addr4->sin_addr);
        } else {
                type = MPTCP_PM_ADDR_ATTR_ADDR6;

                struct sockaddr_in6 const *const addr6 =
                        (struct sockaddr_in6 *) addr;

                data = &addr6->sin6_addr;
                len  = sizeof(addr6->sin6_addr);
        }

        return l_genl_msg_append_attr(msg, type, len, data);
}

// --------------------------------------------------------------

static uint16_t kernel_to_mptcpd_limit(uint16_t type)
{
        // Translate from kernel to mptcpd MPTCP limit.
        switch(type) {
        case MPTCP_PM_ATTR_RCV_ADD_ADDRS:
                return MPTCPD_LIMIT_RCV_ADD_ADDRS;
        case MPTCP_PM_ATTR_SUBFLOWS:
                return MPTCPD_LIMIT_SUBFLOWS;
        default:
                // Kernel sent an unknown MPTCP limit.
                l_warn("Unrecognized MPTCP resource "
                       "limit type: %u.", type);

                break;
        }

        return type;
}

static uint16_t mptcpd_to_kernel_limit(uint16_t type)
{
        switch(type) {
        case MPTCPD_LIMIT_RCV_ADD_ADDRS:
                return MPTCP_PM_ATTR_RCV_ADD_ADDRS;
        case MPTCPD_LIMIT_SUBFLOWS:
                return MPTCP_PM_ATTR_SUBFLOWS;
        default:
                l_warn("Unrecognized MPTCP resource "
                       "limit type: %u.", type);

                break;
        }

        return type;
}

static void get_limits_callback(struct l_genl_msg *msg, void *user_data)
{
        struct get_limits_user_callback const *const cb = user_data;
        struct mptcpd_limit *limits = NULL;
        size_t limits_len = 0;

        if (!mptcpd_check_genl_error(msg, "get_limits"))
                goto get_limits_out;

        struct l_genl_attr attr;
        if (!l_genl_attr_init(&attr, msg)) {
                l_error("get_limits: "
                        "Unable to initialize genl attribute");

                goto get_limits_out;
        }

        /*
          Payload (nested):
              Network address
              Address ID
              Flags
              Network
        */

        uint16_t type;
        uint16_t len;
        void const *data = NULL;

        while (l_genl_attr_next(&attr, &type, &len, &data)) {
                size_t const offset = limits_len++;

                limits = l_realloc(limits,
                                   sizeof(*limits) * limits_len);

                struct mptcpd_limit *const l = limits + offset;

                l->type  = kernel_to_mptcpd_limit(type);
                l->limit = *(uint32_t const *) data;
        }

get_limits_out:

        // Pass the results to the user.
        cb->get_limits(limits, limits_len, cb->data);

        l_free(limits);
}

// --------------------------------------------------------------

static int upstream_add_addr(struct mptcpd_pm *pm,
                             struct sockaddr const *addr,
                             mptcpd_aid_t address_id,
                             uint32_t flags,
                             int index,
                             mptcpd_token_t token)
{
        /*
          MPTCP connection token is not currently needed by upstream
          kernel to add network address.
        */
        if (token != 0)
                l_warn("add_addr: MPTCP connection token is ignored.");

        /*
          Payload (nested):
              Local address family
              Local address
              Local port (optional)
              Local address ID (optional)
              Flags (optional)
              Network inteface index (optional)
         */

        // Types chosen to match MPTCP genl API.
        uint16_t const family = mptcpd_get_addr_family(addr);
        uint16_t const port   = mptcpd_get_port_number(addr);

        /*
          The MPTCP_PM_ADDR_FLAG_SIGNAL flag is required when a port
          is specified.  Make sure it is set.
        */
        if (port != 0)
                flags |= MPTCP_PM_ADDR_FLAG_SIGNAL;

        size_t const payload_size =
                MPTCPD_NLA_ALIGN(family)
                + MPTCPD_NLA_ALIGN_ADDR(addr)
                + MPTCPD_NLA_ALIGN_OPT(port)
                + MPTCPD_NLA_ALIGN_OPT(address_id)
                + MPTCPD_NLA_ALIGN_OPT(flags)
                + MPTCPD_NLA_ALIGN_OPT(index);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_PM_CMD_ADD_ADDR, payload_size);

        bool const appended =
                l_genl_msg_enter_nested(msg,
                                        NLA_F_NESTED | MPTCP_PM_ATTR_ADDR)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_PM_ADDR_ATTR_FAMILY,
                        sizeof(family),  // sizeof(uint16_t)
                        &family)
                && append_addr_attr(msg, addr)
                && (port == 0 ||
                    l_genl_msg_append_attr(msg,
                                           MPTCP_PM_ADDR_ATTR_PORT,
                                           sizeof(port),  // sizeof(uint16_t)
                                           &port))
                && (address_id == 0
                    || l_genl_msg_append_attr(
                            msg,
                            MPTCP_PM_ADDR_ATTR_ID,
                            sizeof(address_id),  // sizeof(uint8_t)
                            &address_id))
                && (flags == 0
                    || l_genl_msg_append_attr(
                            msg,
                            MPTCP_PM_ADDR_ATTR_FLAGS,
                            sizeof(flags),  // sizeof(uint32_t)
                            &flags))
                && (index == 0
                    || l_genl_msg_append_attr(
                            msg,
                            MPTCP_PM_ADDR_ATTR_IF_IDX,
                            sizeof(index),   // sizeof(int32_t)
                            &index))
                && l_genl_msg_leave_nested(msg);

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "add_addr", /* user data */
                                  NULL  /* destroy */) == 0;
}

static int upstream_remove_addr(struct mptcpd_pm *pm,
                                mptcpd_aid_t address_id,
                                mptcpd_token_t token)
{
        /*
          MPTCP connection token is not currently needed by upstream
          kernel to remove network address.
        */
        if (token != 0)
                l_warn("remove_addr: MPTCP connection token "
                       "is ignored.");

        /*
          Payload (nested):
                  Local address ID
         */

        size_t const payload_size = MPTCPD_NLA_ALIGN(address_id);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_PM_CMD_DEL_ADDR, payload_size);

        bool const appended =
                l_genl_msg_enter_nested(msg,
                                        NLA_F_NESTED | MPTCP_PM_ATTR_ADDR)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_PM_ADDR_ATTR_ID,
                        sizeof(address_id),
                        &address_id)
                && l_genl_msg_leave_nested(msg);

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "remove_addr", /* user data */
                                  NULL  /* destroy */) == 0;
}

static int upstream_get_addr(struct mptcpd_pm *pm,
                             mptcpd_aid_t address_id,
                             mptcpd_pm_get_addr_cb callback,
                             void *data)
{
        /*
          Payload (nested):
              Local address ID
         */

        size_t const payload_size = MPTCPD_NLA_ALIGN(address_id);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_PM_CMD_GET_ADDR,
                                     payload_size);

        bool const appended =
                l_genl_msg_enter_nested(msg,
                                        NLA_F_NESTED | MPTCP_PM_ATTR_ADDR)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_PM_ADDR_ATTR_ID,
                        sizeof(address_id),
                        &address_id)
                && l_genl_msg_leave_nested(msg);

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        struct get_addr_user_callback *const cb =
                l_new(struct get_addr_user_callback, 1);

        cb->get_addr = callback;
        cb->data     = data;
        cb->dump     = false;

        return l_genl_family_send(pm->family,
                                  msg,
                                  get_addr_callback,
                                  cb,     /* user data */
                                  l_free  /* destroy */) == 0;
}

static int upstream_dump_addrs(struct mptcpd_pm *pm,
                               mptcpd_pm_get_addr_cb callback,
                               void *data)
{
        /*
          Payload:
              NONE
         */

        struct l_genl_msg *const msg =
                l_genl_msg_new(MPTCP_PM_CMD_GET_ADDR);

        struct get_addr_user_callback *const cb =
                l_new(struct get_addr_user_callback, 1);

        cb->get_addr = callback;
        cb->data     = data;
        cb->dump     = true;

        return l_genl_family_dump(pm->family,
                                  msg,
                                  get_addr_callback,
                                  cb,     /* user data */
                                  l_free  /* destroy */) == 0;
}

static int upstream_flush_addrs(struct mptcpd_pm *pm)
{
        /*
          Payload:
              NONE
         */

        struct l_genl_msg *const msg =
                l_genl_msg_new(MPTCP_PM_CMD_FLUSH_ADDRS);

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "flush_addrs", /* user data */
                                  NULL  /* destroy */) == 0;
}

static int upstream_set_limits(struct mptcpd_pm *pm,
                               struct mptcpd_limit const *limits,
                               size_t len)
{
        if (limits == NULL || len == 0)
                return EINVAL;  // Nothing to set.

        /*
          Payload:
              Maximum number of advertised addresses to receive/accept
              from peer (optional)
              Maximum number of subflows to create (optional)
         */

        size_t const payload_size = len * MPTCPD_NLA_ALIGN(limits->limit);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_PM_CMD_SET_LIMITS,
                                     payload_size);

        for (struct mptcpd_limit const *l = limits;
             l != limits + len;
             ++l) {
                uint16_t const type = mptcpd_to_kernel_limit(l->type);

                if (!l_genl_msg_append_attr(msg,
                                            type,
                                            sizeof(l->limit),
                                            &l->limit)) {
                        l_genl_msg_unref(msg);

                        return ENOMEM;
                }
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "set_limits", /* user data */
                                  NULL  /* destroy */) == 0;
}

static int upstream_get_limits(struct mptcpd_pm *pm,
                               mptcpd_pm_get_limits_cb callback,
                               void *data)
{
        /*
          Payload:
              NONE
         */

        struct l_genl_msg *const msg =
                l_genl_msg_new(MPTCP_PM_CMD_GET_LIMITS);

        struct get_limits_user_callback *const cb =
                l_new(struct get_limits_user_callback, 1);

        cb->get_limits = callback;
        cb->data       = data;

        return l_genl_family_send(pm->family,
                                  msg,
                                  get_limits_callback,
                                  cb,     /* user data */
                                  l_free  /* destroy */) == 0;
}

static int upstream_set_flags(struct mptcpd_pm *pm,
                              struct sockaddr const *addr,
                              mptcpd_flags_t flags)
{
        /*
          Payload (nested):
              Local address family
              Local address
              Flags
         */

        // Types chosen to match MPTCP genl API.
        uint16_t const family = mptcpd_get_addr_family(addr);

        size_t const payload_size =
                MPTCPD_NLA_ALIGN(family)
                + MPTCPD_NLA_ALIGN_ADDR(addr)
                + MPTCPD_NLA_ALIGN(flags);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_PM_CMD_SET_FLAGS,
                                     payload_size);

        bool const appended =
                l_genl_msg_enter_nested(msg,
                                        NLA_F_NESTED | MPTCP_PM_ATTR_ADDR)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_PM_ADDR_ATTR_FAMILY,
                        sizeof(family),  // sizeof(uint16_t)
                        &family)
                && append_addr_attr(msg, addr)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_PM_ADDR_ATTR_FLAGS,
                        sizeof(flags),  // sizeof(uint32_t)
                        &flags)
                && l_genl_msg_leave_nested(msg);

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "set_flags", /* user data */
                                  NULL  /* destroy */) == 0;
}

static struct mptcpd_pm_cmd_ops const cmd_ops =
{
        .add_addr    = upstream_add_addr,
        .remove_addr = upstream_remove_addr,
        .get_addr    = upstream_get_addr,
        .dump_addrs  = upstream_dump_addrs,
        .flush_addrs = upstream_flush_addrs,
        .set_limits  = upstream_set_limits,
        .get_limits  = upstream_get_limits,
        .set_flags   = upstream_set_flags,
};

static struct mptcpd_netlink_pm const npm = {
        .name    = MPTCP_PM_NAME,
        .group   = MPTCP_PM_EV_GRP_NAME,
        .cmd_ops = &cmd_ops
};

struct mptcpd_netlink_pm const *mptcpd_get_netlink_pm_upstream(void)
{
        return &npm;
}

/*
  Local Variables:
  c-file-style: "linux"
  End:
*/
