// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file netlink_pm_mptcp_org.c
 *
 * @brief mptcpd generic netlink commands.
 *
 * Copyright (c) 2017-2021, Intel Corporation
 */

#ifdef HAVE_CONFIG_H
# include <mptcpd/private/config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include <ell/genl.h>
#include <ell/util.h>  // For L_STRINGIFY needed by l_error(), etc.
#include <ell/log.h>

#include "commands.h"

#include <mptcpd/private/mptcp_org.h>
#include <mptcpd/private/netlink_pm.h>
#include <mptcpd/private/path_manager.h>
#include <mptcpd/path_manager.h>


/// Directory containing MPTCP sysctl variable entries.
#define MPTCP_SYSCTL_BASE "/proc/sys/net/mptcp/"

/**
 * @brief Maximum path manager name length.
 *
 * @note @c MPTCP_PM_NAME_MAX is defined in the internal
 *       @c <net/mptcp.h> header in the multipath-tcp.org kernel.
 */
#ifndef MPTCP_PM_NAME_MAX
# define MPTCP_PM_NAME_MAX 16
#endif


/**
 * @brief Verify that the MPTCP "netlink" path manager is selected.
 *
 * Mptcpd requires MPTCP the "netlink" path manager to be selected at
 * run-time when using the multipath-tcp.org kernel.  Issue a warning
 * if it is not selected.
 */
static void check_kernel_mptcp_path_manager(void)
{
        static char const mptcp_path_manager[] =
                MPTCP_SYSCTL_BASE "mptcp_path_manager";

        FILE *const f = fopen(mptcp_path_manager, "r");

        if (f == NULL)
                return;  // Not using multipath-tcp.org kernel.

        char pm[MPTCP_PM_NAME_MAX] = { 0 };

        static char const MPTCP_PM_NAME_FMT[] =
                "%" L_STRINGIFY(MPTCP_PM_NAME_MAX) "s";

        int const n = fscanf(f, MPTCP_PM_NAME_FMT, pm);

        fclose(f);

        if (n == 1) {
                if (strcmp(pm, "netlink") != 0) {
                        /*
                          "netlink" could be set as the default.  It
                          may not appear as "netlink", which is why
                          "may" is used instead of "is" in the warning
                          diagnostic below
                        */
                        l_warn("MPTCP 'netlink' path manager may "
                               "not be selected in the kernel.");
                        l_warn("Try 'sysctl -w "
                               "net.mptcp.mptcp_path_manager=netlink'.");

                        /*
                          Mptcpd should not set this variable since it
                          would need to be run as root in order to
                          gain write access to files in
                          /proc/sys/net/mptcp/ owned by root.
                          Ideally, mptcpd should not be run as the
                          root user.
                        */
                }
        } else {
                l_warn("Unable to determine selected MPTCP "
                       "path manager.");
        }
}

static bool append_addr_attr(struct l_genl_msg *msg,
                             struct sockaddr const *addr,
                             bool local)
{
        assert(mptcpd_is_inet_family(addr));

        uint16_t type = 0;
        uint16_t len = 0;
        void const *data = NULL;

        if (addr->sa_family == AF_INET) {
                if (local)
                        type = MPTCP_ATTR_SADDR4;
                else
                        type = MPTCP_ATTR_DADDR4;

                struct sockaddr_in const *const addr4 =
                        (struct sockaddr_in *) addr;

                data = &addr4->sin_addr;
                len  = sizeof(addr4->sin_addr);
        } else {
                if (local)
                        type = MPTCP_ATTR_SADDR6;
                else
                        type = MPTCP_ATTR_DADDR6;

                struct sockaddr_in6 const *const addr6 =
                        (struct sockaddr_in6 *) addr;

                data = &addr6->sin6_addr;
                len  = sizeof(addr6->sin6_addr);
        }

        return l_genl_msg_append_attr(msg, type, len, data);
}

static bool append_local_addr_attr(struct l_genl_msg *msg,
                                   struct sockaddr const *addr)
{
        static bool const local = true;

        return append_addr_attr(msg, addr, local);
}

static bool append_remote_addr_attr(struct l_genl_msg *msg,
                                    struct sockaddr const *addr)
{
        static bool const local = false;

        return append_addr_attr(msg, addr, local);
}

// ---------------------------------------------------------------------

static int mptcp_org_add_addr(struct mptcpd_pm *pm,
                              struct sockaddr const *addr,
                              mptcpd_aid_t id,
                              uint32_t const flags,
                              int index,
                              mptcpd_token_t token)
{
        /*
          MPTCP flags are not needed by multipath-tcp.org kernel to
          add network address.
        */
        if (flags != 0)
                l_warn("add_addr: MPTCP flags are ignored.");

        /*
          Network interface index is not needed by multipath-tcp.org
          kernel to add network address.
        */
        if (index != 0)
                l_warn("add_addr: Network interface index is ignored.");

        /*
          Payload:
              Token
              Local address ID
              Local address family
              Local address
              Local port (optional)
         */

        // Types chosen to match MPTCP genl API.
        uint16_t const family = mptcpd_get_addr_family(addr);
        uint16_t const port   = mptcpd_get_port_number(addr);

        /**
         * @todo Verify that this payload size calculation is
         *       correct.  The alignment, in particular, doesn't look
         *       quite right.
         */
        size_t const payload_size =
                MPTCPD_NLA_ALIGN(token)
                + MPTCPD_NLA_ALIGN(id)
                + MPTCPD_NLA_ALIGN(family)
                + MPTCPD_NLA_ALIGN_ADDR(addr)
                + MPTCPD_NLA_ALIGN_OPT(port);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_CMD_ANNOUNCE, payload_size);

        bool const appended =
                l_genl_msg_append_attr(msg,
                                       MPTCP_ATTR_TOKEN,
                                       sizeof(token),
                                       &token)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_ATTR_LOC_ID,
                        sizeof(id),
                        &id)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_ATTR_FAMILY,
                        sizeof(family),  // sizeof(uint16_t)
                        &family)
                && append_local_addr_attr(msg, addr)
                && (port == 0 ||
                    l_genl_msg_append_attr(msg,
                                           MPTCP_ATTR_SPORT,
                                           sizeof(port),
                                           &port));

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "add_addr", /* user data */
                                  NULL  /* destroy */)
                == 0;
}

static int mptcp_org_remove_addr(struct mptcpd_pm *pm,
                                 mptcpd_aid_t address_id,
                                 mptcpd_token_t token)
{
        /*
          Payload:
              Token
              Local address ID
         */

        /**
         * @todo Verify that this payload size calculation is
         *       correct.  The alignment, in particular, doesn't look
         *       quite right.
         */
        size_t const payload_size =
                MPTCPD_NLA_ALIGN(token)
                + MPTCPD_NLA_ALIGN(address_id);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_CMD_REMOVE, payload_size);

        bool const appended =
                l_genl_msg_append_attr(msg,
                                       MPTCP_ATTR_TOKEN,
                                       sizeof(token),
                                       &token)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_ATTR_LOC_ID,
                        sizeof(address_id),
                        &address_id);

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "remove_addr", /* user data */
                                  NULL  /* destroy */)
                == 0;
}

static int mptcp_org_add_subflow(struct mptcpd_pm *pm,
                                 mptcpd_token_t token,
                                 mptcpd_aid_t local_address_id,
                                 mptcpd_aid_t remote_address_id,
                                 struct sockaddr const *local_addr,
                                 struct sockaddr const *remote_addr,
                                 bool backup)
{
        /*
          Payload:
              Token
              Address family
              Local address ID
              Remote address ID

              Optional attributes:
                  Local address
                  Local port
                  Remote address
                  Remote port    (required if remote address is specified)
                  Backup priority flag
                  Network interface index
         */

        /**
         * @bug The address family is required but we currently base
         *      it on the optional remote address.
         */
        uint16_t const family      = mptcpd_get_addr_family(remote_addr);
        uint16_t const local_port  = mptcpd_get_port_number(local_addr);
        uint16_t const remote_port = mptcpd_get_port_number(remote_addr);
        // uint16_t per MPTCP genl API.

        /**
         * @todo Verify that this payload size calculation is
         *       correct.  The alignment, in particular, doesn't look
         *       quite right.
         */
        size_t const payload_size =
                MPTCPD_NLA_ALIGN(token)
                + MPTCPD_NLA_ALIGN(family)
                + MPTCPD_NLA_ALIGN(local_address_id)
                + MPTCPD_NLA_ALIGN(remote_address_id)
                + (local_addr == NULL
                   ? 0
                   : (MPTCPD_NLA_ALIGN_ADDR(local_addr)
                      + (MPTCPD_NLA_ALIGN_OPT(local_port))))
                + (remote_addr == NULL
                   ? 0
                   : MPTCPD_NLA_ALIGN_ADDR(remote_addr)
                   + MPTCPD_NLA_ALIGN(remote_port))
                + MPTCPD_NLA_ALIGN(backup);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_CMD_SUB_CREATE, payload_size);

        bool const appended =
                l_genl_msg_append_attr(msg,
                                       MPTCP_ATTR_TOKEN,
                                       sizeof(token),
                                       &token)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_ATTR_LOC_ID,
                        sizeof(local_address_id),
                        &local_address_id)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_ATTR_REM_ID,
                        sizeof(remote_address_id),
                        &remote_address_id)
                && (local_addr == NULL
                    || (append_local_addr_attr(msg, local_addr)
                        && (local_port == 0
                            || l_genl_msg_append_attr(msg,
                                                      MPTCP_ATTR_SPORT,
                                                      sizeof(local_port),
                                                      &local_port))))
                && (remote_addr == NULL
                    || (l_genl_msg_append_attr(
                                msg,
                                MPTCP_ATTR_FAMILY,
                                sizeof(family),
                                &family)
                        && append_remote_addr_attr(msg, remote_addr)
                        && remote_port != 0
                        && l_genl_msg_append_attr(msg,
                                                  MPTCP_ATTR_DPORT,
                                                  sizeof(remote_port),
                                                  &remote_port)))
                && l_genl_msg_append_attr(msg,
                                          MPTCP_ATTR_BACKUP,
                                          sizeof(backup),
                                          &backup);

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "add_subflow", /* user data */
                                  NULL  /* destroy */)
                == 0;
}

static int mptcp_org_set_backup(struct mptcpd_pm *pm,
                                mptcpd_token_t token,
                                struct sockaddr const *local_addr,
                                struct sockaddr const *remote_addr,
                                bool backup)
{
        /*
          Payload:
              Token
              Address family
              Local address
              Local port
              Remote address
              Remote port
              Backup priority flag
         */

        uint16_t const family      = mptcpd_get_addr_family(local_addr);
        uint16_t const local_port  = mptcpd_get_port_number(local_addr);
        uint16_t const remote_port = mptcpd_get_port_number(remote_addr);
        // uint16_t per MPTCP genl API.

        /**
         * @todo Verify that this payload size calculation is
         *       correct.  The alignment, in particular, doesn't look
         *       quite right.
         */
        size_t const payload_size =
                MPTCPD_NLA_ALIGN(token)
                + MPTCPD_NLA_ALIGN(family)
                + MPTCPD_NLA_ALIGN_ADDR(local_addr)
                + MPTCPD_NLA_ALIGN(local_port)
                + MPTCPD_NLA_ALIGN_ADDR(remote_addr)
                + MPTCPD_NLA_ALIGN(remote_port)
                + MPTCPD_NLA_ALIGN(backup);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_CMD_SUB_PRIORITY,
                                     payload_size);

        /**
         * @todo Should we verify that the local and remote address
         *       families match?  The kernel already does that, but we
         *       currently don't propagate any kernel initiated errors
         *       to the caller.
         */
        bool const appended =
                l_genl_msg_append_attr(msg,
                                       MPTCP_ATTR_TOKEN,
                                       sizeof(token),
                                       &token)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_ATTR_FAMILY,
                        sizeof(family),
                        &family)
                && append_local_addr_attr(msg, local_addr)
                && l_genl_msg_append_attr(msg,
                                          MPTCP_ATTR_SPORT,
                                          sizeof(local_port),
                                          &local_port)
                && append_remote_addr_attr(msg, remote_addr)
                && l_genl_msg_append_attr(msg,
                                          MPTCP_ATTR_DPORT,
                                          sizeof(remote_port),
                                          &remote_port)
                && l_genl_msg_append_attr(msg,
                                          MPTCP_ATTR_BACKUP,
                                          sizeof(backup),
                                          &backup);

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "set_backup", /* user data */
                                  NULL  /* destroy */)
                == 0;
}

static int mptcp_org_remove_subflow(struct mptcpd_pm *pm,
                                    mptcpd_token_t token,
                                    struct sockaddr const *local_addr,
                                    struct sockaddr const *remote_addr)
{
        /*
          Payload:
              Token
              Address family
              Local address
              Local port
              Remote address
              Remote port
         */

        uint16_t const family      = mptcpd_get_addr_family(local_addr);
        uint16_t const local_port  = mptcpd_get_port_number(local_addr);
        uint16_t const remote_port = mptcpd_get_port_number(remote_addr);
        // uint16_t per MPTCP genl API.

        /**
         * @todo Verify that this payload size calculation is
         *       correct.  The alignment, in particular, doesn't look
         *       quite right.
         */
        size_t const payload_size =
                MPTCPD_NLA_ALIGN(token)
                + MPTCPD_NLA_ALIGN(family)
                + MPTCPD_NLA_ALIGN_ADDR(local_addr)
                + MPTCPD_NLA_ALIGN(local_port)
                + MPTCPD_NLA_ALIGN_ADDR(remote_addr)
                + MPTCPD_NLA_ALIGN(remote_port);

        struct l_genl_msg *const msg =
                l_genl_msg_new_sized(MPTCP_CMD_SUB_DESTROY, payload_size);

        /**
         * @todo Should we verify that the local and remote address
         *       families match?  The kernel already does that, but we
         *       currently don't propagate any kernel initiated errors
         *       to the caller.
         */
        bool const appended =
                l_genl_msg_append_attr(msg,
                                       MPTCP_ATTR_TOKEN,
                                       sizeof(token),
                                       &token)
                && l_genl_msg_append_attr(
                        msg,
                        MPTCP_ATTR_FAMILY,
                        sizeof(family),
                        &family)
                && append_local_addr_attr(msg, local_addr)
                && l_genl_msg_append_attr(msg,
                                          MPTCP_ATTR_SPORT,
                                          sizeof(local_port),
                                          &local_port)
                && append_remote_addr_attr(msg, remote_addr)
                && l_genl_msg_append_attr(msg,
                                          MPTCP_ATTR_DPORT,
                                          sizeof(remote_port),
                                          &remote_port);

        if (!appended) {
                l_genl_msg_unref(msg);

                return ENOMEM;
        }

        return l_genl_family_send(pm->family,
                                  msg,
                                  mptcpd_family_send_callback,
                                  "remove_subflow", /* user data */
                                  NULL  /* destroy */)
                == 0;
}

static struct mptcpd_pm_cmd_ops const cmd_ops =
{
        .add_addr       = mptcp_org_add_addr,
        .remove_addr    = mptcp_org_remove_addr,
        .add_subflow    = mptcp_org_add_subflow,
        .remove_subflow = mptcp_org_remove_subflow,
        .set_backup     = mptcp_org_set_backup,
};

static struct mptcpd_netlink_pm const npm = {
        .name    = MPTCP_GENL_NAME,
        .group   = MPTCP_GENL_EV_GRP_NAME,
        .cmd_ops = &cmd_ops
};

struct mptcpd_netlink_pm const *mptcpd_get_netlink_pm_mptcp_org(void)
{
        check_kernel_mptcp_path_manager();

        return &npm;
}


/*
  Local Variables:
  c-file-style: "linux"
  End:
*/
