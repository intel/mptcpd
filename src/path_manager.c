// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file src/path_manager.c
 *
 * @brief mptcpd path manager framework.
 *
 * Copyright (c) 2017-2019, Intel Corporation
 */

#include <stdlib.h>
#include <assert.h>

#include <netinet/in.h>
#include <linux/netlink.h>  // For NLA_* macros.
#include <linux/mptcp.h>

#include <ell/genl.h>
#include <ell/log.h>
#include <ell/util.h>

#include <mptcpd/path_manager_private.h>
#include <mptcpd/plugin.h>
#include <mptcpd/network_monitor.h>

#include "path_manager.h"
#include "configuration.h"


/**
 * @struct pm_mcast_group
 *
 * @brief Path mananger generic netlink multicast group information.
 */
struct pm_mcast_group
{
        /**
         * @brief @c mptcp genl family multicast event handler.
         *
         * Generic netlink multicast event handling function for a
         * @c mptcp family multicast group of the name included in
         * this structure.
         *
         * @see @c name
         */
        l_genl_msg_func_t const callback;

        /**
         * @brief Name of @c mptcp genl family multicast group event.
         *
         * The @c mptcp generic netlink family defines several multicast
         * groups, each corresponding to a specific MPTCP event (new
         * connection, etc).  This field contains the name of such a
         * multicast group.
         */
        char const *const name;
};

static void handle_mptcp_event(struct l_genl_msg *msg, void *user_data);

static struct pm_mcast_group const pm_mcast_group_map[] = {
        { .callback = handle_mptcp_event,
          .name     = MPTCP_GENL_EV_GRP_NAME }
};

/**
 * @brief Validate generic netlink attribute size.
 *
 * @param[in] actual   Actual   attribute size.
 * @param[in] expected Expected attribute size.
 *
 * @retval true  Attribute size is valid.
 * @retval false Attribute size is invalid.
 */
static bool validate_attr_len(size_t actual, size_t expected)
{
        bool const is_valid = (actual == expected);

        if (!is_valid)
                l_error("Attribute length (%zu) is "
                        "not the expected length (%zu)",
                        actual,
                        expected);

        return is_valid;
}

/**
 * @brief Retrieve generic netlink attribute.
 *
 * This macro is basically function with a built-in sanity
 * check that casts @c void* typed data to a variable of desired
 * type.
 *
 * @param[in]  data Pointer to source attribute data.
 * @param[in]  len  Length (size) of attribute data.
 * @param[out] attr Pointer to attribute data destination.
 */
#define MPTCP_GET_NL_ATTR(data, len, attr)                  \
        do {                                                \
                if (validate_attr_len(len, sizeof(*attr)))  \
                        attr = data;                        \
        } while(0)

#ifdef MPTCPD_ENABLE_PM_NAME
static char const *get_pm_name(void const *data, size_t len)
{
        char const *pm_name = NULL;

        if (data != NULL) {
                if (validate_attr_len(len, (size_t) MPTCP_PM_NAME_LEN))
                        pm_name = data;
                else
                        l_error("Path manager name length (%zu) "
                                "is not the expected length "
                                "(%d)",
                                len,
                                MPTCP_PM_NAME_LEN);
        }

        return pm_name;
}
#endif // MPTCPD_ENABLE_PM_NAME

static void get_mptcpd_addr(struct in_addr const *addr4,
                            struct in6_addr const *addr6,
                            in_port_t port,
                            struct mptcpd_addr *addr)
{
        assert(addr4 != NULL || addr6 != NULL);
        assert(addr != NULL);

        if (addr4 != NULL) {
                addr->address.family     = AF_INET;
                addr->address.addr.addr4 = *addr4;
        } else {
                addr->address.family     = AF_INET6;
                memcpy(addr->address.addr.addr6.s6_addr,
                       addr6->s6_addr,
                       sizeof(*addr6->s6_addr));
        }

        addr->port = port;
}

static void handle_connection_created(struct l_genl_msg *msg,
                                      void *user_data)
{
        struct l_genl_attr attr;
        if (!l_genl_attr_init(&attr, msg)) {
                l_error("Unable to initialize genl attribute");
                return;
        }

        /*
          Payload:
              Token
              Local address
              Local port
              Remote address
              Remote port
              Backup priority (optional)
              Path management strategy (optional)
        */

        mptcpd_token_t  const *token       = NULL;
        struct in_addr  const *laddr4      = NULL;
        struct in_addr  const *raddr4      = NULL;
        struct in6_addr const *laddr6      = NULL;
        struct in6_addr const *raddr6      = NULL;
        in_port_t       const *local_port  = NULL;
        in_port_t       const *remote_port = NULL;
        char            const *pm_name     = NULL;
        bool backup                        = false;

        uint16_t type;
        uint16_t len;
        void const *data = NULL;

        while (l_genl_attr_next(&attr, &type, &len, &data)) {
                switch (type) {
                case MPTCP_ATTR_TOKEN:
                        MPTCP_GET_NL_ATTR(data, len, token);
                        break;
                case MPTCP_ATTR_SADDR4:
                        MPTCP_GET_NL_ATTR(data, len, laddr4);
                        break;
                case MPTCP_ATTR_SADDR6:
                        MPTCP_GET_NL_ATTR(data, len, laddr6);
                        break;
                case MPTCP_ATTR_SPORT:
                        MPTCP_GET_NL_ATTR(data, len, local_port);
                        break;
                case MPTCP_ATTR_DADDR4:
                        MPTCP_GET_NL_ATTR(data, len, raddr4);
                        break;
                case MPTCP_ATTR_DADDR6:
                        MPTCP_GET_NL_ATTR(data, len, raddr6);
                        break;
                case MPTCP_ATTR_DPORT:
                        MPTCP_GET_NL_ATTR(data, len, remote_port);
                        break;
#ifdef MPTCPD_ENABLE_PM_NAME
                case MPTCP_ATTR_PATH_MANAGER:
                        pm_name = get_pm_name(data, len);
                        break;
#endif  // MPTCPD_ENABLE_PM_NAME
                case MPTCP_ATTR_BACKUP:
                        /*
                          The backup attribute is a NLA_FLAG,
                          meaning its existence *is* the flag.  No
                          payload data exists in such an attribute.
                         */
                        assert(validate_attr_len(len, 0));
                        assert(data == NULL);
                        backup = true;
                        break;
                default:
                        l_warn("Unknown MPTCP_EVENT_CREATED "
                               "attribute: %d",
                               type);
                        break;
                }
        }

        if (!token
            || !(laddr4 || laddr6)
            || !local_port
            || !(raddr4 || raddr6)
            || !remote_port) {
                l_error("Required MPTCP_EVENT_CREATED "
                        "message attributes are missing.");

                return;
        }

        l_debug("token: 0x%" MPTCPD_PRIxTOKEN, *token);
        l_debug("backup: %d", backup);

        struct mptcpd_pm *const pm = user_data;

        struct mptcpd_addr laddr, raddr;
        get_mptcpd_addr(laddr4, laddr6, *local_port, &laddr);
        get_mptcpd_addr(raddr4, raddr6, *remote_port, &raddr);

        mptcpd_plugin_new_connection(pm_name,
                                     *token,
                                     &laddr,
                                     &raddr,
                                     backup,
                                     pm);
}

static void handle_connection_established(struct l_genl_msg *msg,
                                          void *user_data)
{
        (void) msg;
        (void) user_data;

        l_error("%s is currently unimplemented", __func__);
}

static void handle_connection_closed(struct l_genl_msg *msg,
                                     void *user_data)
{
        struct l_genl_attr attr;
        if (!l_genl_attr_init(&attr, msg)) {
                l_error("Unable to initialize genl attribute");
                return;
        }

        /*
          Payload:
              Token
         */

        mptcpd_token_t const *token = NULL;

        uint16_t type;
        uint16_t len;
        void const *data = NULL;

        while (l_genl_attr_next(&attr, &type, &len, &data)) {
                switch (type) {
                case MPTCP_ATTR_TOKEN:
                        MPTCP_GET_NL_ATTR(data, len, token);
                        break;
                default:
                        l_warn("Unknown MPTCP_EVENT_CLOSED "
                               "attribute: %d",
                               type);
                        break;
                }
        }

        if (!token) {
                l_error("Required MPTCP_EVENT_CLOSED "
                        "message attributes are missing.");

                return;
        }

        l_debug("token: 0x%" MPTCPD_PRIxTOKEN, *token);

        struct mptcpd_pm *const pm = user_data;

        mptcpd_plugin_connection_closed(*token, pm);
}

static void handle_new_addr(struct l_genl_msg *msg, void *user_data)
{
        struct l_genl_attr attr;
        if (!l_genl_attr_init(&attr, msg)) {
                l_error("Unable to initialize genl attribute");
                return;
        }

        /*
          Payload:
              Token
              Remote address ID
              Remote address
              Remote port
        */

        mptcpd_token_t  const *token      = NULL;
        mptcpd_aid_t    const *address_id = NULL;
        struct in_addr  const *addr4      = NULL;
        struct in6_addr const *addr6      = NULL;
        in_port_t       const *port       = NULL;

        uint16_t type;
        uint16_t len;
        void const *data = NULL;

        while (l_genl_attr_next(&attr, &type, &len, &data)) {
                switch (type) {
                case MPTCP_ATTR_TOKEN:
                        MPTCP_GET_NL_ATTR(data, len, token);
                        break;
                case MPTCP_ATTR_REM_ID:
                        MPTCP_GET_NL_ATTR(data, len, address_id);
                        break;
                case MPTCP_ATTR_DADDR4:
                        MPTCP_GET_NL_ATTR(data, len, addr4);
                        break;
                case MPTCP_ATTR_DADDR6:
                        MPTCP_GET_NL_ATTR(data, len, addr6);
                        break;
                case MPTCP_ATTR_DPORT:
                        MPTCP_GET_NL_ATTR(data, len, port);
                        break;
                default:
                        l_warn("Unknown MPTCP_EVENT_ANNOUNCED "
                               "attribute: %d",
                               type);
                        break;
                }
        }

        if (!token
            || !address_id
            || !(addr4 || addr6)
            || !port) {
                l_error("Required MPTCP_EVENT_ANNOUNCED "
                        "message attributes are missing.");

                return;
        }

        l_debug("token: 0x%" MPTCPD_PRIxTOKEN, *token);

        struct mptcpd_addr addr;
        get_mptcpd_addr(addr4, addr6, *port, &addr);

        struct mptcpd_pm *const pm = user_data;

        mptcpd_plugin_new_address(*token, *address_id, &addr, pm);
}

static void handle_addr_removed(struct l_genl_msg *msg, void *user_data)
{
        (void) msg;
        (void) user_data;

        l_error("%s is currently unimplemented", __func__);
}

static void handle_new_subflow(struct l_genl_msg *msg, void *user_data)
{
        struct l_genl_attr attr;
        if (!l_genl_attr_init(&attr, msg)) {
                l_error("Unable to initialize genl attribute");
                return;
        }

        /*
          Payload:
              Token
              Local address ID
              Local address
              Local port
              Remote address ID
              Remote address
              Remote port
         */

        mptcpd_token_t  const *token       = NULL;
        mptcpd_aid_t    const *laddr_id    = NULL;
        mptcpd_aid_t    const *raddr_id    = NULL;
        struct in_addr  const *laddr4      = NULL;
        struct in_addr  const *raddr4      = NULL;
        struct in6_addr const *laddr6      = NULL;
        struct in6_addr const *raddr6      = NULL;
        in_port_t       const *local_port  = NULL;
        in_port_t       const *remote_port = NULL;

        uint16_t type;
        uint16_t len;
        void const *data = NULL;

        while (l_genl_attr_next(&attr, &type, &len, &data)) {
                switch (type) {
                case MPTCP_ATTR_TOKEN:
                        MPTCP_GET_NL_ATTR(data, len, token);
                        break;
                case MPTCP_ATTR_LOC_ID:
                        MPTCP_GET_NL_ATTR(data, len, laddr_id);
                        break;
                case MPTCP_ATTR_SADDR4:
                        MPTCP_GET_NL_ATTR(data, len, laddr4);
                        break;
                case MPTCP_ATTR_SADDR6:
                        MPTCP_GET_NL_ATTR(data, len, laddr6);
                        break;
                case MPTCP_ATTR_SPORT:
                        MPTCP_GET_NL_ATTR(data, len, local_port);
                        break;
                case MPTCP_ATTR_REM_ID:
                        MPTCP_GET_NL_ATTR(data, len, raddr_id);
                        break;
                case MPTCP_ATTR_DADDR4:
                        MPTCP_GET_NL_ATTR(data, len, raddr4);
                        break;
                case MPTCP_ATTR_DADDR6:
                        MPTCP_GET_NL_ATTR(data, len, raddr6);
                        break;
                case MPTCP_ATTR_DPORT:
                        MPTCP_GET_NL_ATTR(data, len, remote_port);
                        break;
                default:
                        l_warn("Unknown MPTCP_EVENT_SUB_ESTABLISHED "
                               "attribute: %d",
                               type);
                        break;
                }
        }

        if (!token
            || !laddr_id
            || !(laddr4 || laddr6)
            || !local_port
            || !raddr_id
            || !(raddr4 || raddr6)
            || !remote_port) {
                l_error("Required MPTCP_EVENT_SUB_ESTABLISHED "
                        "message attributes are missing.");

                return;
        }

        l_debug("token: 0x%" MPTCPD_PRIxTOKEN, *token);

        struct mptcpd_addr laddr, raddr;
        get_mptcpd_addr(laddr4, laddr6, *local_port,  &laddr);
        get_mptcpd_addr(raddr4, raddr6, *remote_port, &raddr);

        struct mptcpd_pm *const pm = user_data;

        mptcpd_plugin_new_subflow(*token,
                                  *laddr_id,
                                  &laddr,
                                  *raddr_id,
                                  &raddr,
                                  pm);
}

static void handle_subflow_closed(struct l_genl_msg *msg, void *user_data)
{
        struct l_genl_attr attr;
        if (!l_genl_attr_init(&attr, msg)) {
                l_error("Unable to initialize genl attribute");
                return;
        }

        /*
          Payload:
              Token
              Local address
              Local port
              Remote address
              Remote port
         */

        mptcpd_token_t  const *token       = NULL;
        struct in_addr  const *laddr4      = NULL;
        struct in_addr  const *raddr4      = NULL;
        struct in6_addr const *laddr6      = NULL;
        struct in6_addr const *raddr6      = NULL;
        in_port_t       const *local_port  = NULL;
        in_port_t       const *remote_port = NULL;

        uint16_t type;
        uint16_t len;
        void const *data = NULL;

        while (l_genl_attr_next(&attr, &type, &len, &data)) {
                switch (type) {
                case MPTCP_ATTR_TOKEN:
                        MPTCP_GET_NL_ATTR(data, len, token);
                        break;
                case MPTCP_ATTR_SADDR4:
                        MPTCP_GET_NL_ATTR(data, len, laddr4);
                        break;
                case MPTCP_ATTR_SADDR6:
                        MPTCP_GET_NL_ATTR(data, len, laddr6);
                        break;
                case MPTCP_ATTR_SPORT:
                        MPTCP_GET_NL_ATTR(data, len, local_port);
                        break;
                case MPTCP_ATTR_DADDR4:
                        MPTCP_GET_NL_ATTR(data, len, raddr4);
                        break;
                case MPTCP_ATTR_DADDR6:
                        MPTCP_GET_NL_ATTR(data, len, raddr6);
                        break;
                case MPTCP_ATTR_DPORT:
                        MPTCP_GET_NL_ATTR(data, len, remote_port);
                        break;
                default:
                        l_warn("Unknown MPTCP_EVENT_SUB_CLOSED "
                               "attribute: %d",
                               type);
                        break;
                }
        }

        if (!token
            || !(laddr4 || laddr6)
            || !local_port
            || !(raddr4 || raddr6)
            || !remote_port) {
                l_error("Required MPTCP_EVENT_SUB_CLOSED "
                        "message attributes are missing.");

                return;
        }

        l_debug("token: 0x%" MPTCPD_PRIxTOKEN, *token);

        struct mptcpd_addr laddr, raddr;
        get_mptcpd_addr(laddr4, laddr6, *local_port,  &laddr);
        get_mptcpd_addr(raddr4, raddr6, *remote_port, &raddr);

        struct mptcpd_pm *const pm = user_data;

        mptcpd_plugin_subflow_closed(*token, &laddr, &raddr, pm);
}

static void handle_priority_changed(struct l_genl_msg *msg,
                                    void *user_data)
{
        (void) msg;
        (void) user_data;

        l_error("%s is currently unimplemented", __func__);
}

static void handle_mptcp_event(struct l_genl_msg *msg, void *user_data)
{
        int const cmd = l_genl_msg_get_command(msg);

        assert(cmd != 0);

        switch(cmd) {
        case MPTCP_EVENT_CREATED:
                handle_connection_created(msg, user_data);
                break;

        case MPTCP_EVENT_ESTABLISHED:
                handle_connection_established(msg, user_data);
                break;

        case MPTCP_EVENT_CLOSED:
                handle_connection_closed(msg, user_data);
                break;

        case MPTCP_EVENT_ANNOUNCED:
                handle_new_addr(msg, user_data);
                break;

        case MPTCP_EVENT_REMOVED:
                handle_addr_removed(msg, user_data);
                break;

        case MPTCP_EVENT_SUB_ESTABLISHED:
                handle_new_subflow(msg, user_data);
                break;

        case MPTCP_EVENT_SUB_CLOSED:
                handle_subflow_closed(msg, user_data);
                break;

        case MPTCP_EVENT_SUB_PRIORITY:
                handle_priority_changed(msg, user_data);
                break;

        default:
                l_error("Unhandled MPTCP event: %d", cmd);
                break;
        };
}

/**
 * @brief Handle MPTCP generic netlink family appearing on us.
 *
 * This function performs operations that must occur after the MPTCP
 * generic netlink family has appeared since some data is only
 * available after that has happened.  Such data includes multicast
 * groups exposed by the generic netlink family, etc.
 *
 * @param[in,out] user_data Pointer @c mptcp_pm object to which the
 *                          @c l_genl_family watch belongs.
 */
static void family_appeared(void *user_data)
{
        struct mptcpd_pm *const pm = user_data;

        l_debug(MPTCP_GENL_NAME " generic netlink family appeared");

        pm->id = l_new(unsigned int, L_ARRAY_SIZE(pm_mcast_group_map));

        /*
          Register callbacks for MPTCP generic netlink multicast
          notifications.
        */
        for (size_t i = 0; i < L_ARRAY_SIZE(pm_mcast_group_map); ++i) {
                struct pm_mcast_group const *const mcg =
                        &pm_mcast_group_map[i];

                pm->id[i] = l_genl_family_register(pm->family,
                                                   mcg->name,
                                                   mcg->callback,
                                                   pm,
                                                   NULL /* destroy */);

                if (pm->id[i] == 0) {
                        /**
                         * @todo Should we exit with an error
                         *       instead?  If so, we need to make sure
                         *       the remaining array elements are set
                         *       to zero to prevent an uninitialized
                         *       value from being used at cleanup.
                         */
                        l_warn("Unable to register handler for %s "
                               "multicast messages",
                               mcg->name);
                }
        }
}

/**
 * @brief Handle MPTCP generic netlink family disappearing on us.
 *
 * @param[in,out] user_data Pointer @c mptcp_pm object to which the
 *                          @c l_genl_family watch belongs.
 */
static void family_vanished(void *user_data)
{
        struct mptcpd_pm *const pm = user_data;

        l_debug(MPTCP_GENL_NAME " generic netlink family vanished");

        if (pm->id == NULL)
                return;     // Nothing to do.

        /*
          Unregister callbacks for MPTCP generic netlink multicast
          notifications.
        */
        for (size_t i = 0; i < L_ARRAY_SIZE(pm_mcast_group_map); ++i) {
                if (pm->id[i] != 0
                    && !l_genl_family_unregister(pm->family, pm->id[i]))
                        l_warn("%s multicast handler deregistration "
                               "failed.",
                               pm_mcast_group_map[i].name);
        }

        l_free(pm->id);

        /*
          In case family_vanished() is called again without a prior
          call to family_appeared().
        */
        pm->id = NULL;
}

struct mptcpd_pm *mptcpd_pm_create(struct mptcpd_config const *config)
{
        assert(config != NULL);

        /**
         * @bug Mptcpd plugins should only be loaded once at process
         *      start.  The @c mptcpd_plugin_load() function only
         *      loads the functions once, and only reloads after
         *      @c mptcpd_plugin_unload() is called.
         */
        if (!mptcpd_plugin_load(config->plugin_dir,
                                config->default_plugin)) {
                l_error("Unable to load path manager plugins.");

                return NULL;
        }

        struct mptcpd_pm *const pm = l_new(struct mptcpd_pm, 1);

        // No need to check for NULL.  l_new() abort()s on failure.

        assert(pm->id == NULL);

        pm->genl = l_genl_new_default();
        if (pm->genl == NULL) {
                mptcpd_pm_destroy(pm);
                l_error("Unable to initialize Generic Netlink system.");
                return NULL;
        }

        pm->family = l_genl_family_new(pm->genl, MPTCP_GENL_NAME);
        if (pm->family == NULL) {
                mptcpd_pm_destroy(pm);
                l_error("Unable to initialize \"" MPTCP_GENL_NAME
                        "\" Generic Netlink family.");
                return NULL;
        }

        if (!l_genl_family_set_watches(pm->family,
                                       family_appeared,
                                       family_vanished,
                                       pm,
                                       NULL)) {
                mptcpd_pm_destroy(pm);
                l_error("Unable to set watches for \"" MPTCP_GENL_NAME
                        "\" Generic Netlink family.");
                return NULL;
        }

        // Listen for network device changes.
        pm->nm = mptcpd_nm_create();

        if (pm->nm == NULL) {
                mptcpd_pm_destroy(pm);
                l_error("Unable to create network monitor.");
                return NULL;
        }

        return pm;
}

void mptcpd_pm_destroy(struct mptcpd_pm *pm)
{
        if (pm == NULL)
                return;

        mptcpd_nm_destroy(pm->nm);

        l_genl_family_unref(pm->family);
        l_genl_unref(pm->genl);
        l_free(pm);

        /**
         * @bug Mptcpd plugins should only be unloaded once at process
         *      exit, or at least after the last @c mptcpd_pm object
         *      has been destroyed.
         */
        mptcpd_plugin_unload();
}


/*
  Local Variables:
  c-file-style: "linux"
  End:
*/
