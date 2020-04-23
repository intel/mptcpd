// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file mptcpd/path_manager.h
 *
 * @brief mptcpd generic netlink commands.
 *
 * Copyright (c) 2017-2020, Intel Corporation
 */

#ifndef MPTCPD_LIB_PATH_MANAGER_H
#define MPTCPD_LIB_PATH_MANAGER_H

#include <mptcpd/export.h>
#include <mptcpd/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sockaddr;
struct mptcpd_pm;

/**
 * @brief Is mptcpd path manager ready for use?
 *
 * The mptcpd path manager is ready for use when the @c "mptcp"
 * generic netlink family is available in the Linux kernel.  No
 * path management related interaction with the kernel can occur until
 * that family appears.
 *
 * @param[in] pm Mptcpd path manager.
 *
 * @return @c true if the mptcpd path manager is ready for use, and @c
 *         false otherwise.
 */
MPTCPD_API bool mptcpd_pm_ready(struct mptcpd_pm const *pm);

/**
 * @brief Send @c MPTCP_CMD_ANNOUNCE genl command to kernel.
 *
 * @param[in] pm         The mptcpd path manager object.
 * @param[in] token      MPTCP connection token.
 * @param[in] address_id MPTCP local address ID.
 * @param[in] addr       MPTCP local IP address and port to be
 *                       advertised through the MPTCP protocol
 *                       @c ADD_ADDR option.  The port is optional,
 *                       and is ignored if it is zero.
 *
 * @return @c true if operation was successful. @c false otherwise.
 */
MPTCPD_API bool mptcpd_pm_send_addr(struct mptcpd_pm *pm,
                                    mptcpd_token_t token,
                                    mptcpd_aid_t address_id,
                                    struct sockaddr const *addr);

/**
 * @brief Send @c MPTCP_CMD_REMOVE genl command to kernel.
 *
 * @param[in] pm         The mptcpd path manager object.
 * @param[in] token      MPTCP connection token.
 * @param[in] address_id MPTCP local address ID to be sent in the
 *                       MPTCP protocol @c REMOVE_ADDR option
 *                       corresponding to the local address that will
 *                       no longer be available.
 *
 * @return @c true if operation was successful. @c false otherwise.
 */
MPTCPD_API bool mptcpd_pm_remove_addr(struct mptcpd_pm *pm,
                                      mptcpd_token_t token,
                                      mptcpd_aid_t address_id);

/**
 * @brief Send @c MPTCP_GENL_CMD_ADD_SUBFLOW genl command to kernel.
 *
 * @param[in] pm                The mptcpd path manager object.
 * @param[in] token             MPTCP connection token.
 * @param[in] local_address_id  MPTCP local address ID.
 * @param[in] remote_address_id MPTCP remote address ID.
 * @param[in] local_addr        MPTCP subflow local address
 *                              information, including the port.
 * @param[in] remote_addr       MPTCP subflow remote address
 *                              information, including the port.
 * @param[in] backup            Whether or not to set the MPTCP
 *                              subflow backup priority flag.
 *
 * @return @c true if operation was successful. @c false otherwise.
 *
 * @todo There far too many parameters.  Reduce.
 */
MPTCPD_API bool
mptcpd_pm_add_subflow(struct mptcpd_pm *pm,
                      mptcpd_token_t token,
                      mptcpd_aid_t local_address_id,
                      mptcpd_aid_t remote_address_id,
                      struct sockaddr const *local_addr,
                      struct sockaddr const *remote_addr,
                      bool backup);

/**
 * @brief Send @c MPTCP_GENL_CMD_SET_BACKUP genl command to kernel.
 *
 * @param[in] pm                The mptcpd path manager object.
 * @param[in] token             MPTCP connection token.
 * @param[in] local_addr        MPTCP subflow local address
 *                              information, including the port.
 * @param[in] remote_addr       MPTCP subflow remote address
 *                              information, including the port.
 * @param[in] backup            Whether or not to set the MPTCP
 *                              subflow backup priority flag.
 *
 * @return @c true if operation was successful. @c false otherwise.
 */
MPTCPD_API bool mptcpd_pm_set_backup(
        struct mptcpd_pm *pm,
        mptcpd_token_t token,
        struct sockaddr const *local_addr,
        struct sockaddr const *remote_addr,
        bool backup);

/**
 * @brief Send @c MPTCP_GENL_CMD_REMOVE_SUBFLOW genl command to kernel.
 *
 * @param[in] pm                The mptcpd path manager object.
 * @param[in] token             MPTCP connection token.
 * @param[in] local_addr        MPTCP subflow local address
 *                              information, including the port.
 * @param[in] remote_addr       MPTCP subflow remote address
 *                              information, including the port.
 *
 * @return @c true if operation was successful. @c false otherwise.
 */
MPTCPD_API bool mptcpd_pm_remove_subflow(
        struct mptcpd_pm *pm,
        mptcpd_token_t token,
        struct sockaddr const *local_addr,
        struct sockaddr const *remote_addr);

/**
 * @brief Get pointer to the underlying network monitor.
 *
 * @param[in] pm Mptcpd path manager.
 *
 * @return Mptcpd network monitor.
 */
MPTCPD_API struct mptcpd_nm const *
mptcpd_pm_get_nm(struct mptcpd_pm const *pm);

#ifdef __cplusplus
}
#endif

#endif  // MPTCPD_LIB_PATH_MANAGER_H

/*
  Local Variables:
  c-file-style: "linux"
  End:
*/
