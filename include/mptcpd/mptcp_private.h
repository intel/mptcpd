// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file mptcpd/mptcp_private.h
 *
 * @brief mptcpd convenience wrapper around <linux/mptcp.h>.
 *
 * Support for the upstream (server-oriented) and the
 * multipath-tcp.org (client-oriented) <linux/mptcp.h> headers.
 *
 * Copyright (c) 2020, Intel Corporation
 */

#ifndef MPTCPD_MPTCP_PRIVATE_H
#define MPTCPD_MPTCP_PRIVATE_H

#ifdef HAVE_CONFIG_H
# include "config-private.h"
#endif

#ifdef HAVE_LINUX_MPTCP_H
# include <linux/mptcp.h>

# ifdef MPTCP_PM_NAME
/*
  Platform has upstream / server-oriented MPTCP path mangement generic
  netlink API so include local copy of the multipath-tcp-org /
  client-oriented <linux/mptcp.h> header.
*/
#  include "linux/mptcp_client.h"
# elif defined(MPTCP_GENL_NAME)
/*
  Platform has multipath-tcp.org / client-oriented MPTCP path
  mangement generic netlink API so include local copy of the upstream
  / server-oriented <linux/mptcp.h> header.
*/
#  include "linux/mptcp_server.h"
# else
#  error "Unrecognized <linux/mptcp.h> header."
# endif // MPTCP_PM_NAME
#else
/*
  No <linux/mptcp.h> header exists on the platform so use the local
  mptcpd copies to allow mptcpd to be compiled.
*/
/**
 * @todo Should we drop this case entirely, and require the
 *       <linux/mptcp.h> header to exist?
 */
# include "linux/mptcp_server.h"
# include "linux/mptcp_client.h"
#endif // HAVE_LINUX_MPTCP_H

#endif // MPTCPD_MPTCP_PRIVATE_H
