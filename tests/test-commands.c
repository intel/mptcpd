// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file test-commands.c
 *
 * @brief mptcpd commands API test.
 *
 * Copyright (c) 2019-2020, Intel Corporation
 */

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include <ell/main.h>
#include <ell/genl.h>
#include <ell/timeout.h>
#include <ell/util.h>      // Needed by <ell/log.h>
#include <ell/log.h>
#include <ell/test.h>

#include "../src/configuration.h"   // INTERNAL!
#include "../src/path_manager.h"    // INTERNAL!

#include "test-plugin.h"
#include "test-util.h"

#include <mptcpd/path_manager.h>
#include <mptcpd/addr_info.h>
#include <mptcpd/mptcp_private.h>


// -------------------------------------------------------------------

struct test_info
{
        char const *const family_name;

        bool tests_called;
};

// -------------------------------------------------------------------

static struct sockaddr const *const laddr1 =
        (struct sockaddr const *) &test_laddr_1;

static struct sockaddr const *const laddr2 =
        (struct sockaddr const *) &test_laddr_2;

static struct sockaddr const *const raddr1 =
        (struct sockaddr const *) &test_raddr_1;

static struct sockaddr const *const raddr2 =
        (struct sockaddr const *) &test_raddr_2;

// -------------------------------------------------------------------

static uint32_t const max_addrs = 3;
static uint32_t const max_subflows = 5;

static struct mptcpd_limit const limits[] = {
        {
                .type  = MPTCPD_LIMIT_RCV_ADD_ADDRS,
                .limit = max_addrs
        },
        {
                .type  = MPTCPD_LIMIT_SUBFLOWS,
                .limit = max_subflows
        }
};
        
// -------------------------------------------------------------------

static bool is_pm_ready(struct mptcpd_pm const *pm, char const *fname)
{
        bool const ready = mptcpd_pm_ready(pm);

        if (!ready)
                l_warn("Path manager not yet ready.  "
                       "%s cannot be completed.", fname);

        return ready;
}

// -------------------------------------------------------------------

static void test_add_addr(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        uint32_t flags = 0;
        int index = 0;

        assert(mptcpd_pm_add_addr(pm,
                                  laddr1,
                                  test_laddr_id_1,
                                  flags,
                                  index,
                                  test_token_1) == 0);
}

static void test_remove_addr(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        assert(mptcpd_pm_remove_addr(pm,
                                     test_laddr_id_1,
                                     test_token_1) == 0);
}

static void test_get_addr(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        mptcpd_aid_t const id = test_laddr_id_1;
        struct mptcpd_addr_info *info = NULL;

        int const result = mptcpd_pm_get_addr(pm, id, &info);

        assert(result == 0 || result == ENOTSUP);

        if (result == 0) {
                /**
                 * @bug We could have a resource leak in the kernel
                 *      here if the below assert()s are triggered
                 *      since addresses previously added through
                 *      @c mptcpd_pm_add_addr() would end up not being
                 *      removed prior to test exit.
                 */
                assert(info != NULL);
                assert(info->id == id);

                struct sockaddr const *const addr = laddr1;
                assert(sockaddr_is_equal(addr,
                                         (struct sockaddr *) &info->addr));

                mptcpd_addr_info_destroy(info);
        }
}

static void test_dump_addrs(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        struct mptcpd_addr_info *info = NULL;
        size_t len = 0;

        int const result = mptcpd_pm_dump_addrs(pm, &info, &len);

        assert(result == 0 || result == ENOTSUP);

        if (result == 0) {
                /**
                 * @bug We could have a resource leak in the kernel
                 *      here if the below assert()s are triggered
                 *      since addresses previously added through
                 *      @c mptcpd_pm_add_addr() would end up not being
                 *      removed prior to test exit.
                 */
                assert(info != NULL);
                assert(len != 0);

                mptcpd_aid_t const id = test_laddr_id_1;
                assert(info[0].id == id);

                struct sockaddr const *const addr = laddr1;
                assert(sockaddr_is_equal(addr,
                                         (struct sockaddr *) &(info[0].addr)));

                mptcpd_addr_info_destroy(info);
        }
}

static void test_flush_addrs(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        int const result = mptcpd_pm_flush_addrs(pm);

        /**
         * @bug We could have a resource leak in the kernel here if
         *      the below assert()s are triggered since addresses
         *      previously added through @c mptcpd_pm_add_addr() would
         *      end up not being removed prior to test exit.
         */
        assert(result == 0 || result == ENOTSUP);
}

static void test_set_limits(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        int const result = mptcpd_pm_set_limits(pm,
                                                limits,
                                                L_ARRAY_SIZE(limits));

        assert(result == 0 || result == ENOTSUP);
}

static void test_get_limits(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        struct mptcpd_limit *rl = NULL;
        size_t len = 0;

        int const result = mptcpd_pm_get_limits(pm,
                                                &rl,
                                                &len);

        assert(result == 0 || result == ENOTSUP);

        if (result == 0) {
                assert(rl != NULL);
                assert(len == L_ARRAY_SIZE(limits));

                for (struct mptcpd_limit *l = rl; l != rl + len; ++l) {
                        if (l->type == MPTCPD_LIMIT_RCV_ADD_ADDRS) {
                                assert(l->limit == max_addrs);
                        } else if (l->type == MPTCPD_LIMIT_SUBFLOWS) {
                                assert(l->limit == max_subflows);
                        } else {
                                /*
                                  Unless more MPTCP limit types are
                                  added to the kernel path management
                                  API this should never be reached.
                                */
                                l_error("Unexpected MPTCP limit type.");
                        }
                }

                free(rl);
        }
}

static void test_add_subflow(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        int const result = mptcpd_pm_add_subflow(pm,
                                                 test_token_2,
                                                 test_laddr_id_2,
                                                 test_raddr_id_2,
                                                 laddr2,
                                                 raddr2,
                                                 test_backup_2);

        assert(result == 0 || result == ENOTSUP);
}

void test_set_backup(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;


        int const result = mptcpd_pm_set_backup(pm,
                                                test_token_1,
                                                laddr1,
                                                raddr1,
                                                test_backup_1);

        assert(result == 0 || result == ENOTSUP);
}

void test_remove_subflow(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        if (!is_pm_ready(pm, __func__))
                return;

        int const result = mptcpd_pm_remove_subflow(pm,
                                                    test_token_1,
                                                    laddr1,
                                                    raddr1);

        assert(result == 0 || result == ENOTSUP);
}

void test_get_nm(void const *test_data)
{
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) test_data;

        assert(mptcpd_pm_get_nm(pm) != NULL);
}

// -------------------------------------------------------------------

static void run_tests(struct l_genl_family_info const *info,
                      void *user_data)
{
        /*
          Check if the initial request for the MPTCP generic netlink
          family failed.  A subsequent family watch will be used to
          call this function again when it appears.
         */
        if (info == NULL)
                return;

        struct test_info *const t = user_data;

        assert(strcmp(l_genl_family_info_get_name(info),
                      t->family_name) == 0);

        l_test_run();

        t->tests_called = true;

        l_main_quit();
}

static void timeout_callback(struct l_timeout *timeout,
                             void *user_data)
{
        (void) timeout;
        (void) user_data;

        l_debug("test timed out");

        l_main_quit();
}

// -------------------------------------------------------------------

int main(void)
{
        if (!l_main_init())
                return -1;

        l_log_set_stderr();
        l_debug_enable("*");

        static char *argv[] = {
                "test-commands",
                "--plugin-dir",
                TEST_PLUGIN_DIR
        };
        static char **args = argv;

        static int argc = L_ARRAY_SIZE(argv);

        struct mptcpd_config *const config =
                mptcpd_config_create(argc, argv);
        assert(config);

        struct mptcpd_pm *pm = mptcpd_pm_create(config);
        assert(pm);

        struct test_info info = {
                .family_name = tests_get_pm_family_name()
        };

        assert(info.family_name);

        l_test_init(&argc, &args);

        l_test_add("add_addr",       test_add_addr,       pm);
        l_test_add("get_addr",       test_get_addr,       pm);
        l_test_add("dump_addrs",     test_dump_addrs,     pm);
        l_test_add("flush_addrs",    test_flush_addrs,    pm);
        l_test_add("remove_addr",    test_remove_addr,    pm);
        l_test_add("set_limits",     test_set_limits,     pm);
        l_test_add("get_limits",     test_get_limits,     pm);
        l_test_add("add_subflow",    test_add_subflow,    pm);
        l_test_add("set_backup",     test_set_backup,     pm);
        l_test_add("remove_subflow", test_remove_subflow, pm);
        l_test_add("get_nm",         test_get_nm,         pm);

        /*
          Prepare to run the path management generic netlink command
          tests.
        */
        struct l_genl *const genl = l_genl_new();
        assert(genl != NULL);

        unsigned int const watch_id =
                l_genl_add_family_watch(genl,
                                        info.family_name,
                                        run_tests,
                                        NULL,
                                        &info,
                                        NULL);

        assert(watch_id != 0);

        bool const requested = l_genl_request_family(genl,
                                                     info.family_name,
                                                     run_tests,
                                                     &info,
                                                     NULL);
        assert(requested);

        // Bound the time we wait for the tests to run.
        static unsigned long const milliseconds = 500;
        struct l_timeout *const timeout =
                l_timeout_create_ms(milliseconds,
                                    timeout_callback,
                                    NULL,
                                    NULL);

        (void) l_main_run();

        /*
          The tests will have run only if the MPTCP generic netlink
          family appeared.
         */
        assert(info.tests_called);

        l_timeout_remove(timeout);
        l_genl_remove_family_watch(genl, watch_id);
        l_genl_unref(genl);
        mptcpd_pm_destroy(pm);
        mptcpd_config_destroy(config);

        return l_main_exit() ? 0 : -1;
}


/*
  Local Variables:
  c-file-style: "linux"
  End:
*/
