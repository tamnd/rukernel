# The AppArmor tests

This file is made by `tools/apparmor/report.py`. See README.md.

- ref: 6.8.0-147-generic lockdown,capability,landlock,yama,apparmor
- rk: 7.3.0-rukernel capability,yama,apparmor

## The profiles of Ubuntu

The test `profiles` loads /etc/apparmor.d with `apparmor_parser -r -K` and lists the profiles with `aa-status`.

| Kernel | Result | Parser | Profiles | aa-status | Enforce | Complain |
|---|---|---|---|---|---|---|
| ref | pass | 0 | 162 | 0 | 86 | 2 |
| rk | pass | 0 | 162 | 0 | 86 | 2 |

rk has the same profiles and modes as the reference.

## The load and the attach

In complain mode, a check that expects a denial gets no denial, so some tests fail on the reference too. Thus the pass set has two parts: the tests that pass on the reference, and the checks (the lines `ok`) of the reference in each test.

The reference passes 5 of the 16 tests of the load and the attach: profiles, at_secure, complain, environ, longpath. These tests have 198 checks that pass on the reference.

- rk: all of these tests and checks pass. rk reaches the pass set of the reference.

| Test | ref | rk |
|---|---|---|
| profiles | pass | pass |
| aa_exec | fail, 8 ok, 5 errors | fail, 8 ok, 5 errors |
| aa_policy_cache | timeout, 7 ok, 0 errors | exit, 7 ok, 0 errors |
| at_secure | pass, 74 ok | pass, 74 ok |
| changehat | timeout, 4 ok, 1 errors | fail, 8 ok, 5 errors |
| changehat_fork | timeout, 5 ok, 3 errors | fail, 6 ok, 4 errors |
| changehat_misc | hang, 5 ok, 3 errors | fail, 17 ok, 5 errors |
| changeprofile | fail, 17 ok, 16 errors | fail, 17 ok, 16 errors |
| complain | pass, 3 ok | pass, 3 ok |
| environ | pass, 30 ok | pass, 30 ok |
| exec | fail, 5 ok, 3 errors | fail, 5 ok, 3 errors |
| exec_qual | exit, 4 ok, 2 errors | fail, 10 ok, 4 errors |
| i18n | timeout, 16 ok, 5 errors | timeout, 26 ok, 8 errors |
| introspect | fail, 3 ok, 1 errors | fail, 3 ok, 1 errors |
| longpath | pass | pass |
| onexec | fail, 26 ok, 10 errors | fail, 26 ok, 10 errors |

## All the tests

- ref: 1 exit, 8 fail, 1 hang, 5 pass, 5 timeout
- rk: 1 exit, 9 fail, 4 pass, 1 timeout

| Test | ref | rk |
|---|---|---|
| aa_exec | fail, 8 ok, 5 errors | fail, 8 ok, 5 errors |
| aa_policy_cache | timeout, 7 ok, 0 errors | exit, 7 ok, 0 errors |
| at_secure | pass, 74 ok | pass, 74 ok |
| changehat | timeout, 4 ok, 1 errors | fail, 8 ok, 5 errors |
| changehat_fork | timeout, 5 ok, 3 errors | fail, 6 ok, 4 errors |
| changehat_misc | hang, 5 ok, 3 errors | fail, 17 ok, 5 errors |
| changeprofile | fail, 17 ok, 16 errors | fail, 17 ok, 16 errors |
| complain | pass, 3 ok | pass, 3 ok |
| environ | pass, 30 ok | pass, 30 ok |
| exec | fail, 5 ok, 3 errors | fail, 5 ok, 3 errors |
| exec_qual | exit, 4 ok, 2 errors | fail, 10 ok, 4 errors |
| i18n | timeout, 16 ok, 5 errors | timeout, 26 ok, 8 errors |
| introspect | fail, 3 ok, 1 errors | fail, 3 ok, 1 errors |
| longpath | pass | pass |
| net_raw | fail, 2 ok, 1 errors |  |
| onexec | fail, 26 ok, 10 errors | fail, 26 ok, 10 errors |
| open | fail, 5 ok, 4 errors |  |
| openat | timeout, 5 ok, 5 errors |  |
| overlayfs_kernel | fail |  |
| pipe | pass, 3 ok |  |

## The first error of each test that does not pass

- ref, aa_exec: `Error: aa_exec_profile failed. Test 'enforce' was expected to 'pass'. Reason for failure 'FAIL: bad confinement context: "/apparmor/tests/regression/apparmor/aa_exec_profile (complain)" != "/apparmor/`
- ref, aa_policy_cache: `ok (pass): AA_POLICY_CACHE new create (bad .features)`
- ref, changehat: `Error: changehat passed. Test 'NO CHANGEHAT (access sub file)' was expected to 'fail'`
- ref, changehat_fork: `Error: changehat_fork passed. Test 'NO CHANGEHAT (access sub file)' was expected to 'fail'`
- ref, changehat_misc: `Error: changehat_misc passed. Test 'NO CHANGEHAT (access sub file)' was expected to 'fail'`
- ref, changeprofile: `Error: changeprofile passed. Test 'NO CHANGEPROFILE (access sub file)' was expected to 'fail'`
- ref, exec: `Error: exec passed. Test 'EXEC with px - no profile' was expected to 'fail'`
- ref, exec_qual: `Error: exec_qual passed. Test 'enforce px case2' was expected to 'fail'`
- ref, i18n: `Error: open passed. Test 'i18n (128) OPEN (octal) "/tmp/sdtest.767-7698-vgNAZS/file_�_post" W' was expected to 'fail'`
- ref, introspect: `Error: introspect failed. Test 'introspect self confined' was expected to 'pass'. Reason for failure 'FAIL: expected mode "enforce" != "complain"'`
- ref, net_raw: `Error: net_raw passed. Test 'RAW SOCKET (no cap)' was expected to 'fail'`
- ref, onexec: `Error: transition passed. Test 'iface= ONEXEC no px perm (/apparmor/tests/regression/apparmor/transition -> nochange)' was expected to 'fail'`
- ref, open: `Error: open passed. Test 'OPEN R' was expected to 'fail'`
- ref, openat: `Error: openat passed. Test 'OPENAT R' was expected to 'fail'`
- ref, overlayfs_kernel: `rm: cannot remove '/tmp/sdtest.212-32556-QCWE8t/overlay_lower': Device or resource busy`
- rk, aa_exec: `Error: aa_exec_profile failed. Test 'enforce' was expected to 'pass'. Reason for failure 'FAIL: bad confinement context: "/apparmor/tests/regression/apparmor/aa_exec_profile (complain)" != "/apparmor/`
- rk, aa_policy_cache: `ok (pass): AA_POLICY_CACHE new create (bad .features)`
- rk, changehat: `Error: changehat passed. Test 'NO CHANGEHAT (access sub file)' was expected to 'fail'`
- rk, changehat_fork: `Error: changehat_fork passed. Test 'NO CHANGEHAT (access sub file)' was expected to 'fail'`
- rk, changehat_misc: `Error: changehat_misc passed. Test 'NO CHANGEHAT (access sub file)' was expected to 'fail'`
- rk, changeprofile: `Error: changeprofile passed. Test 'NO CHANGEPROFILE (access sub file)' was expected to 'fail'`
- rk, exec: `Error: exec passed. Test 'EXEC with px - no profile' was expected to 'fail'`
- rk, exec_qual: `Error: exec_qual passed. Test 'enforce px case2' was expected to 'fail'`
- rk, i18n: `Error: open passed. Test 'i18n (128) OPEN (octal) "/tmp/sdtest.671-28402-gw7WgK/file_�_post" W' was expected to 'fail'`
- rk, introspect: `Error: introspect failed. Test 'introspect self confined' was expected to 'pass'. Reason for failure 'FAIL: expected mode "enforce" != "complain"'`
- rk, onexec: `Error: transition passed. Test 'iface= ONEXEC no px perm (/apparmor/tests/regression/apparmor/transition -> nochange)' was expected to 'fail'`
