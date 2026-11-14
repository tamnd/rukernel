# nftables tests/shell results

report.py makes this file from the logs of the runs of run.py. Do not change it by hand.

These are the results of the tests of tests/shell of nftables 1.0.9, with `nft` 1.0.9 of Alpine. The README in this directory tells how the tests run. The Linux column is the result on the reference kernel. A test that passes on Linux and does not pass on rukernel is work that remains. A skip is a test that needs a feature that the kernel or `nft` does not have, as run-tests.sh finds it.

## Status at 2026-11-14

| Directory | Tests | Pass on Linux | Pass on rukernel x86_64 | Pass on both | Pass on rukernel arm64 |
| --- | --- | --- | --- | --- | --- |
| bitwise | 10 | 10 | 10 | 10 | 10 |
| bogons | 1 | 1 | 1 | 1 | 1 |
| cache | 11 | 11 | 8 | 8 | 8 |
| chains | 44 | 40 | 38 | 34 | 38 |
| comments | 1 | 1 | 1 | 1 | 1 |
| flowtable | 15 | 15 | 15 | 15 | 15 |
| include | 21 | 21 | 21 | 21 | 21 |
| json | 7 | 6 | 5 | 5 | 5 |
| listing | 22 | 22 | 22 | 22 | 22 |
| maps | 31 | 31 | 29 | 29 | 27 |
| netns | 3 | 3 | 3 | 3 | 3 |
| nft-f | 34 | 34 | 31 | 31 | 31 |
| nft-i | 1 | 1 | 1 | 1 | 1 |
| optimizations | 16 | 16 | 14 | 14 | 14 |
| optionals | 11 | 11 | 11 | 11 | 11 |
| owner | 1 | 1 | 1 | 1 | 1 |
| packetpath | 1 | 1 | 0 | 0 | 0 |
| parsing | 4 | 4 | 3 | 3 | 3 |
| rule_management | 12 | 12 | 11 | 11 | 11 |
| sets | 93 | 91 | 85 | 85 | 81 |
| transactions | 41 | 39 | 39 | 37 | 39 |
| all | 380 | 371 | 349 | 343 | 343 |

## Work that remains

These tests pass on Linux and do not pass on rukernel x86_64.

- cache: 3: [cache/0005_cache_chain_flush](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0005_cache_chain_flush?h=v1.0.9), [cache/0006_cache_table_flush](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0006_cache_table_flush?h=v1.0.9), [cache/0010_implicit_chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0010_implicit_chain_0?h=v1.0.9).
- chains: 6: [chains/0021prio_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0021prio_0?h=v1.0.9), [chains/0041chain_binding_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0041chain_binding_0?h=v1.0.9), [chains/0042chain_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0042chain_variable_0?h=v1.0.9), [chains/0043chain_ingress_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0043chain_ingress_0?h=v1.0.9), [chains/netdev_chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/netdev_chain_0?h=v1.0.9), [chains/netdev_chain_autoremove](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/netdev_chain_autoremove?h=v1.0.9).
- json: 1: [json/netdev](https://git.netfilter.org/nftables/tree/tests/shell/testcases/json/netdev?h=v1.0.9).
- maps: 2: [maps/typeof_maps_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_maps_0?h=v1.0.9), [maps/typeof_maps_add_delete](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_maps_add_delete?h=v1.0.9).
- nft-f: 3: [nft-f/0022variables_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0022variables_0?h=v1.0.9), [nft-f/0032pknock_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0032pknock_0?h=v1.0.9), [nft-f/sample-ruleset](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/sample-ruleset?h=v1.0.9).
- optimizations: 2: [optimizations/merge_vmaps](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_vmaps?h=v1.0.9), [optimizations/ruleset](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/ruleset?h=v1.0.9).
- packetpath: 1: [packetpath/vlan_8021ad_tag](https://git.netfilter.org/nftables/tree/tests/shell/testcases/packetpath/vlan_8021ad_tag?h=v1.0.9).
- parsing: 1: [parsing/large_rule_pipe](https://git.netfilter.org/nftables/tree/tests/shell/testcases/parsing/large_rule_pipe?h=v1.0.9).
- rule_management: 1: [rule_management/0011reset_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0011reset_0?h=v1.0.9).
- sets: 6: [sets/0028autoselect_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0028autoselect_0?h=v1.0.9), [sets/0055tcpflags_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0055tcpflags_0?h=v1.0.9), [sets/dynset_missing](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/dynset_missing?h=v1.0.9), [sets/inner_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/inner_0?h=v1.0.9), [sets/sets_with_ifnames](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/sets_with_ifnames?h=v1.0.9), [sets/typeof_sets_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/typeof_sets_0?h=v1.0.9).
- transactions: 2: [transactions/0049huge_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0049huge_0?h=v1.0.9), [transactions/table_onoff](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/table_onoff?h=v1.0.9).

## Each test

| Test | Linux | rukernel x86_64 | rukernel arm64 | Note |
| --- | --- | --- | --- | --- |
| [bitwise/0040mark_binop_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_0?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_1?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_2](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_2?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_3](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_3?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_4](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_4?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_5](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_5?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_6](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_6?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_7](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_7?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_8](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_8?h=v1.0.9) | pass | pass | pass |  |
| [bitwise/0040mark_binop_9](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bitwise/0040mark_binop_9?h=v1.0.9) | pass | pass | pass |  |
| [bogons/assert_failures](https://git.netfilter.org/nftables/tree/tests/shell/testcases/bogons/assert_failures?h=v1.0.9) | pass | pass | pass |  |
| [cache/0001_cache_handling_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0001_cache_handling_0?h=v1.0.9) | pass | pass | pass |  |
| [cache/0002_interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0002_interval_0?h=v1.0.9) | pass | pass | pass |  |
| [cache/0003_cache_update_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0003_cache_update_0?h=v1.0.9) | pass | pass | pass |  |
| [cache/0004_cache_update_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0004_cache_update_0?h=v1.0.9) | pass | pass | pass |  |
| [cache/0005_cache_chain_flush](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0005_cache_chain_flush?h=v1.0.9) | pass | dump differs | dump differs |  |
| [cache/0006_cache_table_flush](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0006_cache_table_flush?h=v1.0.9) | pass | dump differs | dump differs |  |
| [cache/0007_echo_cache_init_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0007_echo_cache_init_0?h=v1.0.9) | pass | pass | pass |  |
| [cache/0008_delete_by_handle_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0008_delete_by_handle_0?h=v1.0.9) | pass | pass | pass |  |
| [cache/0009_delete_by_handle_incorrect_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0009_delete_by_handle_incorrect_0?h=v1.0.9) | pass | pass | pass |  |
| [cache/0010_implicit_chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0010_implicit_chain_0?h=v1.0.9) | pass | skip | skip |  |
| [cache/0011_index_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/cache/0011_index_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0001jumps_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0001jumps_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0002jumps_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0002jumps_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0003jump_loop_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0003jump_loop_1?h=v1.0.9) | fail | pass | pass | E: loop of jumps ignored? |
| [chains/0004busy_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0004busy_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0005busy_map_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0005busy_map_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0006masquerade_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0006masquerade_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0007masquerade_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0007masquerade_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0008masquerade_jump_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0008masquerade_jump_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0009masquerade_jump_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0009masquerade_jump_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0010endless_jump_loop_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0010endless_jump_loop_1?h=v1.0.9) | fail | pass | pass | E: accepted endless jump loop in a vmap |
| [chains/0011endless_jump_loop_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0011endless_jump_loop_1?h=v1.0.9) | fail | pass | pass | E: accepted endless jump loop in a vmap |
| [chains/0013rename_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0013rename_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0014rename_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0014rename_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0015check_jump_loop_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0015check_jump_loop_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0016delete_handle_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0016delete_handle_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0017masquerade_jump_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0017masquerade_jump_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0018check_jump_loop_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0018check_jump_loop_1?h=v1.0.9) | fail | pass | pass | E: Accepted jump-to-self |
| [chains/0019masquerade_jump_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0019masquerade_jump_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0020depth_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0020depth_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0021prio_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0021prio_0?h=v1.0.9) | pass | fail | fail | tmp.DL3kuboju5:381:42-89: Error: Chain of type "filter" is not supported, perhaps kernel support ... |
| [chains/0022prio_dummy_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0022prio_dummy_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0023prio_inet_srcnat_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0023prio_inet_srcnat_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0024prio_inet_dstnat_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0024prio_inet_dstnat_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0025prio_arp_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0025prio_arp_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0026prio_netdev_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0026prio_netdev_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0027prio_bridge_dstnat_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0027prio_bridge_dstnat_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0028prio_bridge_out_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0028prio_bridge_out_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0029prio_bridge_srcnat_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0029prio_bridge_srcnat_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0030create_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0030create_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0031priority_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0031priority_variable_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0032priority_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0032priority_variable_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0033priority_variable_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0033priority_variable_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0034priority_variable_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0034priority_variable_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0035policy_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0035policy_variable_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0036policy_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0036policy_variable_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0037policy_variable_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0037policy_variable_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0038policy_variable_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0038policy_variable_1?h=v1.0.9) | pass | pass | pass |  |
| [chains/0039negative_priority_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0039negative_priority_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/0041chain_binding_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0041chain_binding_0?h=v1.0.9) | pass | skip | skip |  |
| [chains/0042chain_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0042chain_variable_0?h=v1.0.9) | pass | fail | fail | /dev/stdin:5:3-56: Error: Chain of type "filter" is not supported, perhaps kernel support is miss... |
| [chains/0043chain_ingress_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0043chain_ingress_0?h=v1.0.9) | pass | skip | skip |  |
| [chains/0044chain_destroy_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/0044chain_destroy_0?h=v1.0.9) | pass | pass | pass |  |
| [chains/netdev_chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/netdev_chain_0?h=v1.0.9) | pass | skip | skip |  |
| [chains/netdev_chain_autoremove](https://git.netfilter.org/nftables/tree/tests/shell/testcases/chains/netdev_chain_autoremove?h=v1.0.9) | pass | fail | fail | RTNETLINK answers: Not supported |
| [comments/comments_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/comments/comments_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0001flowtable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0001flowtable_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0002create_flowtable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0002create_flowtable_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0003add_after_flush_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0003add_after_flush_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0004delete_after_add_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0004delete_after_add_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0005delete_in_use_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0005delete_in_use_1?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0006segfault_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0006segfault_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0007prio_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0007prio_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0008prio_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0008prio_1?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0009deleteafterflush_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0009deleteafterflush_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0010delete_handle_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0010delete_handle_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0011deleteafterflush_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0011deleteafterflush_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0012flowtable_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0012flowtable_variable_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0013addafterdelete_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0013addafterdelete_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0014addafterdelete_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0014addafterdelete_0?h=v1.0.9) | pass | pass | pass |  |
| [flowtable/0015destroy_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/flowtable/0015destroy_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0001absolute_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0001absolute_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0002relative_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0002relative_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0003includepath_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0003includepath_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0004endlessloop_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0004endlessloop_1?h=v1.0.9) | pass | pass | pass |  |
| [include/0005glob_empty_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0005glob_empty_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0006glob_single_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0006glob_single_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0007glob_double_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0007glob_double_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0008glob_nofile_wildcard_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0008glob_nofile_wildcard_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0009glob_nofile_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0009glob_nofile_1?h=v1.0.9) | pass | pass | pass |  |
| [include/0010glob_broken_file_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0010glob_broken_file_1?h=v1.0.9) | pass | pass | pass |  |
| [include/0011glob_dependency_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0011glob_dependency_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0012glob_dependency_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0012glob_dependency_1?h=v1.0.9) | pass | pass | pass |  |
| [include/0013glob_dotfile_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0013glob_dotfile_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0013input_descriptors_included_files_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0013input_descriptors_included_files_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0014glob_directory_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0014glob_directory_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0015doubleincludepath_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0015doubleincludepath_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0016maxdepth_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0016maxdepth_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0017glob_more_than_maxdepth_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0017glob_more_than_maxdepth_1?h=v1.0.9) | pass | pass | pass |  |
| [include/0018include_error_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0018include_error_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0019include_error_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0019include_error_0?h=v1.0.9) | pass | pass | pass |  |
| [include/0020include_chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/include/0020include_chain_0?h=v1.0.9) | pass | pass | pass |  |
| [json/0001set_statements_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/json/0001set_statements_0?h=v1.0.9) | pass | pass | pass |  |
| [json/0002table_map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/json/0002table_map_0?h=v1.0.9) | pass | pass | pass |  |
| [json/0003json_schema_version_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/json/0003json_schema_version_0?h=v1.0.9) | pass | pass | pass |  |
| [json/0004json_schema_version_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/json/0004json_schema_version_1?h=v1.0.9) | pass | pass | pass |  |
| [json/0005secmark_objref_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/json/0005secmark_objref_0?h=v1.0.9) | fail | fail | fail | internal:0:0-0: Error: Could not process rule: No such file or directory |
| [json/0006obj_comment_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/json/0006obj_comment_0?h=v1.0.9) | pass | pass | pass |  |
| [json/netdev](https://git.netfilter.org/nftables/tree/tests/shell/testcases/json/netdev?h=v1.0.9) | pass | fail | fail | internal:0:0-0: Error: Chain of type "filter" is not supported, perhaps kernel support is missing? |
| [listing/0001ruleset_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0001ruleset_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0002ruleset_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0002ruleset_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0003table_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0003table_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0004table_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0004table_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0005ruleset_ip_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0005ruleset_ip_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0006ruleset_ip6_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0006ruleset_ip6_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0007ruleset_inet_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0007ruleset_inet_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0008ruleset_arp_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0008ruleset_arp_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0009ruleset_bridge_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0009ruleset_bridge_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0010sets_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0010sets_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0011sets_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0011sets_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0012sets_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0012sets_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0013objects_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0013objects_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0014objects_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0014objects_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0015dynamic_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0015dynamic_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0016anonymous_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0016anonymous_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0017objects_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0017objects_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0018data_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0018data_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0019set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0019set_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0020flowtable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0020flowtable_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0021ruleset_json_terse_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0021ruleset_json_terse_0?h=v1.0.9) | pass | pass | pass |  |
| [listing/0022terse_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/listing/0022terse_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0003map_add_many_elements_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0003map_add_many_elements_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0004interval_map_create_once_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0004interval_map_create_once_0?h=v1.0.9) | pass | pass | hang |  |
| [maps/0005interval_map_add_many_elements_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0005interval_map_add_many_elements_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0006interval_map_overlap_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0006interval_map_overlap_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0007named_ifname_dtype_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0007named_ifname_dtype_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0008interval_map_delete_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0008interval_map_delete_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0009vmap_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0009vmap_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0010concat_map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0010concat_map_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0011vmap_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0011vmap_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0012map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0012map_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0013map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0013map_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0014destroy_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0014destroy_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0016map_leak_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0016map_leak_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0017_map_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0017_map_variable_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/0018map_leak_timeout_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/0018map_leak_timeout_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/anon_objmap_concat](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/anon_objmap_concat?h=v1.0.9) | pass | pass | pass |  |
| [maps/anonymous_snat_map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/anonymous_snat_map_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/different_map_types_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/different_map_types_1?h=v1.0.9) | pass | pass | pass |  |
| [maps/map_catchall_double_deactivate](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/map_catchall_double_deactivate?h=v1.0.9) | pass | pass | pass |  |
| [maps/map_with_flags_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/map_with_flags_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/named_snat_map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/named_snat_map_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/nat_addr_port](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/nat_addr_port?h=v1.0.9) | pass | pass | pass |  |
| [maps/typeof_integer_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_integer_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/typeof_maps_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_maps_0?h=v1.0.9) | pass | fail | fail | /dev/stdin:34:3-16: Error: Could not process rule: No such file or directory |
| [maps/typeof_maps_add_delete](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_maps_add_delete?h=v1.0.9) | pass | dump differs | dump differs | Error: Could not process rule: No such file or directory |
| [maps/typeof_maps_concat](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_maps_concat?h=v1.0.9) | pass | pass | pass |  |
| [maps/typeof_maps_concat_update_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_maps_concat_update_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/typeof_maps_update_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_maps_update_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/typeof_raw_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/typeof_raw_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/vmap_mark_bitwise_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/vmap_mark_bitwise_0?h=v1.0.9) | pass | pass | pass |  |
| [maps/vmap_timeout](https://git.netfilter.org/nftables/tree/tests/shell/testcases/maps/vmap_timeout?h=v1.0.9) | pass | pass | hang |  |
| [netns/0001nft-f_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/netns/0001nft-f_0?h=v1.0.9) | pass | pass | pass |  |
| [netns/0002loosecommands_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/netns/0002loosecommands_0?h=v1.0.9) | pass | pass | pass |  |
| [netns/0003many_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/netns/0003many_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0001define_slash_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0001define_slash_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0002rollback_rule_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0002rollback_rule_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0003rollback_jump_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0003rollback_jump_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0004rollback_set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0004rollback_set_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0005rollback_map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0005rollback_map_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0006action_object_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0006action_object_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0007action_object_set_segfault_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0007action_object_set_segfault_1?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0008split_tables_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0008split_tables_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0009variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0009variable_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0010variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0010variable_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0011manydefines_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0011manydefines_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0012different_defines_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0012different_defines_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0013defines_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0013defines_1?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0014defines_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0014defines_1?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0015defines_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0015defines_1?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0016redefines_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0016redefines_1?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0017ct_timeout_obj_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0017ct_timeout_obj_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0018ct_expectation_obj_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0018ct_expectation_obj_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0018jump_variable_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0018jump_variable_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0019jump_variable_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0019jump_variable_1?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0020jump_variable_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0020jump_variable_1?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0021list_ruleset_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0021list_ruleset_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0022variables_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0022variables_0?h=v1.0.9) | pass | dump differs | dump differs |  |
| [nft-f/0023check_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0023check_1?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0024priority_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0024priority_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0025empty_dynset_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0025empty_dynset_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0026listing_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0026listing_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0027split_chains_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0027split_chains_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0028variable_cmdline_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0028variable_cmdline_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0029split_file_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0029split_file_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0030variable_reuse_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0030variable_reuse_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0031vmap_string_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0031vmap_string_0?h=v1.0.9) | pass | pass | pass |  |
| [nft-f/0032pknock_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/0032pknock_0?h=v1.0.9) | pass | dump differs | dump differs |  |
| [nft-f/sample-ruleset](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-f/sample-ruleset?h=v1.0.9) | pass | skip | skip |  |
| [nft-i/0001define_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/nft-i/0001define_0?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/dependency_kill](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/dependency_kill?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/merge_nat](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_nat?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/merge_reject](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_reject?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/merge_stmts](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_stmts?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/merge_stmts_concat](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_stmts_concat?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/merge_stmts_concat_vmap](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_stmts_concat_vmap?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/merge_stmts_vmap](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_stmts_vmap?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/merge_vmap_raw](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_vmap_raw?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/merge_vmaps](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/merge_vmaps?h=v1.0.9) | pass | dump differs | dump differs | meta l4proto vmap { tcp : goto filter_in_tcp, udp : goto filter_in_udp } |
| [optimizations/not_mergeable](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/not_mergeable?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/ruleset](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/ruleset?h=v1.0.9) | pass | fail | fail | /dev/stdin:85:3-16: Error: Could not process rule: No such file or directory |
| [optimizations/single_anon_set](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/single_anon_set?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/skip_merge](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/skip_merge?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/skip_non_eq](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/skip_non_eq?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/skip_unsupported](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/skip_unsupported?h=v1.0.9) | pass | pass | pass |  |
| [optimizations/variables](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optimizations/variables?h=v1.0.9) | pass | pass | pass |  |
| [optionals/comments_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/comments_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/comments_chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/comments_chain_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/comments_handles_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/comments_handles_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/comments_objects_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/comments_objects_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/comments_objects_dup_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/comments_objects_dup_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/comments_table_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/comments_table_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/delete_object_handles_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/delete_object_handles_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/handles_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/handles_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/handles_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/handles_1?h=v1.0.9) | pass | pass | pass |  |
| [optionals/log_prefix_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/log_prefix_0?h=v1.0.9) | pass | pass | pass |  |
| [optionals/update_object_handles_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/optionals/update_object_handles_0?h=v1.0.9) | pass | pass | pass |  |
| [owner/0001-flowtable-uaf](https://git.netfilter.org/nftables/tree/tests/shell/testcases/owner/0001-flowtable-uaf?h=v1.0.9) | pass | pass | pass |  |
| [packetpath/vlan_8021ad_tag](https://git.netfilter.org/nftables/tree/tests/shell/testcases/packetpath/vlan_8021ad_tag?h=v1.0.9) | pass | fail | fail | RTNETLINK answers: Not supported |
| [parsing/describe](https://git.netfilter.org/nftables/tree/tests/shell/testcases/parsing/describe?h=v1.0.9) | pass | pass | pass |  |
| [parsing/large_rule_pipe](https://git.netfilter.org/nftables/tree/tests/shell/testcases/parsing/large_rule_pipe?h=v1.0.9) | pass | fail | fail | /dev/stdin:246:21-39: Error: Could not process rule: No such file or directory |
| [parsing/log](https://git.netfilter.org/nftables/tree/tests/shell/testcases/parsing/log?h=v1.0.9) | pass | pass | pass |  |
| [parsing/octal](https://git.netfilter.org/nftables/tree/tests/shell/testcases/parsing/octal?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0001addinsertposition_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0001addinsertposition_0?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0002addinsertlocation_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0002addinsertlocation_1?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0003insert_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0003insert_0?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0004replace_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0004replace_0?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0005replace_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0005replace_1?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0006replace_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0006replace_1?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0007delete_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0007delete_0?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0008delete_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0008delete_1?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0009delete_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0009delete_1?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0010replace_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0010replace_0?h=v1.0.9) | pass | pass | pass |  |
| [rule_management/0011reset_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0011reset_0?h=v1.0.9) | pass | skip | skip |  |
| [rule_management/0012destroy_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/rule_management/0012destroy_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0001named_interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0001named_interval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0002named_interval_automerging_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0002named_interval_automerging_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0003named_interval_missing_flag_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0003named_interval_missing_flag_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0004named_interval_shadow_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0004named_interval_shadow_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0005named_interval_shadow_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0005named_interval_shadow_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0006create_set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0006create_set_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0007create_element_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0007create_element_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0008comments_interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0008comments_interval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0008create_verdict_map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0008create_verdict_map_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0009comments_timeout_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0009comments_timeout_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0010comments_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0010comments_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0011add_many_elements_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0011add_many_elements_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0012add_delete_many_elements_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0012add_delete_many_elements_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0013add_delete_many_elements_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0013add_delete_many_elements_0?h=v1.0.9) | pass | pass | hang |  |
| [sets/0014malformed_set_is_not_defined_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0014malformed_set_is_not_defined_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0015rulesetflush_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0015rulesetflush_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0016element_leak_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0016element_leak_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0017add_after_flush_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0017add_after_flush_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0018set_check_size_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0018set_check_size_1?h=v1.0.9) | pass | pass | pass |  |
| [sets/0019set_check_size_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0019set_check_size_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0020comments_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0020comments_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0021nesting_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0021nesting_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0022type_selective_flush_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0022type_selective_flush_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0023incomplete_add_set_command_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0023incomplete_add_set_command_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0024named_objects_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0024named_objects_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0025anonymous_set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0025anonymous_set_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0026named_limit_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0026named_limit_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0027ipv6_maps_ipv4_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0027ipv6_maps_ipv4_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0028autoselect_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0028autoselect_0?h=v1.0.9) | pass | dump differs | dump differs |  |
| [sets/0028delete_handle_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0028delete_handle_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0029named_ifname_dtype_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0029named_ifname_dtype_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0030add_many_elements_interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0030add_many_elements_interval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0031set_timeout_size_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0031set_timeout_size_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0032restore_set_simple_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0032restore_set_simple_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0033add_set_simple_flat_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0033add_set_simple_flat_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0034get_element_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0034get_element_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0035add_set_elements_flat_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0035add_set_elements_flat_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0036add_set_element_expiration_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0036add_set_element_expiration_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0037_set_with_inet_service_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0037_set_with_inet_service_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0038meter_list_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0038meter_list_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0039delete_interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0039delete_interval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0040get_host_endian_elements_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0040get_host_endian_elements_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0041interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0041interval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0042update_set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0042update_set_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0043concatenated_ranges_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0043concatenated_ranges_0?h=v1.0.9) | fail | fail | fail | /dev/stdin:14:26-39: Error: Could not process rule: Invalid argument |
| [sets/0043concatenated_ranges_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0043concatenated_ranges_1?h=v1.0.9) | pass | pass | pass |  |
| [sets/0044interval_overlap_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0044interval_overlap_0?h=v1.0.9) | pass | pass | hang |  |
| [sets/0044interval_overlap_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0044interval_overlap_1?h=v1.0.9) | pass | pass | hang |  |
| [sets/0045concat_ipv4_service](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0045concat_ipv4_service?h=v1.0.9) | pass | pass | pass |  |
| [sets/0046netmap_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0046netmap_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0047nat_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0047nat_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0048set_counters_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0048set_counters_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0049set_define_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0049set_define_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0050set_define_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0050set_define_1?h=v1.0.9) | pass | pass | pass |  |
| [sets/0051set_interval_counter_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0051set_interval_counter_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0052overlap_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0052overlap_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0053echo_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0053echo_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0054comments_set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0054comments_set_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0055tcpflags_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0055tcpflags_0?h=v1.0.9) | pass | dump differs | dump differs |  |
| [sets/0056dynamic_limit_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0056dynamic_limit_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0057set_create_fails_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0057set_create_fails_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0058_setupdate_timeout_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0058_setupdate_timeout_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0059set_update_multistmt_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0059set_update_multistmt_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0060set_multistmt_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0060set_multistmt_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0060set_multistmt_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0060set_multistmt_1?h=v1.0.9) | pass | pass | pass |  |
| [sets/0061anonymous_automerge_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0061anonymous_automerge_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0062set_connlimit_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0062set_connlimit_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0063set_catchall_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0063set_catchall_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0064map_catchall_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0064map_catchall_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0065_icmp_postprocessing](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0065_icmp_postprocessing?h=v1.0.9) | pass | pass | pass |  |
| [sets/0067nat_concat_interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0067nat_concat_interval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0068interval_stack_overflow_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0068interval_stack_overflow_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0069interval_merge_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0069interval_merge_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0070stacked_l2_headers](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0070stacked_l2_headers?h=v1.0.9) | pass | pass | pass |  |
| [sets/0071unclosed_prefix_interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0071unclosed_prefix_interval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0072destroy_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0072destroy_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/0073flat_interval_set](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0073flat_interval_set?h=v1.0.9) | pass | pass | pass |  |
| [sets/0074nested_interval_set](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/0074nested_interval_set?h=v1.0.9) | pass | pass | pass |  |
| [sets/automerge_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/automerge_0?h=v1.0.9) | pass | pass | hang |  |
| [sets/collapse_elem_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/collapse_elem_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/concat_interval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/concat_interval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/dynset_missing](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/dynset_missing?h=v1.0.9) | pass | dump differs | dump differs |  |
| [sets/errors_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/errors_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/exact_overlap_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/exact_overlap_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/inner_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/inner_0?h=v1.0.9) | pass | skip | skip |  |
| [sets/reset_command_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/reset_command_0?h=v1.0.9) | fail | skip | skip | counters and expiry are reset: FAIL |
| [sets/set_eval_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/set_eval_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/sets_with_ifnames](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/sets_with_ifnames?h=v1.0.9) | pass | fail | fail | Expected 3 matching rules, got 0, packets 9 in v4icmp |
| [sets/type_set_symbol](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/type_set_symbol?h=v1.0.9) | pass | pass | pass |  |
| [sets/typeof_raw_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/typeof_raw_0?h=v1.0.9) | pass | pass | pass |  |
| [sets/typeof_sets_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/typeof_sets_0?h=v1.0.9) | pass | fail | fail | }< |
| [sets/typeof_sets_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/typeof_sets_1?h=v1.0.9) | pass | pass | pass |  |
| [sets/typeof_sets_concat](https://git.netfilter.org/nftables/tree/tests/shell/testcases/sets/typeof_sets_concat?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0001table_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0001table_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0002table_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0002table_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0003table_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0003table_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0010chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0010chain_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0011chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0011chain_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0012chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0012chain_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0013chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0013chain_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0014chain_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0014chain_1?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0015chain_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0015chain_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0020rule_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0020rule_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0021rule_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0021rule_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0022rule_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0022rule_1?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0023rule_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0023rule_1?h=v1.0.9) | fail | pass | pass | E: allowing jump to chain loop |
| [transactions/0024rule_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0024rule_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0025rule_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0025rule_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0030set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0030set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0031set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0031set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0032set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0032set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0033set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0033set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0034set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0034set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0035set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0035set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0036set_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0036set_1?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0037set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0037set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0038set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0038set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0039set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0039set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0040set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0040set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0041nat_restore_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0041nat_restore_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0042_stateful_expr_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0042_stateful_expr_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0043set_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0043set_1?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0044rule_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0044rule_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0045anon-unbind_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0045anon-unbind_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0046set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0046set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0047set_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0047set_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0048helpers_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0048helpers_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0049huge_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0049huge_0?h=v1.0.9) | pass | dump differs | dump differs | internal:0:0-0: Error: Could not process rule: No such file or directory |
| [transactions/0050rule_1](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0050rule_1?h=v1.0.9) | pass | pass | pass |  |
| [transactions/0051map_0](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/0051map_0?h=v1.0.9) | pass | pass | pass |  |
| [transactions/30s-stress](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/30s-stress?h=v1.0.9) | pass | pass | pass |  |
| [transactions/anon_chain_loop](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/anon_chain_loop?h=v1.0.9) | fail | pass | pass | E: able to load bad ruleset |
| [transactions/bad_expression](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/bad_expression?h=v1.0.9) | pass | pass | pass |  |
| [transactions/table_onoff](https://git.netfilter.org/nftables/tree/tests/shell/testcases/transactions/table_onoff?h=v1.0.9) | pass | fail | fail | /dev/stdin:4:1-15: Error: Could not process rule: Invalid argument |
