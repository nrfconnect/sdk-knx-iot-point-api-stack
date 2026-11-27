# The stack built WITHOUT OC_PUBLISHER_TABLE (plain sender), as with OC_PUBLISHER_TABLE_ENABLED=OFF or
# CONFIG_KNXIOT_PUBLISHER_TABLE=n. kis-common leaves OC_PUBLISHER_TABLE out for targets with the property
# KIS_NO_PUBLISHER_TABLE. The test files that depend on the switch run here a second time, their
# publisher tests left out and the plain-sender ones in:
# - test_oc_knx_fp.cpp: the tables, their resources and the group multicast joins
# - test_oc_core_res.cpp: the core resource registry without /fp/p and /fp/p/*
# Nothing here is part of the default build: the CTests below build and run it.
kis_add_stack_variant(kis-publisher-off PublisherOff StackBuildsAndLinksWithoutPublisherTable SUFFIX _publisher_off
                      SOURCES test_oc_knx_fp.cpp test_oc_core_res.cpp)
set_target_properties(kis-publisher-off ${KIS_VARIANT_TESTS} PROPERTIES KIS_NO_PUBLISHER_TABLE ON)
target_link_options(test_oc_knx_fp_publisher_off PRIVATE -Wl,--wrap=oc_connectivity_subscribe_mcast_ipv6)
# oc_rep macros use g_err |= cbor_encode_*(), an invalid enum-to-int conversion in strict C++
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_oc_knx_fp_publisher_off PRIVATE -fpermissive)
endif()