# The stack built WITHOUT OC_CLIENT, as on Zephyr and ESP-IDF with CONFIG_KNXIOT_CLIENT=n. The host build
# defines OC_CLIENT for the whole tree; this directory drops it for its own targets. Nothing here is part
# of the default build: the CTests below build and run it.
get_directory_property(client_off_definitions COMPILE_DEFINITIONS)
list(REMOVE_ITEM client_off_definitions OC_CLIENT)
set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "${client_off_definitions}")

kis_add_stack_variant(kis-client-off ClientOff StackBuildsAndLinksWithoutOcClient SOURCES test_oc_knx_client_off.cpp)