#
# Copyright 2026 NervesHub contributors
#
# SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later
#

set(ATOMVM_WEBSOCKET_CLIENT_COMPONENT_SRCS
    "ports/atomvm_websocket_client.c"
)

# WHOLE_ARCHIVE keeps the port driver's registration record from being dropped
# by the linker: nothing in the VM references it by name.
if(IDF_VERSION_MAJOR GREATER_EQUAL 5)
    set(OPTIONAL_WHOLE_ARCHIVE WHOLE_ARCHIVE)
else()
    set(OPTIONAL_WHOLE_ARCHIVE "")
endif()

idf_component_register(
    SRCS ${ATOMVM_WEBSOCKET_CLIENT_COMPONENT_SRCS}
    PRIV_REQUIRES "libatomvm" "avm_sys" "esp_websocket_client" "esp-tls" "esp_event"
    ${OPTIONAL_WHOLE_ARCHIVE}
)

if(IDF_VERSION_MAJOR EQUAL 4)
    idf_build_set_property(
        LINK_OPTIONS "-Wl,--whole-archive ${CMAKE_CURRENT_BINARY_DIR}/lib${COMPONENT_NAME}.a -Wl,--no-whole-archive"
        APPEND
    )
endif()
