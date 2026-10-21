#
# Copyright 2026 NervesHub contributors
#
# SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later
#

set(ATOMVM_WEBSOCKET_CLIENT_COMPONENT_SRCS
    "ports/atomvm_websocket_client.c"
)

# WHOLE_ARCHIVE keeps the port driver's registration record from being dropped
# by the linker: nothing in the VM references it by name. idf_component.yml
# requires ESP-IDF 5.2, so the keyword is always available.
idf_component_register(
    SRCS ${ATOMVM_WEBSOCKET_CLIENT_COMPONENT_SRCS}
    PRIV_REQUIRES "libatomvm" "avm_sys" "esp_websocket_client" "esp-tls" "esp_event"
    WHOLE_ARCHIVE
)
