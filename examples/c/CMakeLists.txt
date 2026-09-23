# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# C Examples CMakeLists.txt
#
# Every example links the library a user would (shared when built, static
# otherwise) and, when tests are enabled, runs as a CTest case: each returns
# non-zero when a call it demonstrates fails, so an example that stops working
# fails the suite.  They used to be built and never run.

set(AMA_EXAMPLE_TARGETS "")

function(ama_add_example name)
    add_executable(${name} ${name}.c)
    if(AMA_BUILD_SHARED)
        target_link_libraries(${name} ama_cryptography_shared)
    else()
        target_link_libraries(${name} ama_cryptography_static)
    endif()
    if(AMA_BUILD_TESTS)
        string(REGEX REPLACE "^example_" "" short ${name})
        add_test(NAME example_${short} COMMAND ${name})
    endif()
    set(AMA_EXAMPLE_TARGETS ${AMA_EXAMPLE_TARGETS} ${name} PARENT_SCOPE)
endfunction()

ama_add_example(simple_example)
ama_add_example(pqc_demo)
ama_add_example(example_encrypt_decrypt)
ama_add_example(example_hash)

# ama_dilithium_* and ama_kyber_* live in the AMA_USE_NATIVE_PQC source group.
if(AMA_USE_NATIVE_PQC)
    ama_add_example(example_sign_verify)
    ama_add_example(example_kem)
endif()

install(TARGETS ${AMA_EXAMPLE_TARGETS}
    RUNTIME DESTINATION bin/examples
)
