# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# C Examples CMakeLists.txt
#
# Every example links the library a user would (shared when built, static
# otherwise) and, when tests are enabled, runs as a CTest case: each returns
# non-zero when a call it demonstrates fails, so an example that stops working
# fails the suite.  They used to be built and never run.

set(AMA_EXAMPLE_TARGETS "")

# Link whichever production library this configuration builds.  Choosing by
# AMA_BUILD_SHARED alone named ama_cryptography_static whenever shared was
# OFF, whether or not the static library existed, so with both OFF every
# example linked a bare -lama_cryptography_static the linker could not find.
# With neither production library there is nothing an example may link (the
# AMA_TESTING_MODE archive is not an API), so none are registered, and the
# configure says why instead of emitting link commands that cannot succeed.
if(TARGET ama_cryptography_shared)
    set(AMA_EXAMPLE_LIBRARY ama_cryptography_shared)
elseif(TARGET ama_cryptography_static)
    set(AMA_EXAMPLE_LIBRARY ama_cryptography_static)
else()
    message(STATUS
        "Examples: not built -- AMA_BUILD_SHARED and AMA_BUILD_STATIC are both "
        "OFF, so there is no production library for them to link")
    return()
endif()

function(ama_add_example name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} ${AMA_EXAMPLE_LIBRARY})
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
