# C Tests CMakeLists.txt

# Helper macro for adding tests
# Links against ama_cryptography_test (has AMA_TESTING_MODE) instead of
# the production shared/static libraries.
macro(add_ava_test test_name test_source)
    add_executable(${test_name} ${test_source})
    target_link_libraries(${test_name} ama_cryptography_test)
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

# Core tests
add_ava_test(test_consttime test_consttime.c)
add_ava_test(test_core test_core.c)

# Cryptographic primitive tests
add_ava_test(test_sha3 test_sha3.c)
add_ava_test(test_hkdf test_hkdf.c)
add_ava_test(test_ed25519 test_ed25519.c)

# PQC Known Answer Tests (KAT)
if(AMA_USE_NATIVE_PQC)
    add_executable(test_kat test_kat.c)
    target_link_libraries(test_kat ama_cryptography_test OpenSSL::Crypto)
    add_test(NAME test_kat COMMAND test_kat
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

# Performance benchmark (not added to ctest - run manually)
add_executable(test_benchmark test_benchmark.c)
target_link_libraries(test_benchmark ama_cryptography_test)
