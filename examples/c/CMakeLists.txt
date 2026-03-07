# C Examples CMakeLists.txt

# Simple example demonstrating basic usage
add_executable(simple_example simple_example.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(simple_example ama_cryptography_shared)
else()
    target_link_libraries(simple_example ama_cryptography_static)
endif()

# PQC demo demonstrating ML-DSA-65 and Kyber-1024
# Requires native PQC: cmake -DAMA_USE_NATIVE_PQC=ON ..
add_executable(pqc_demo pqc_demo.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(pqc_demo ama_cryptography_shared)
else()
    target_link_libraries(pqc_demo ama_cryptography_static)
endif()

# Install examples
install(TARGETS simple_example pqc_demo
    RUNTIME DESTINATION bin/examples
)
