# C Examples CMakeLists.txt

# Simple example demonstrating basic usage
add_executable(simple_example simple_example.c)
if(AVA_BUILD_SHARED)
    target_link_libraries(simple_example ava_guardian_shared)
else()
    target_link_libraries(simple_example ava_guardian_static)
endif()

# PQC demo demonstrating ML-DSA-65 and Kyber-1024
# Requires native PQC: cmake -DAVA_USE_NATIVE_PQC=ON ..
add_executable(pqc_demo pqc_demo.c)
if(AVA_BUILD_SHARED)
    target_link_libraries(pqc_demo ava_guardian_shared)
else()
    target_link_libraries(pqc_demo ava_guardian_static)
endif()

# Install examples
install(TARGETS simple_example pqc_demo
    RUNTIME DESTINATION bin/examples
)
