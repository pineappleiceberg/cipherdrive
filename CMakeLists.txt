cmake_minimum_required(VERSION 3.15)
project(nbd_aead_logfile C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)   # -fpic cmdline equivalent
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)           
endif()
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
pkg_check_modules(NBDKIT    REQUIRED nbdkit)

#use the new filter code
add_library(nbd_aead_logfile SHARED
    ${CMAKE_SOURCE_DIR}/chapoly_nbd.c
)

target_include_directories(nbd_aead_logfile PRIVATE
    ${LIBSODIUM_INCLUDE_DIRS}
    ${NBDKIT_INCLUDE_DIRS}
)

target_compile_options(nbd_aead_logfile PRIVATE
    ${LIBSODIUM_CFLAGS_OTHER}
    ${NBDKIT_CFLAGS_OTHER}
)

target_link_libraries(nbd_aead_logfile PRIVATE
    ${LIBSODIUM_LIBRARIES}
    ${NBDKIT_LIBRARIES}
)

set_target_properties(nbd_aead_logfile PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "nbd_aead_logfile"
    SUFFIX ".so"
)

install(TARGETS nbd_aead_logfile
        LIBRARY DESTINATION lib)      # this should go to /usr/local/lib i think
