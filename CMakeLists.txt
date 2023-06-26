cmake_minimum_required(VERSION 3.0.0)
project(DNS-relay VERSION 0.1.0 LANGUAGES C)

include(CTest)
enable_testing()

add_executable(DNS-relay
    main.c
    protocol.c
    database.c
    dns.c
    lookup.c
    logger.c
    pool.c
    cache.c
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3  -Wall -Werror")

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/dnsrelay.txt
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

if(CMAKE_HOST_SYSTEM_NAME MATCHES "Windows")

target_link_libraries(DNS-relay
  ws2_32
)

endif()

