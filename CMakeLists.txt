cmake_minimum_required(VERSION 3.3)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
project(libconvert C)

option(BUILD_TESTS "" OFF)
option(BUILD_EXAMPLES "" OFF)
add_subdirectory(lib/syscall_intercept)
add_subdirectory(lib/picotcpls)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra")

include_directories(lib)
include_directories(lib/syscall_intercept/include)
include_directories(lib/log.c/src)
include_directories(lib/picotcpls/include)

# libconvert_util
add_library(convert_util SHARED convert_util.c)

# libconvert_client
add_library(convert_client SHARED convert_client.c lib/log.c/src/log.c)
target_link_libraries(convert_client PRIVATE syscall_intercept_static convert_util)

# libconvert_tcpls_client
add_library(convert_tcpls_client SHARED convert_tcpls_client.c lib/log.c/src/log.c)
target_link_libraries(convert_tcpls_client PRIVATE syscall_intercept_static convert_util)

# libconvert_tcpls_server
add_library(convert_tcpls_server SHARED convert_tcpls_server.c lib/log.c/src/log.c)
target_link_libraries(convert_tcpls_server PRIVATE syscall_intercept_static convert_util)

# Unit & integration tests
add_subdirectory(tests)

# Tests for code linting & formatting
enable_testing()

list(APPEND LIBCONVERT_SOURCES convert_client.c convert_tcpls_client.c  convert_tcpls_server.c convert_tcpls.c convert.h convert_util.c convert_util.h)

add_test(NAME uncrustify
         COMMAND uncrustify -c uncrustify.cfg --check -l C ${LIBCONVERT_SOURCES}
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

add_test(NAME cppcheck
         COMMAND cppcheck -I/usr/include -q
                          --language=c --std=c99 --error-exitcode=1
                          --enable=warning,style,performance,portability
                          --suppress=unusedStructMember ${LIBCONVERT_SOURCES}
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

add_test(NAME scan-build
         COMMAND bash -c "rm -rf scan-build && \
                          mkdir scan-build && \
                          cd scan-build && \
                          scan-build-6.0 cmake ${PROJECT_SOURCE_DIR} && \
                          scan-build-6.0 -v --status-bugs make")
