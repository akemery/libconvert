cmake_minimum_required(VERSION 3.3)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
project(libconvert C)

option(BUILD_TESTS "" OFF)
option(BUILD_EXAMPLES "" OFF)
add_subdirectory(lib/syscall_intercept)
add_subdirectory(lib/picotcpls)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3 -Wall -Werror -Wextra")

include_directories(lib)
include_directories(lib/syscall_intercept/include)
include_directories(lib/log.c/src)
include_directories(lib/picotcpls/include)

# libconvert_util
# add_library(convert_util SHARED convert_util.c)


# libconvert_tcpls
add_library(convert_tcpls SHARED convert_tcpls.c lib/log.c/src/log.c)
target_link_libraries(convert_tcpls PRIVATE picotls-core picotls-minicrypto picotls-openssl )

# libconvert_tcpls_client
add_library(convert_tcpls_client SHARED convert_tcpls_client.c lib/log.c/src/log.c)
target_link_libraries(convert_tcpls_client PRIVATE syscall_intercept_static  convert_tcpls)

# libconvert_tcpls_server
add_library(convert_tcpls_server SHARED convert_tcpls_server.c lib/log.c/src/log.c)
target_link_libraries(convert_tcpls_server PRIVATE syscall_intercept_static  convert_tcpls)

# Unit & integration tests
# add_subdirectory(tests)

# Tests for code linting & formatting
enable_testing()

add_test(NAME wget
         COMMAND bash -c "CONVERT_LOG=./wget_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so wget http://172.17.0.2"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME wget1M
         COMMAND bash -c "CONVERT_LOG=./wget1M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so wget http://172.17.0.2/1M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME wget5M
         COMMAND bash -c "CONVERT_LOG=./wget5M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so wget http://172.17.0.2/5M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME wget10M
         COMMAND bash -c "CONVERT_LOG=./wget10M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so wget http://172.17.0.2/10M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME curl
         COMMAND bash -c "CONVERT_LOG=./curl_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so curl http://172.17.0.2"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME curl1M
         COMMAND bash -c "CONVERT_LOG=./curl1M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so curl -o 1M http://172.17.0.2/1M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})


add_test(NAME curl5M
         COMMAND bash -c "CONVERT_LOG=./curl5M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so curl -o 5M http://172.17.0.2/5M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME curl10M
         COMMAND bash -c "CONVERT_LOG=./curl10M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so curl -o 10M http://172.17.0.2/10M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME ab
         COMMAND bash -c "CONVERT_LOG=./ab_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so /usr/local/apache2/bin/ab -n 100 -c 10 http://172.17.0.2/"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME ab1M
         COMMAND bash -c "CONVERT_LOG=./ab5M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so /usr/local/apache2/bin/ab -n 100 -c 10 http://172.17.0.2/1M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME ab5M
         COMMAND bash -c "CONVERT_LOG=./ab5M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so /usr/local/apache2/bin/ab -n 100 -c 10 http://172.17.0.2/5M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

add_test(NAME ab10M
         COMMAND bash -c "CONVERT_LOG=./ab5M_converter.log LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so /usr/local/apache2/bin/ab -n 100 -c 10 http://172.17.0.2/10M"
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR})

list(APPEND LIBCONVERT_SOURCES  convert_tcpls_client.c  convert_tcpls_server.c convert_tcpls.c convert_tcpls.h )
