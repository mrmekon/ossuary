cmake_minimum_required(VERSION 3.12)
project(ffi C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto -O3")

add_executable (ffi ffi.c)
target_include_directories (ffi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../ffi)
target_link_libraries (ffi LINK_PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../target/release/libossuary.dylib)

#target_link_libraries (ffi LINK_PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../target/release/libossuary.a)
#find_library(SECURITY_FRAMEWORK Security)
#target_link_libraries(ffi LINK_PUBLIC ${SECURITY_FRAMEWORK})

add_executable (client client.c)
target_include_directories (client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../ffi)
target_link_libraries (client LINK_PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../target/release/libossuary.dylib)

add_executable (server server.c)
target_include_directories (server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../ffi)
target_link_libraries (server LINK_PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../target/release/libossuary.dylib)
