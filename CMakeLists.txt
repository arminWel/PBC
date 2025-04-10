cmake_minimum_required(VERSION 3.31)
project(pbc)

set(PROJECT_VERSION "0.1.0-dev")
message(STATUS "${PROJECT_NAME} version: ${PROJECT_VERSION}")

set(PROJECT_SOURCE_DIR src)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(botan REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(GTest CONFIG REQUIRED)

add_executable(server_test ${PROJECT_SOURCE_DIR}/server_test.cpp)
add_executable(client_test ${PROJECT_SOURCE_DIR}/client_test.cpp)

add_library(server ${PROJECT_SOURCE_DIR}/server.cpp)
add_library(common STATIC ${PROJECT_SOURCE_DIR}/common.cpp)
add_library(client ${PROJECT_SOURCE_DIR}/client.cpp)

set(COMMON_LIBS Botan::Botan-static nlohmann_json::nlohmann_json common)
set(TESTS_LIBS GTest::gtest)

target_link_libraries(common PRIVATE Botan::Botan-static)
target_link_libraries(server PRIVATE ${COMMON_LIBS})
target_link_libraries(client PRIVATE ${COMMON_LIBS})
target_link_libraries(server_test PRIVATE server ${COMMON_LIBS} ${TESTS_LIBS})
target_link_libraries(client_test PRIVATE client ${COMMON_LIBS} ${TESTS_LIBS})

enable_testing()
include(GoogleTest)
gtest_discover_tests(client_test)
gtest_discover_tests(server_test)
