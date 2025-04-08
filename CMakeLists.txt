cmake_minimum_required(VERSION 3.31)
project(pbc)

# Set the version for pbc
set(pbc_Version_Major 0)
set(pbc_Version_Minor 1)
set(pbc_Version_Patch 0)
set(pbc_Version_Status "-dev")
set(PROJECT_VERSION
  "${pbc_Version_Major}.${pbc_Version_Minor}.${pbc_Version_Patch}${pbc_Version_Status}"
)
message(STATUS "${PROJECT_NAME} version: ${PROJECT_VERSION}")

set(PROJECT_SOURCE_DIR src)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Catch2 REQUIRED)
find_package(botan REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(GTest CONFIG REQUIRED)

add_executable(
  main
  ${PROJECT_SOURCE_DIR}/main.cpp
)

add_library(
  server
  ${PROJECT_SOURCE_DIR}/server.cpp
)

add_library(
  common
  STATIC
  ${PROJECT_SOURCE_DIR}/common.cpp
)

add_library(
  client
  ${PROJECT_SOURCE_DIR}/client.cpp
)

add_executable(
  server_test
  ${PROJECT_SOURCE_DIR}/server_test.cpp
)
add_executable(
  client_test
  ${PROJECT_SOURCE_DIR}/client_test.cpp
)

set(COMMON_LIBS Botan::Botan-static nlohmann_json::nlohmann_json common)

target_link_libraries(common PRIVATE Botan::Botan-static)
target_link_libraries(server PRIVATE ${COMMON_LIBS})
target_link_libraries(client PRIVATE ${COMMON_LIBS})
target_link_libraries(main PRIVATE ${COMMON_LIBS} Catch2::Catch2WithMain)
target_link_libraries(server_test PRIVATE server ${COMMON_LIBS} Catch2::Catch2WithMain)
# target_link_libraries(client_test PRIVATE client ${COMMON_LIBS} Catch2::Catch2WithMain)
target_link_libraries(client_test PRIVATE client ${COMMON_LIBS} GTest::gtest_main)

enable_testing()


include(GoogleTest)
gtest_discover_tests(client_test)
add_test(NAME server_test
  COMMAND
  $<TARGET_FILE:server_test>)

# add_test(NAME client_test
#   COMMAND
#   $<TARGET_FILE:client_test>)
