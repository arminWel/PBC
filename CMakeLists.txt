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

add_executable(
  main
  ${PROJECT_SOURCE_DIR}/main.cpp
)

add_library(
  server
  ${PROJECT_SOURCE_DIR}/server.cpp
)

add_executable(
  server_test
  ${PROJECT_SOURCE_DIR}/server_test.cpp
)

set(COMMON_LIBS Botan::Botan-static nlohmann_json::nlohmann_json)

target_link_libraries(server PRIVATE ${COMMON_LIBS})
target_link_libraries(main PRIVATE ${COMMON_LIBS} Catch2::Catch2WithMain)
target_link_libraries(server_test PRIVATE server ${COMMON_LIBS} Catch2::Catch2WithMain)


enable_testing()
add_test(NAME server_test
  COMMAND
  $<TARGET_FILE:server_test>)

