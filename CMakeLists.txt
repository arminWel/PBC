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

set(CMAKE_SOURCE_DIR src)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# set(CMAKE_PREFIX_PATH /opt/homebrew/Cellar/botan/3.7.1/)
find_package(catch2 REQUIRED)
find_package(botan REQUIRED)
find_package(nlohmann_json REQUIRED)



add_executable(
  main
  ${CMAKE_SOURCE_DIR}/main.cpp
)

add_library(
  server
  ${CMAKE_SOURCE_DIR}/server.cpp
)

add_executable(
  server_test
  ${CMAKE_SOURCE_DIR}/server_test.cpp
)
# target_include_directories(main PUBLIC /opt/homebrew/Cellar/botan)
# link_directories(/opt/homebrew/Cellar/botan/3.7.1/)
target_link_libraries(server PRIVATE Botan::Botan-static
  nlohmann_json::nlohmann_json)
target_link_libraries( main PRIVATE Botan::Botan-static
  Catch2::Catch2WithMain)
target_link_libraries(server_test
  PRIVATE server
  Botan::Botan-static
  Catch2::Catch2WithMain
  nlohmann_json::nlohmann_json)


enable_testing()
add_test(NAME server_test
  COMMAND
  $<TARGET_FILE:server_test>)
