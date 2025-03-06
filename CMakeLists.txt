cmake_minimum_required(VERSION 3.16)
project(pbc)

if(NOT CMAKE_BUILD_TYPE)
  set(default_build_type "Debug")
  message(STATUS "Set the build type to `${default_build_type}` as none was specified.")
  set(CMAKE_BUILD_TYPE ${default_build_type} CACHE STRING "Chooce the build type." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
  "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "pbc Build Type: ${CMAKE_BUILD_TYPE}")

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

set(CMAKE_PREFIX_PATH /opt/homebrew/Cellar/botan/3.7.1/)
find_package(catch2 REQUIRED)
find_package(Botan REQUIRED)
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
target_link_libraries(server PRIVATE Botan::Botan
  nlohmann_json::nlohmann_json)
target_link_libraries( main PRIVATE Botan::Botan
  Catch2::Catch2WithMain)
target_link_libraries(server_test
  PRIVATE server
  Botan::Botan
  Catch2::Catch2WithMain)


enable_testing()
add_test(NAME server_test
  COMMAND
  $<TARGET_FILE:server_test>)
