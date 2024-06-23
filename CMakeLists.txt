cmake_minimum_required(VERSION 3.1...3.27)

project(cadical)

file(GLOB_RECURSE SRC "src/*.cpp")
list(REMOVE_ITEM SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/mobical.cpp)

if (BUILD_TYPE STREQUAL "debug")
    message("Debug build")
    set(CMAKE_CXX_FLAGS "-Wall -Wextra -O3 -g")
else()
    message("Production build")
    set(CMAKE_CXX_FLAGS "-Wall -Wextra -O3 -DNDEBUG")
endif()

# Write the build.hpp file
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/build/build.hpp
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/build
    COMMAND ../scripts/make-build-header.sh > build.hpp
    COMMAND echo '\#define COMPILER \"${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}\"' >> build.hpp
    COMMAND echo '\#define FLAGS \"${CMAKE_CXX_FLAGS}\"' >> build.hpp
)

set(EXEC cadical)
add_executable(${EXEC} ${SRC} ${CMAKE_SOURCE_DIR}/build/build.hpp)
target_include_directories(${EXEC} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(${EXEC} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/build)
