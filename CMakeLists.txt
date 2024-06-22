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

set(EXEC cadical)
add_executable(${EXEC} ${SRC})
target_include_directories(${EXEC} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(${EXEC} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/build)
