cmake_minimum_required(VERSION 3.1...3.27)

project(cadical)

file(GLOB SRC
    "src/*.cpp"
)

list(REMOVE_ITEM SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/mobical.cpp)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -O3 -DNDEBUG")
# set(CMAKE_CXX_FLAGS "-Wall -Wextra -O3 -g")

set(EXEC cadical)
add_executable(${EXEC} ${SRC})
target_include_directories(${EXEC} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(${EXEC} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/build)
target_include_directories(${EXEC} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ntl/include)
target_link_directories(${EXEC} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_link_libraries(${EXEC} ntl gmp z)