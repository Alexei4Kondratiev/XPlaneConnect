cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(xplane-connect-cpp LANGUAGES CXX VERSION 1.0.0)

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# version parameters
message(STATUS)
message(STATUS "Project name: ${PROJECT_NAME}")
message(STATUS "Project version: ${PROJECT_VERSION}")
message(STATUS)

# add source
file(GLOB SOURCES "./src/*.cpp")

add_library(${PROJECT_NAME}_object OBJECT ${SOURCES})

set_target_properties(${PROJECT_NAME}_object
        PROPERTIES POSITION_INDEPENDENT_CODE 1)

add_library(
        ${PROJECT_NAME}_shared SHARED $<TARGET_OBJECTS:${PROJECT_NAME}_object>)

set_target_properties(${PROJECT_NAME}_shared PROPERTIES OUTPUT_NAME
        ${PROJECT_NAME})

add_library(${PROJECT_NAME}_static STATIC
        $<TARGET_OBJECTS:${PROJECT_NAME}_object>)

set_target_properties(${PROJECT_NAME}_static PROPERTIES OUTPUT_NAME
        ${PROJECT_NAME})

target_include_directories(
        ${PROJECT_NAME}_object
        PRIVATE src
        PUBLIC $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

#target_compile_options(${PROJECT_NAME}_shared PRIVATE -Wall -Wextra -Wpedantic -Werror)

#target_compile_options(${PROJECT_NAME}_static PRIVATE -Wall -Wextra -Wpedantic -Werror)

# add public header files
file(GLOB PUBLIC_HEADERS
        ${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_NAME}/*.h)

# Linux default install path is /usr/local/
install(FILES ${PUBLIC_HEADERS}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/${PROJECT_NAME})

install(TARGETS ${PROJECT_NAME}_shared ${PROJECT_NAME}_static
        EXPORT ${PROJECT_NAME}_export
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/)

install(EXPORT ${PROJECT_NAME}_export
        FILE ${PROJECT_NAME}-config.cmake
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${PROJECT_NAME})
