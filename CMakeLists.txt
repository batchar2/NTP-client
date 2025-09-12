cmake_minimum_required(VERSION 3.0.0)
project(ntp_client)

set(CMAKE_CXX_STANDARD 14)

file(GLOB_RECURSE SOURCES src/*.cpp include/*.h*)
include_directories(include)

add_library(${PROJECT_NAME} STATIC ${SOURCES})

add_definitions(-DNDEBUG -DO3)

if(IOS)
    set(CMAKE_OSX_DEPLOYMENT_TARGET 17.0)
    set(CMAKE_XCODE_ATTRIBUTE_ENABLE_BITCODE NO)

    target_link_libraries(${PROJECT_NAME} PRIVATE "-framework Foundation"
            "-framework Network")
else()

    add_executable(ntp_example main.cpp)
    target_link_libraries(ntp_example ${PROJECT_NAME})

    if(WIN32)
        target_link_libraries(${PROJECT_NAME} ws2_32)
    endif()
    # Instalation
    install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION bin)
endif()

install(
        DIRECTORY "include/"
        DESTINATION "include"
        FILES_MATCHING
        PATTERN "*.h"
        PATTERN "*.hpp")
