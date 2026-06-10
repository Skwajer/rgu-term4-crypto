cmake_minimum_required(VERSION 3.10)
project(RC4_Encryption_System VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Threads REQUIRED)

if(UNIX AND NOT APPLE)
    set(RT_LIBRARY rt)
else()
    set(RT_LIBRARY "")
endif()

add_executable(rc4_app main.cpp)
target_link_libraries(rc4_app PRIVATE Threads::Threads)
if(RT_LIBRARY)
    target_link_libraries(rc4_app PRIVATE ${RT_LIBRARY})
endif()