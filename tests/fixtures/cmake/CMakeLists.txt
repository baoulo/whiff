# Harbour tools build
cmake_minimum_required(VERSION 3.25)
project(harbour VERSION 2.3.0 LANGUAGES C CXX)

find_package(Threads REQUIRED)
include(GNUInstallDirs)

add_library(tides STATIC src/tides.c)
add_executable(harbour src/main.cpp)
target_link_libraries(harbour PRIVATE tides Threads::Threads)

function(harbour_option name)
  option(${name} "Harbour option" OFF)
endfunction()
