cmake_minimum_required(VERSION 3.20.0)
project(of_core_fs_android VERSION 1.0.1 DESCRIPTION "OpenFiles File Handler for Android")

include_directories(
        ${of_core_BINARY_DIR}
        ${of_core_SOURCE_DIR}/include
        include
)

set(SRCS
        src/fs_android.c
        src/fs_match.c
        )

add_library(of_core_fs_android OBJECT ${SRCS})
set_property(TARGET of_core_fs_android PROPERTY POSITION_INDEPENDENT_CODE ON)

