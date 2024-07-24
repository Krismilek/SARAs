cmake_minimum_required(VERSION 3.9)

project(extension)

set(TEE_TYPE "" CACHE STRING "Type of TEE (CVM, TZ, SGX, etc)")
# set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
# set(CMAKE_C_COMPILER "/usr/bin/clang")
set(CMAKE_CXX_STANDARD 14)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(PostgreSQL)
if(PostgreSQL_FOUND)
set(_link_flags "${PostgreSQL_SHARED_LINK_OPTIONS}")
foreach(_dir ${PostgreSQL_SERVER_LIBRARY_DIRS})
    set(_link_flags "${_link_flags} -L${_dir}")
endforeach()
endif()

file(GLOB DES_SRCS
    # privacy_zone/plain_ops/*.c
    privacy_zone/desenitizer.cpp
    privacy_zone/crypto.cpp
)
add_executable(desenitizer ${DES_SRCS})
target_include_directories(desenitizer
        PRIVATE privacy_zone/include
        PRIVATE privacy_zone
        PRIVATE include
        )
target_link_libraries(desenitizer mbedcrypto pthread)


find_package(PkgConfig REQUIRED)
# 使用pkg-config找到gtkmm和glibmm
pkg_check_modules(GTKMM REQUIRED gtkmm-3.0)

# 打印GTKMM_INCLUDE_DIRS和GTKMM_LIBRARIES以调试
message(STATUS "GTKMM_INCLUDE_DIRS: ${GTKMM_INCLUDE_DIRS}")
message(STATUS "GTKMM_LIBRARIES: ${GTKMM_LIBRARIES}")

# 递归地将所有源文件添加到DEBUG_SRCS变量中
file(GLOB_RECURSE DEBUG_SRCS
    #"integrity_zone/SARAs_cmd.cpp"
    "integrity_zone/ops_client/enc_int_ops.cpp"
    "integrity_zone/interface/*.cpp"
    "integrity_zone/record_replay/*.cpp"
    "utils/sync.cpp"
    "integrity_zone/SARAs_UI.cpp"
)

# 添加可执行文件目标    
add_executable(attackui ${DEBUG_SRCS})


# 指定头文件的搜索目录 
target_include_directories(attackui
        PRIVATE /usr/include/postgresql/14/server
        PRIVATE integrity_zone/include
        PRIVATE privacy_zone/include
        PRIVATE ./include
        PRIVATE /usr/lib/postgresql/14/lib
        PRIVATE /usr/include/gtkmm-3.0
        PRIVATE /usr/lib/x86_64-linux-gnu/glibmm-2.4/include/  
        PRIVATE /usr/include/glibmm-2.4/
        PRIVATE /usr/include/glib-2.0/
        PRIVATE /usr/lib/x86_64-linux-gnu/glib-2.0/include/
        PRIVATE /usr/include/sigc++-2.0/sigc++/
        PRIVATE ${GTKMM_INCLUDE_DIRS}
)

#link_directories(/usr/lib/postgresql/14/lib)
target_link_libraries(attackui
    mbedcrypto
    pthread
    crypto
    /usr/lib/x86_64-linux-gnu/libpq.so
    /usr/lib/postgresql/14/lib/libpgcommon.a
    /usr/lib/postgresql/14/lib/libpgport.a
    ${GTKMM_LIBRARIES} 
)


if ( ${TEE_TYPE} STREQUAL "CVM" )
    add_compile_definitions(TEE_CVM)
    file(GLOB SRCS
        privacy_zone/crypto.cpp
        privacy_zone/ops_server.cpp
        privacy_zone/handle_ops.cpp
        privacy_zone/enc_ops/*.cpp
        privacy_zone/plain_ops/*.c
        utils/*.cpp
    )
    add_executable(ops_server ${SRCS})
    target_include_directories(ops_server
        PRIVATE integrity_zone/include
        PRIVATE privacy_zone/include
        PRIVATE privacy_zone
        PRIVATE include
        )
    # link_directories(privacy_zone/)
    #target_link_libraries(ops_server mbedcrypto pthread)
    target_link_libraries(ops_server mbedcrypto pthread crypto)
    # install
    # SET(INSTALL_DIR "/usr/local/lib/hedb")
    # install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/ops DESTINATION ${INSTALL_DIR})
    # install(CODE "execute_process(COMMAND chown postgres:postgres ${INSTALL_DIR}/ops )")

    if(PostgreSQL_FOUND)
    file(GLOB USRCS
        utils/sync.cpp
        utils/base64.cpp
        integrity_zone/interface/cvm_interface.cpp
        )
    add_library(CVMInterface ${USRCS})

    target_include_directories(CVMInterface
        PRIVATE integrity_zone/include
        PRIVATE integrity_zone/interface
        PRIVATE include
        )

    target_include_directories(CVMInterface
        PRIVATE ${PostgreSQL_INCLUDE_DIRS}
        PRIVATE ${PostgreSQL_SERVER_INCLUDE_DIRS}
    )
    endif()

else()
    message(FATAL_ERROR "TEE_TYPE ${TEE_TYPE} not specified (SGX/TZ). CMake will exit.")
endif()

## for extension
if(PostgreSQL_FOUND)
add_subdirectory(integrity_zone)
endif()

OPTION(ENABLE_PARALLEL "parallel enc/dec in UDF" OFF) # disabled by default
IF(ENABLE_PARALLEL)
    add_compile_definitions(ENABLE_PARA)
ENDIF(ENABLE_PARALLEL)

