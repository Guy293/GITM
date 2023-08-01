cmake_minimum_required(VERSION 3.16)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

project("MITMProxy")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    if(MSVC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /DEBUG:FULL")
    endif()
endif()


# set(CMAKE_CXX_CLANG_TIDY clang-tidy; -header-filter=.; -checks=*;)

# set(CMAKE_CXX_CLANG_TIDY "clang-tidy;-checks=*")

# set(CMAKE_AUTOMOC ON) set(CMAKE_AUTORCC ON) set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARIES})

set(Boost_NO_WARN_NEW_VERSIONS ON)

if(WIN32)
    set(Boost_USE_STATIC_LIBS TRUE)
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -DBOOST_USE_WINAPI_VERSION=0x0601"
    )
    find_package(Boost 1.71.0 REQUIRED COMPONENTS zlib iostreams log log_setup)
else()
    find_package(Boost 1.71.0 REQUIRED COMPONENTS iostreams log log_setup)
endif()

include_directories(${Boost_INCLUDE_DIRS})

find_package(Brotli REQUIRED)
include_directories(${BROTLI_INCLUDE_DIR})
link_directories(${BROTLI_LIBRARIES})

# Set the Windows header version
if(WIN32)
    macro(get_win32_winnt version)
        if(CMAKE_SYSTEM_VERSION)
            set(ver ${CMAKE_SYSTEM_VERSION})
            string(REGEX MATCH "^([0-9]+).([0-9])" ver ${ver})
            string(REGEX MATCH "^([0-9]+)" verMajor ${ver})
            # Check for Windows 10, b/c we'll need to convert to hex 'A'.
            if("${verMajor}" MATCHES "10")
                set(verMajor "A")
                string(REGEX REPLACE "^([0-9]+)" ${verMajor} ver ${ver})
            endif()
            # Remove all remaining '.' characters.
            string(REPLACE "." "" ver ${ver})
            # Prepend each digit with a  zero.
            string(REGEX REPLACE "([0-9A-Z])" "0\\1" ver ${ver})
            set(${version} "0x${ver}")
        endif()
    endmacro()

    get_win32_winnt(ver)
    add_definitions(-D_WIN32_WINNT=${ver})
endif()

add_executable(
  MITMProxy
  "src/helper.h"
  "src/logger.cpp"
  "src/main.cpp"
  "src/http_parser.cpp"
  "src/cert.cpp"
  "src/server.cpp"
  "src/http_request_parser.cpp"
  "src/http_response_parser.cpp"
  "src/mainwindow.cpp"
  "src/mainwindow.h"
  "src/mainwindow.ui"
  "src/session.cpp"
  "src/http_highlighter.cpp"
  "src/pending_sessions_list_model.cpp")
        MITMProxy
        "src/helper.h"
        "src/logger.cpp"
        "src/main.cpp"
        "src/http_parser/http_parser.cpp"
        "src/cert.cpp"
        "src/server.cpp"
        "src/http_parser/http_request_parser.cpp"
        "src/http_parser/http_response_parser.cpp"
        "src/mainwindow.cpp"
        "src/mainwindow.h"
        "src/mainwindow.ui"
        "src/session.cpp"
        "src/http_highlighter.cpp"
        "src/pending_sessions_list_model.cpp"

target_link_libraries(MITMProxy Qt6::Core Qt6::Gui Qt6::Widgets)
target_link_libraries(MITMProxy ${Boost_LIBRARIES})
target_link_libraries(MITMProxy OpenSSL::SSL)
target_link_libraries(MITMProxy ${BROTLI_LIBRARY_COMMON} ${BROTLI_LIBRARY_ENC}
                      ${BROTLI_LIBRARY_DEC})

if(WIN32)
    set(DEBUG_SUFFIX)
    if(MSVC AND CMAKE_BUILD_TYPE MATCHES "Debug")
        set(DEBUG_SUFFIX "d")
    endif()
    set(QT_INSTALL_PATH "${CMAKE_PREFIX_PATH}")
    if(NOT EXISTS "${QT_INSTALL_PATH}/bin")
        set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        if(NOT EXISTS "${QT_INSTALL_PATH}/bin")
            set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        endif()
    endif()
    if(EXISTS "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll")
        add_custom_command(
                TARGET ${PROJECT_NAME}
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
        add_custom_command(
                TARGET ${PROJECT_NAME}
                POST_BUILD
                COMMAND
                ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
    endif()
    foreach(QT_LIB Core Gui Widgets)
        add_custom_command(
                TARGET ${PROJECT_NAME}
                POST_BUILD
                COMMAND
                ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/bin/Qt6${QT_LIB}${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
    endforeach(QT_LIB)
endif()
