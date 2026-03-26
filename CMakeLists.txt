cmake_minimum_required(VERSION 3.21)

project(PenguFoce VERSION 0.1.0 LANGUAGES CXX)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PENGUFOCE_WITH_HTML5_PARSER "Enable future HTML5 parser integration scaffold" ON)
option(PENGUFOCE_FETCHCONTENT_TLS_VERIFY "Enable TLS certificate verification for FetchContent downloads" ON)

include(FetchContent)
include(CTest)
enable_testing()

find_package(Qt6 6.5 REQUIRED COMPONENTS
    Core
    Gui
    Network
    Qml
    Quick
    Quick3D
    QuickWidgets
    Widgets
)
find_package(Boost CONFIG QUIET)
find_package(CURL QUIET)
find_path(GUMBO_INCLUDE_DIR gumbo.h)
find_library(GUMBO_LIBRARY NAMES gumbo)

if(WIN32)
    set(PENGUFOCE_NPCAP_ROOT "C:/Program Files/Npcap")
    find_path(NPCAP_INCLUDE_DIR pcap.h
        HINTS
            "${PENGUFOCE_NPCAP_ROOT}/Include"
    )
    find_library(NPCAP_WPCAP_LIBRARY NAMES wpcap
        HINTS
            "${PENGUFOCE_NPCAP_ROOT}/Lib/x64"
            "${PENGUFOCE_NPCAP_ROOT}/Lib"
    )
    find_library(NPCAP_PACKET_LIBRARY NAMES Packet
        HINTS
            "${PENGUFOCE_NPCAP_ROOT}/Lib/x64"
            "${PENGUFOCE_NPCAP_ROOT}/Lib"
    )
endif()

qt_standard_project_setup(REQUIRES 6.5)

if(WIN32)
    get_target_property(QT_QMAKE_EXECUTABLE Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(QT_BIN_DIR "${QT_QMAKE_EXECUTABLE}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE
        NAMES windeployqt windeployqt6
        HINTS "${QT_BIN_DIR}"
    )
endif()

# Internal libraries
add_subdirectory(src/libs/pengucore)

qt_add_executable(PenguFoce
    src/main.cpp
    src/controllers/app/appcontroller.cpp
    src/core/framework/moduleinterface.cpp
    src/core/framework/modulemanager.cpp
    src/core/framework/moduleregistry.cpp
    src/core/settings/settingsmanager.cpp
    src/controllers/app/sessionmanager.cpp
    src/core/logging/logger.cpp
    src/core/logging/logmodel.cpp
    src/core/theme/themeengine.cpp
    src/modules/portscanner/portscannermodule.cpp
    src/modules/proxy/proxymodule.cpp
    src/modules/recon/reconmodule.cpp
    src/modules/spider/spidermodule.cpp
    src/modules/pengucore/pengucoremodule.cpp
    src/modules/recon/engine/scanorchestrator.cpp
    src/modules/recon/engine/fastportscannermodule.cpp
    src/modules/recon/engine/dnsreconmodule.cpp
    src/modules/recon/engine/osintandleakmodule.cpp
    src/modules/recon/engine/pengufoce_masterscanner.cpp
    src/modules/recon/engine/vulnmatchermodule.cpp
    src/modules/spider/engine/cdpclient.cpp
    src/modules/spider/engine/htmlextractor.cpp
    src/modules/spider/engine/spidercore.cpp
    src/modules/spider/engine/spiderscope.cpp
    src/modules/spider/engine/spiderworkflow.cpp
    src/ui/layout/flowlayout.cpp
    src/ui/layout/workspacecontainers.cpp
    src/ui/shell/bladesidebar.cpp
    src/ui/shell/mainwindow.cpp
    src/ui/panels/controlcenter/settingslogwidget.cpp
    src/ui/views/portscanner/portscannerwidget.cpp
    src/ui/views/proxy/proxywidget.cpp
    src/ui/views/recon/reconwidget.cpp
    src/ui/shell/settingsdialog.cpp
    src/ui/views/spider/spiderwidget.cpp
    src/ui/views/pengucore/pengucorewidget.cpp
)

qt_add_resources(PenguFoce "pengufoce_ui_shell_qml"
    PREFIX "/"
    FILES
        src/ui/shell/qml/OrbitalSidebar3D.qml
)

set_source_files_properties(
    src/ui/shell/qml/OrbitalSidebar3D.qml
    PROPERTIES QT_RESOURCE_ALIAS "OrbitalSidebar3D.qml"
)

target_include_directories(PenguFoce PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(PenguFoce PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Network
    Qt6::Qml
    Qt6::Quick
    Qt6::Quick3D
    Qt6::QuickWidgets
    Qt6::Widgets
    pengufoce::pengucore
)

if(WIN32)
    target_link_libraries(PenguFoce PRIVATE mswsock)
endif()

if(CURL_FOUND)
    target_link_libraries(PenguFoce PRIVATE CURL::libcurl)
    target_compile_definitions(PenguFoce PRIVATE PENGUFOCE_WITH_LIBCURL=1)
endif()

set(PENGUFOCE_USE_FETCHED_BOOST OFF)

if(NOT Boost_FOUND)
    message(STATUS "System Boost bulunamadi, header-only Boost arsivi indirilecek")
    FetchContent_Declare(
        boost_headers
        URL https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        TLS_VERIFY ${PENGUFOCE_FETCHCONTENT_TLS_VERIFY}
    )
    FetchContent_MakeAvailable(boost_headers)
    if(EXISTS "${boost_headers_SOURCE_DIR}/boost/version.hpp")
        set(PENGUFOCE_USE_FETCHED_BOOST ON)
    endif()
endif()

if(Boost_FOUND OR PENGUFOCE_USE_FETCHED_BOOST)
    target_sources(PenguFoce PRIVATE
        src/modules/proxy/engine/localresearchcore.cpp
    )
    if(Boost_FOUND)
        target_include_directories(PenguFoce PRIVATE ${Boost_INCLUDE_DIRS})
        if(TARGET Boost::headers)
            target_link_libraries(PenguFoce PRIVATE Boost::headers)
        elseif(Boost_LIBRARIES)
            target_link_libraries(PenguFoce PRIVATE ${Boost_LIBRARIES})
        endif()
    else()
        target_include_directories(PenguFoce PRIVATE ${boost_headers_SOURCE_DIR})
        target_compile_definitions(PenguFoce PRIVATE
            BOOST_ERROR_CODE_HEADER_ONLY=1
            BOOST_SYSTEM_NO_LIB=1
            BOOST_ALL_NO_LIB=1
        )
    endif()
    target_compile_definitions(PenguFoce PRIVATE PENGUFOCE_WITH_BOOST_PROXY=1)
endif()

if(PENGUFOCE_WITH_HTML5_PARSER)
    target_compile_definitions(PenguFoce PRIVATE PENGUFOCE_WITH_HTML5_PARSER=1)
endif()

if(PENGUFOCE_WITH_HTML5_PARSER AND GUMBO_INCLUDE_DIR AND GUMBO_LIBRARY)
    target_include_directories(PenguFoce PRIVATE ${GUMBO_INCLUDE_DIR})
    target_link_libraries(PenguFoce PRIVATE ${GUMBO_LIBRARY})
    target_compile_definitions(PenguFoce PRIVATE PENGUFOCE_WITH_GUMBO=1)
endif()

set_target_properties(PenguFoce PROPERTIES
    MACOSX_BUNDLE TRUE
)

if(WIN32 AND WINDEPLOYQT_EXECUTABLE)
    add_custom_command(TARGET PenguFoce POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
            --dir "$<TARGET_FILE_DIR:PenguFoce>"
            --qmldir "${CMAKE_CURRENT_SOURCE_DIR}/src"
            --no-translations
            --no-system-d3d-compiler
            --no-opengl-sw
            "$<TARGET_FILE:PenguFoce>"
        COMMENT "Deploying Qt runtime dependencies with windeployqt"
        VERBATIM
    )
endif()

install(TARGETS PenguFoce
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)

add_executable(pengufoce_pengucore_tests
    tests/pengucore_tests.cpp
)

target_include_directories(pengufoce_pengucore_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(pengufoce_pengucore_tests PRIVATE
    Qt6::Core
    pengufoce::pengucore
)

target_compile_definitions(pengufoce_pengucore_tests PRIVATE
    PENGUFOCE_SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
)

add_test(
    NAME pengufoce_pengucore_tests
    COMMAND pengufoce_pengucore_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(pengufoce_spider_tests
    tests/spider_extractor_tests.cpp
    src/modules/spider/engine/htmlextractor.cpp
)

target_include_directories(pengufoce_spider_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(pengufoce_spider_tests PRIVATE
    Qt6::Core
)

if(PENGUFOCE_WITH_HTML5_PARSER)
    target_compile_definitions(pengufoce_spider_tests PRIVATE PENGUFOCE_WITH_HTML5_PARSER=1)
endif()

if(PENGUFOCE_WITH_HTML5_PARSER AND GUMBO_INCLUDE_DIR AND GUMBO_LIBRARY)
    target_include_directories(pengufoce_spider_tests PRIVATE ${GUMBO_INCLUDE_DIR})
    target_link_libraries(pengufoce_spider_tests PRIVATE ${GUMBO_LIBRARY})
    target_compile_definitions(pengufoce_spider_tests PRIVATE PENGUFOCE_WITH_GUMBO=1)
endif()

add_test(
    NAME pengufoce_spider_tests
    COMMAND pengufoce_spider_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(pengufoce_spider_workflow_tests
    tests/spider_workflow_tests.cpp
    src/modules/spider/engine/spiderscope.cpp
    src/modules/spider/engine/spiderworkflow.cpp
    src/modules/spider/engine/htmlextractor.cpp
)

target_include_directories(pengufoce_spider_workflow_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(pengufoce_spider_workflow_tests PRIVATE
    Qt6::Core
)

if(PENGUFOCE_WITH_HTML5_PARSER)
    target_compile_definitions(pengufoce_spider_workflow_tests PRIVATE PENGUFOCE_WITH_HTML5_PARSER=1)
endif()

if(PENGUFOCE_WITH_HTML5_PARSER AND GUMBO_INCLUDE_DIR AND GUMBO_LIBRARY)
    target_include_directories(pengufoce_spider_workflow_tests PRIVATE ${GUMBO_INCLUDE_DIR})
    target_link_libraries(pengufoce_spider_workflow_tests PRIVATE ${GUMBO_LIBRARY})
    target_compile_definitions(pengufoce_spider_workflow_tests PRIVATE PENGUFOCE_WITH_GUMBO=1)
endif()

add_test(
    NAME pengufoce_spider_workflow_tests
    COMMAND pengufoce_spider_workflow_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(pengufoce_spider_core_tests
    tests/spider_core_tests.cpp
    src/modules/spider/engine/cdpclient.cpp
    src/modules/spider/engine/spidercore.cpp
    src/modules/spider/engine/spiderscope.cpp
    src/modules/spider/engine/spiderworkflow.cpp
    src/modules/spider/engine/htmlextractor.cpp
)

target_include_directories(pengufoce_spider_core_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(pengufoce_spider_core_tests PRIVATE
    Qt6::Core
    Qt6::Network
)

if(PENGUFOCE_WITH_HTML5_PARSER)
    target_compile_definitions(pengufoce_spider_core_tests PRIVATE PENGUFOCE_WITH_HTML5_PARSER=1)
endif()

if(PENGUFOCE_WITH_HTML5_PARSER AND GUMBO_INCLUDE_DIR AND GUMBO_LIBRARY)
    target_include_directories(pengufoce_spider_core_tests PRIVATE ${GUMBO_INCLUDE_DIR})
    target_link_libraries(pengufoce_spider_core_tests PRIVATE ${GUMBO_LIBRARY})
    target_compile_definitions(pengufoce_spider_core_tests PRIVATE PENGUFOCE_WITH_GUMBO=1)
endif()

add_test(
    NAME pengufoce_spider_core_tests
    COMMAND pengufoce_spider_core_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
