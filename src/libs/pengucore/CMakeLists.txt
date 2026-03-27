add_library(pengucore STATIC
    include/pengucore/api/pengucoreengine.h
    include/pengucore/api/pengucoresessionreportservice.h
    include/pengucore/model/packettypes.h
    include/pengucore/capture/livecaptureengine.h
    include/pengucore/capture/pcapfilereader.h
    include/pengucore/capture/pcapfilewriter.h
    include/pengucore/parser/basicframeparser.h
    include/pengucore/flow/flowtracker.h
    src/api/pengucoreengine.cpp
    src/api/pengucoresessionreportservice.cpp
    src/capture/livecaptureengine.cpp
    src/capture/pcapfilereader.cpp
    src/capture/pcapfilewriter.cpp
    src/parser/basicframeparser.cpp
    src/flow/flowtracker.cpp
)

set_target_properties(pengucore PROPERTIES
    AUTOMOC ON
)

add_library(pengufoce::pengucore ALIAS pengucore)

target_include_directories(pengucore
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(pengucore
    PUBLIC
        Qt6::Core
)

if(WIN32 AND NPCAP_INCLUDE_DIR AND NPCAP_WPCAP_LIBRARY AND NPCAP_PACKET_LIBRARY)
    target_include_directories(pengucore PRIVATE ${NPCAP_INCLUDE_DIR})
    target_link_libraries(pengucore PRIVATE ${NPCAP_WPCAP_LIBRARY} ${NPCAP_PACKET_LIBRARY})
    target_compile_definitions(pengucore PUBLIC PENGUFOCE_WITH_NPCAP=1)
endif()
