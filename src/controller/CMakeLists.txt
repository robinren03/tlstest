set(HEADERS
        ${HEADERS}
        ${CMAKE_CURRENT_SOURCE_DIR}/beast.h
        ${CMAKE_CURRENT_SOURCE_DIR}/controller.h
        ${CMAKE_CURRENT_SOURCE_DIR}/poodle.h
        PARENT_SCOPE
        )

set(SOURCE
        ${SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/beast.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/poodle.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/controller.cpp
        PARENT_SCOPE
        )