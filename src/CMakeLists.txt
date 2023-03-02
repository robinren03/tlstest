add_subdirectory(controller)
add_subdirectory(common)
add_subdirectory(client)
add_subdirectory(server)

add_definitions(-DDEBUG)
add_definitions("-Wall -g")

add_library(${CMAKE_PROJECT_NAME}_lib  ${HEADERS} ${SOURCE})
add_library(ssl STATIC IMPORTED)
set_property(TARGET ssl PROPERTY IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/test/lib/libssl.a)
add_library(crypto STATIC IMPORTED)
set_property(TARGET crypto PROPERTY IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/test/lib/libcrypto.a)

add_executable(${CMAKE_PROJECT_NAME}_server server/main.cpp)
add_executable(${CMAKE_PROJECT_NAME}_client client/main.cpp)
add_executable(${CMAKE_PROJECT_NAME}_ctrl controller/main.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}_server  ${CMAKE_PROJECT_NAME}_lib ssl crypto dl)
target_link_libraries(${CMAKE_PROJECT_NAME}_client  ${CMAKE_PROJECT_NAME}_lib ssl crypto dl)
target_link_libraries(${CMAKE_PROJECT_NAME}_ctrl  ${CMAKE_PROJECT_NAME}_lib ssl crypto dl)