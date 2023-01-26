add_subdirectory(controller)
add_subdirectory(common)
add_subdirectory(client)
add_subdirectory(server)

add_definitions(-DDEBUG)
add_definitions("-Wall -g")

add_library(${CMAKE_PROJECT_NAME}_lib ${SOURCE} ${HEADERS})
add_executable(${CMAKE_PROJECT_NAME}_server server/main.cpp)
add_executable(${CMAKE_PROJECT_NAME}_client client/main.cpp)
add_executable(${CMAKE_PROJECT_NAME}_ctrl controller/main.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}_server  ${CMAKE_PROJECT_NAME}_lib )
target_link_libraries(${CMAKE_PROJECT_NAME}_client  ${CMAKE_PROJECT_NAME}_lib )
target_link_libraries(${CMAKE_PROJECT_NAME}_ctrl  ${CMAKE_PROJECT_NAME}_lib )