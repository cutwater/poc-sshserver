cmake_minimum_required(VERSION 3.3)
project(sshserver)

set(SOURCE_FILES main.c)
set(LIBRARIES util ssh)

add_executable(sshserver ${SOURCE_FILES})
target_link_libraries(sshserver ${LIBRARIES})