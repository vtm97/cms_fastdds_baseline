cmake_minimum_required(VERSION 3.16)

project(cms_fastdds_baseline LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(fastdds REQUIRED)
find_package(fastcdr REQUIRED)

add_library(cms_message_types
    generated/idl/CmsMessagePubSubTypes.cxx
    generated/idl/CmsMessageTypeObjectSupport.cxx
)

target_include_directories(cms_message_types
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/generated/idl
)

target_link_libraries(cms_message_types
    PUBLIC
        fastdds
        fastcdr
)

add_executable(cms_publisher
    src/publisher.cpp
)

target_link_libraries(cms_publisher
    PRIVATE
        cms_message_types
)

add_executable(cms_subscriber
    src/subscriber.cpp
)

target_link_libraries(cms_subscriber
    PRIVATE
        cms_message_types
)

add_executable(cms_echo_responder
    src/echo_responder.cpp
)

target_link_libraries(cms_echo_responder
    PRIVATE
        cms_message_types
)


add_executable(cms_echo_responder_queue
    src/echo_responder_queue.cpp
)

target_link_libraries(cms_echo_responder_queue
    PRIVATE
        cms_message_types
)

add_executable(cms_rtt_client
    src/rtt_client.cpp
)

target_link_libraries(cms_rtt_client
    PRIVATE
        cms_message_types
)
