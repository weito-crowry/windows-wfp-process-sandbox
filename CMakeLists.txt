cmake_minimum_required(VERSION 3.20)

project(WfpProcessSandbox LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "WfpProcessSandbox requires Windows.")
endif()

add_executable(WfpProcessSandbox
    src/main.cpp
    src/wfp_session.cpp
    src/user_identity.cpp
    src/process_runner.cpp
)
target_compile_features(WfpProcessSandbox PRIVATE cxx_std_17)
target_compile_definitions(WfpProcessSandbox PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)
target_link_libraries(WfpProcessSandbox PRIVATE Fwpuclnt Advapi32)

add_executable(WfpTestClient test_client/main.cpp)
target_compile_features(WfpTestClient PRIVATE cxx_std_17)
target_compile_definitions(WfpTestClient PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)
target_link_libraries(WfpTestClient PRIVATE Ws2_32)
