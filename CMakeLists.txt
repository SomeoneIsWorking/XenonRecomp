cmake_minimum_required (VERSION 3.20)

set(THIRDPARTY_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)

set(CMAKE_CXX_STANDARD 17)
set(BUILD_SHARED_LIBS OFF)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_subdirectory(${THIRDPARTY_ROOT})
set(XENONANALYSE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/XenonAnalyse)
set(XENONUTILS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/XenonUtils)
set(XENONRECOMP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/XenonRecomp)

project ("XenonRecomp-ALL")

if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "XenonRecomp requires the Clang C++ toolchain")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)

add_subdirectory(${XENONANALYSE_ROOT})
add_subdirectory(${XENONRECOMP_ROOT})
add_subdirectory(${XENONUTILS_ROOT})
add_subdirectory(XexInspect)

# Only tests if this is the top level project
if (${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_SOURCE_DIR})
    add_subdirectory(XenonTests)

    if (BUILD_TESTING)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        add_subdirectory(XenonRecompTests)
        add_subdirectory(XexInspectTests)
        add_test(NAME XenonRecompCppQuality
            COMMAND ${Python3_EXECUTABLE}
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_cpp_quality.py"
                    "${CMAKE_BINARY_DIR}")
        add_test(NAME XenonRecompSourceStructure
            COMMAND ${Python3_EXECUTABLE}
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_source_structure.py")
        add_test(NAME XenonRecompSourceStructureSelftest
            COMMAND ${Python3_EXECUTABLE}
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_source_structure.py"
                    --selftest)
    endif()
endif()
