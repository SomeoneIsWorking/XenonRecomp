project("XexInspect")

add_library(XexInspectLib
    "inspect.cpp"
    "pattern_scan.cpp")
target_include_directories(XexInspectLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(XexInspectLib PUBLIC XenonUtils)

add_executable(xex-inspect "main.cpp")
target_link_libraries(xex-inspect PRIVATE XexInspectLib)
