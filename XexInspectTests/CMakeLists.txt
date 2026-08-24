project("XexInspectTests")

add_executable(XexInspectTests "inspect_tests.cpp")
target_link_libraries(XexInspectTests PRIVATE XexInspectLib)
add_test(NAME XexInspectTests COMMAND XexInspectTests)
