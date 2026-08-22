project("XenonRecompTests")

add_executable(XenonRecompBindingTests
    "binding_direct_alias_generated.cpp"
    "binding_emission_test.cpp"
    "binding_link_generated.cpp"
    "binding_link_override.cpp"
    "../XenonRecomp/function_binding.cpp")

target_include_directories(XenonRecompBindingTests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../XenonRecomp")

add_test(NAME XenonRecompBindingTests COMMAND XenonRecompBindingTests)
