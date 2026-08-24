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

add_executable(XenonRecompInstructionTests
    "instruction_emission_test.cpp"
    "../XenonRecomp/data_range.cpp"
    "../XenonRecomp/function_binding.cpp"
    "../XenonRecomp/function_scan.cpp"
    "../XenonRecomp/recompiler.cpp"
    "../XenonRecomp/recompiler_loader.cpp"
    "../XenonRecomp/recompiler_config.cpp"
    "../XenonRecomp/switch_extent.cpp")

target_include_directories(XenonRecompInstructionTests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../XenonRecomp")

target_precompile_headers(XenonRecompInstructionTests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../XenonRecomp/pch.h")

target_link_libraries(XenonRecompInstructionTests PRIVATE
    LibXenonAnalyse
    XenonUtils
    fmt::fmt
    tomlplusplus::tomlplusplus
    xxHash::xxhash)

add_test(NAME XenonRecompInstructionTests COMMAND XenonRecompInstructionTests)

add_executable(XenonRecompFunctionScanTests
    "function_scan_test.cpp"
    "../XenonRecomp/data_range.cpp"
    "../XenonRecomp/function_scan.cpp")

target_include_directories(XenonRecompFunctionScanTests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../XenonRecomp")

target_link_libraries(XenonRecompFunctionScanTests PRIVATE
    LibXenonAnalyse
    XenonUtils
    fmt::fmt)

add_test(NAME XenonRecompFunctionScanTests COMMAND XenonRecompFunctionScanTests)

add_executable(XenonRecompDisassemblerStateTests
    "disassembler_state_test.cpp")

target_link_libraries(XenonRecompDisassemblerStateTests PRIVATE
    XenonUtils)

add_test(NAME XenonRecompDisassemblerStateTests COMMAND XenonRecompDisassemblerStateTests)

add_executable(XenonRecompDataRangeTests
    "data_range_test.cpp"
    "../XenonRecomp/data_range.cpp"
    "../XenonRecomp/recompiler_config.cpp")

target_include_directories(XenonRecompDataRangeTests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../XenonRecomp")

target_precompile_headers(XenonRecompDataRangeTests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../XenonRecomp/pch.h")

target_link_libraries(XenonRecompDataRangeTests PRIVATE
    LibXenonAnalyse
    XenonUtils
    fmt::fmt
    tomlplusplus::tomlplusplus
    xxHash::xxhash)

add_test(NAME XenonRecompDataRangeTests COMMAND XenonRecompDataRangeTests)
