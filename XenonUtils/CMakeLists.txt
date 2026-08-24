project("XenonUtils")

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(XenonUtils
    "disasm.cpp" 
    "xex.cpp" 
    "image.cpp" 
    "xdbf_wrapper.cpp"
    "xex_patcher.cpp"
    "memory_mapped_file.cpp"
    "sha256.cpp"
    "${THIRDPARTY_ROOT}/libmspack/libmspack/mspack/lzxd.c"
    "${THIRDPARTY_ROOT}/tiny-AES-c/aes.c"
)

target_compile_definitions(XenonUtils
    PRIVATE
        NOMINMAX
)

target_include_directories(XenonUtils 
    PUBLIC
        .
        "${THIRDPARTY_ROOT}/simde"
    PRIVATE
        "${THIRDPARTY_ROOT}/libmspack/libmspack/mspack"
        "${THIRDPARTY_ROOT}/tiny-AES-c"
        "${THIRDPARTY_ROOT}/TinySHA1"
)

target_link_libraries(XenonUtils 
    PUBLIC
        disasm
        OpenSSL::Crypto
)
