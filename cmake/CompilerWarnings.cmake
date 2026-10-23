# cmake/CompilerWarnings.cmake
# Applies CLICOM standard compiler warnings to a named target.
#
# Usage:
#   clicom_set_warnings(my_target)

function(clicom_set_warnings target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            /W4          # High warning level
            /WX-         # Warnings are not errors (during active development)
            /wd4996      # Disable "deprecated" warnings (cross-platform portability)
            /wd4100      # Disable "unreferenced formal parameter"
        )
    else()
        # GCC / Clang
        target_compile_options(${target_name} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wno-unused-parameter
            -Wformat=2
            -Wstrict-prototypes
            -Wmissing-prototypes
        )
    endif()
endfunction()
