
spec2def(storport.sys storport.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    fdo.c
    miniport.c
    misc.c
    pdo.c
    storport.c
    stubs.c
fkrnlimp.c)

list(APPEND PCH_SKIP_SOURCE
    guid.c)
# Add include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/include/ddk
    ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/include/reactos
    ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/lib/pseh/include/pseh

)
add_library(storport MODULE
    ${SOURCE}
    ${PCH_SKIP_SOURCE}
    storport.rc
    ${CMAKE_CURRENT_BINARY_DIR}/storport.def)

add_pch(storport precomp.h "${PCH_SKIP_SOURCE}")
set_module_type(storport kernelmodedriver)
add_importlibs(storport ntoskrnl hal)
add_cd_file(TARGET storport DESTINATION reactos/system32/drivers NO_CAB FOR all)
