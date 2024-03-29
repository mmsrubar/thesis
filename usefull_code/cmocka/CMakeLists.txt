project(cmocka C)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "0")
set(APPLICATION_VERSION_MINOR "4")
set(APPLICATION_VERSION_PATCH "0")

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

# SOVERSION scheme: CURRENT.AGE.REVISION
#   If there was an incompatible interface change:
#     Increment CURRENT. Set AGE and REVISION to 0
#   If there was a compatible interface change:
#     Increment AGE. Set REVISION to 0
#   If the source code was changed, but there were no interface changes:
#     Increment REVISION.
set(LIBRARY_VERSION "0.2.0")
set(LIBRARY_SOVERSION "0")

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

# add definitions
include(DefineCMakeDefaults)
include(DefinePlatformDefaults)
include(DefineCompilerFlags)
include(DefineInstallationPaths)
include(DefineOptions.cmake)
include(CPackConfig.cmake)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# check subdirectories
add_subdirectory(doc)
add_subdirectory(include)
add_subdirectory(src)

if (UNIT_TESTING)
    include(AddCMockaTest)
    add_subdirectory(tests)
endif (UNIT_TESTING)

add_subdirectory(example)

# pkg-config file
configure_file(cmocka.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/cmocka.pc)
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cmocka.pc
  DESTINATION
    ${LIB_INSTALL_DIR}/pkgconfig
  COMPONENT
    pkgconfig
)

# cmake config files
configure_file(cmocka-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/cmocka-config.cmake @ONLY)
configure_file(cmocka-config-version.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/cmocka-config-version.cmake @ONLY)
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/cmocka-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/cmocka-config-version.cmake
    DESTINATION
        ${CMAKE_INSTALL_DIR}
    COMPONENT
        devel
)
