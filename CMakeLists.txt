cmake_minimum_required(VERSION 3.4)

configure_file("version.config" "version.config" COPYONLY)
file(READ version.config VERSION_CONFIG)
set(VERSION_REGEX "version[\t ]*=[\t ]*([0-9]+\\.[0-9]+\\.*[0-9]*)([-]([a-z]+))*\r?\nupdate_from_version[\t ]*=[\t ]*([0-9]+\\.[0-9]+\\.*[0-9]*)(\r?\n)*$")

if (NOT (${VERSION_CONFIG} MATCHES ${VERSION_REGEX}))
  message(FATAL_ERROR "Cannot read version from version.config")
endif ()

set(VERSION ${CMAKE_MATCH_1})
set(VERSION_MOD ${CMAKE_MATCH_3})
set(UPDATE_FROM_VERSION ${CMAKE_MATCH_4})

if (VERSION_MOD)
  set(PROJECT_VERSION_MOD ${VERSION}-${VERSION_MOD})
else ()
  set(PROJECT_VERSION_MOD ${VERSION})
endif ()

if (NOT CMAKE_BUILD_TYPE)
  # Default to Release builds
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif ()

if (WIN32)
  if (NOT CMAKE_CONFIGURATION_TYPES)
    # Default to only include Release builds so MSBuild.exe 'just works'
    set(CMAKE_CONFIGURATION_TYPES Release CACHE STRING "Semicolon separated list of supported configuration types, only supports Debug, Release, MinSizeRel, and RelWithDebInfo, anything else will be ignored." FORCE)
  endif ()
endif (WIN32)

project(pg_backend_stats VERSION ${VERSION})

message(STATUS "pg_backend_stats version ${PROJECT_VERSION_MOD}. Can be updated from version ${UPDATE_FROM_VERSION}")
message(STATUS "Build type is ${CMAKE_BUILD_TYPE}")

# Search paths for Postgres binaries
if (WIN32)
  find_path(PG_PATH
    bin/postgres
    HINTS
    "C:/PostgreSQL"
    "C:/Program Files/PostgreSQL"
    PATH_SUFFIXES
    bin
    10/bin
    96/bin
    pg96/bin
    DOC
    "The path to a PostgreSQL installation")
endif (WIN32)

if (UNIX)
  find_path(PG_PATH
    bin/postgres
    HINTS
    $ENV{HOME}
    /opt/local/pgsql
    /usr/local/pgsql
    /usr/lib/postgresql
    PATH_SUFFIXES
    bin
    10/bin
    9.6/bin
    96/bin
    pg96/bin
    DOC
    "The path to a PostgreSQL installation")
endif (UNIX)

find_program(PG_CONFIG pg_config
  HINTS
  ${PG_PATH}
  PATH_SUFFIXES
  bin
  DOC
  "The path to the pg_config of the PostgreSQL version to compile against"
  REQUIRED)

if (NOT PG_CONFIG)
  message(FATAL_ERROR "Unable to find 'pg_config'")
endif ()

message(STATUS "Using pg_config ${PG_CONFIG}")

# Check PostgreSQL version
execute_process(
  COMMAND ${PG_CONFIG} --version
  OUTPUT_VARIABLE PG_VERSION_STRING
  OUTPUT_STRIP_TRAILING_WHITESPACE)

if (NOT ${PG_VERSION_STRING} MATCHES "^PostgreSQL[ ]+([0-9]+)\\.?([0-9]*)(\\.([0-9]+))*(devel)?")
  message(FATAL_ERROR "Could not parse PostgreSQL version ${PG_VERSION_STRING}")
endif ()

set(PG_VERSION_MAJOR ${CMAKE_MATCH_1})
set(PG_VERSION_MINOR ${CMAKE_MATCH_2})
set(PG_VERSION_PATCH ${CMAKE_MATCH_4})

if (NOT ${PG_VERSION_PATCH} OR ${PG_VERSION_PATCH} EQUAL "")
  set(PG_VERSION "${PG_VERSION_MAJOR}.${PG_VERSION_MINOR}")
else ()
  set(PG_VERSION "${PG_VERSION_MAJOR}.${PG_VERSION_MINOR}.${PG_VERSION_PATCH}")
endif ()

message(STATUS "Compiling against PostgreSQL version ${PG_VERSION}")

# Get PostgreSQL configuration from pg_config
execute_process(
  COMMAND ${PG_CONFIG} --includedir
  OUTPUT_VARIABLE PG_INCLUDEDIR
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --includedir-server
  OUTPUT_VARIABLE PG_INCLUDEDIR_SERVER
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --libdir
  OUTPUT_VARIABLE PG_LIBDIR
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --pkglibdir
  OUTPUT_VARIABLE PG_PKGLIBDIR
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --sharedir
  OUTPUT_VARIABLE PG_SHAREDIR
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --bindir
  OUTPUT_VARIABLE PG_BINDIR
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --cppflags
  OUTPUT_VARIABLE PG_CPPFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --cflags
  OUTPUT_VARIABLE PG_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --ldflags
  OUTPUT_VARIABLE PG_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
  COMMAND ${PG_CONFIG} --libs
  OUTPUT_VARIABLE PG_LIBS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

find_path(PG_SOURCE_DIR
  src/include/pg_config.h.in
  HINTS
  $ENV{HOME}
  $ENV{HOME}/projects
  $ENV{HOME}/Projects
  $ENV{HOME}/development
  $ENV{HOME}/Development
  $ENV{HOME}/workspace
  PATH_SUFFIXES
  postgres
  postgresql
  pgsql
  DOC
  "The path to the PostgreSQL source tree")

if (PG_SOURCE_DIR)
  message(STATUS "Found PostgreSQL source in ${PG_SOURCE_DIR}")
endif (PG_SOURCE_DIR)

add_custom_target(controlfile ALL DEPENDS pg_backend_stats.control)

add_subdirectory(src)

install(
  FILES pg_backend_stats.control
  DESTINATION "${PG_SHAREDIR}/extension")

macro(get_parents DIR DIR_LIST)
    list(APPEND DIR_LIST ${DIR})
    set(PDIR ${DIR})
  while (NOT (${PDIR} STREQUAL "/"))
    list(APPEND DIR_LIST ${PDIR})
    get_filename_component(PDIR ${PDIR} DIRECTORY)
  endwhile ()
endmacro()

set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION_MOD})
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Optiver")
set(CPACK_PACKAGE_VENDOR "Optiver")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
get_parents(${PG_SHAREDIR}/extension DIR_LIST)
get_parents(${PG_PKGLIBDIR} DIR_LIST)
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION ${DIR_LIST})
include(CPack)
