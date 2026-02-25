#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "LIEF::LIEF" for configuration "Release"
set_property(TARGET LIEF::LIEF APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(LIEF::LIEF PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/LIEF_imp.a"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/LIEF.dll"
  )

list(APPEND _cmake_import_check_targets LIEF::LIEF )
list(APPEND _cmake_import_check_files_for_LIEF::LIEF "${_IMPORT_PREFIX}/lib/LIEF_imp.a" "${_IMPORT_PREFIX}/lib/LIEF.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
