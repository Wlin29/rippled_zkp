# This module finds the libsnark library

# Find the path to the libsnark installation
find_path(LIBSNARK_INCLUDE_DIR
  NAMES libsnark/common/default_types/r1cs_ppzksnark_pp.hpp
  PATHS ${CMAKE_SOURCE_DIR}/libsnark_install/include
  NO_DEFAULT_PATH
)

find_library(LIBSNARK_LIBRARY
  NAMES snark
  PATHS ${CMAKE_SOURCE_DIR}/libsnark_install/lib
  NO_DEFAULT_PATH
)

# Find libsnark's dependencies (this is a simplified version)
find_library(GMP_LIBRARY gmp)
find_library(GMPXX_LIBRARY gmpxx)

if(LIBSNARK_INCLUDE_DIR AND LIBSNARK_LIBRARY)
  set(LIBSNARK_FOUND TRUE)
  set(LIBSNARK_INCLUDE_DIRS ${LIBSNARK_INCLUDE_DIR})
  set(LIBSNARK_LIBRARIES ${LIBSNARK_LIBRARY} ${GMP_LIBRARY} ${GMPXX_LIBRARY})
  message(STATUS "Found libsnark: ${LIBSNARK_LIBRARY}")
else()
  set(LIBSNARK_FOUND FALSE)
endif()

mark_as_advanced(
  LIBSNARK_INCLUDE_DIR
  LIBSNARK_LIBRARY
)