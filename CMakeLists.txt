cmake_minimum_required(VERSION 3.19)

project(tancrypt VERSION 1.0.0 LANGUAGES CXX)

option(DO_TEST "Toggle for unit tests [ON by default]" ON)

include(GNUInstallDirs)
file(GLOB_RECURSE SRC_FILES src/*.cc src/*.cpp)

add_library(${PROJECT_NAME} INTERFACE)

if(NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "(arm|aarch64)")

  if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME}
    INTERFACE
    $<$<CONFIG:Debug>: -Wall -fsanitize=address>
    $<$<CONFIG:Release>: -O2>
    )
    target_compile_definitions(${PROJECT_NAME}
    INTERFACE
    $<$<CONFIG:Debug>:_DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION _DISABLE_OPTIONAL_ANNOTATION>
    )
  else()
    target_compile_options(${PROJECT_NAME}
    INTERFACE
    $<$<CONFIG:Debug>: -Wall -Wextra -Wpedantic -fsanitize=address -fno-omit-frame-pointer>
    $<$<CONFIG:Release>: -O3>
    )
    target_link_options(${PROJECT_NAME}
    INTERFACE
    $<$<CONFIG:Debug>:-fsanitize=address>
    )
  endif()
endif()

file(GLOB_RECURSE SHARED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc)
target_sources(${PROJECT_NAME} INTERFACE ${SHARED_SRCS})

file(GLOB_RECURSE COPY_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/aes/include/*.h
  ${CMAKE_CURRENT_SOURCE_DIR}/aes/include/*.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}/hash/include/*.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hash/include/*.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rsa/include/*.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rsa/include/*.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}/include/dutils.hpp
)

file(COPY ${COPY_HEADERS} DESTINATION ${CMAKE_BINARY_DIR}/include/${PROJECT_NAME}/)

add_subdirectory(aes)
add_subdirectory(hash)
add_subdirectory(rsa)

target_include_directories(${PROJECT_NAME} INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)

target_link_libraries(${PROJECT_NAME} INTERFACE aes)
target_link_libraries(${PROJECT_NAME} INTERFACE hash)
target_link_libraries(${PROJECT_NAME} INTERFACE rsa)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/dutils.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tancrypt/)

install(EXPORT "${PROJECT_NAME}Targets"
  FILE "${PROJECT_NAME}Targets.cmake"
  NAMESPACE "${PROJECT_NAME}::"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

include(CMakePackageConfigHelpers)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/tancryptConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/tancryptConfig.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_SOURCE_DIR})
 enable_testing()
 add_subdirectory(tests)
 endif()
