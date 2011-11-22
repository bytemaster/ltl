PROJECT( gate_controller )

CMAKE_MINIMUM_REQUIRED( VERSION 2.8.0 )

SET( CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules;${CMAKE_MODULE_PATH}" )

INCLUDE( VersionMacros )

SET( DEFAULT_HEADER_INSTALL_DIR include/\${target} )
SET( DEFAULT_LIBRARY_INSTALL_DIR lib/ )
SET( DEFAULT_EXECUTABLE_INSTALL_DIR bin/ )
SET( CMAKE_DEBUG_POSTFIX _debug )
SET( BUILD_SHARED_LIBS NO )

SET(Boost_USE_STATIC_LIBS ON)
FIND_PACKAGE( Boost COMPONENTS thread date_time system filesystem program_options signals serialization chrono) 
FIND_PACKAGE( Wt REQUIRED )

INCLUDE_DIRECTORIES( .. )
INCLUDE_DIRECTORIES( libs )
INCLUDE_DIRECTORIES( ${CMAKE_SOURCE_DIR} )
INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )
INCLUDE_DIRECTORIES( ${Wt_INCLUDE_DIR} )
LINK_DIRECTORIES( ${Boost_LIBRARY_DIRS} )

INCLUDE( SetupTargetMacros )

set( sources 
  date_time.cpp
  server.cpp
  identity.cpp
  asset.cpp
  action.cpp
  account.cpp
  transaction.cpp
  main.cpp
  )
set( libraries 
    pthread
    scrypt
    json
    ${Wt_LIBRARIES}
    ${Wt_HTTP_LIBRARY}
    ${Wt_EXT_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}  
    ${Boost_PROPERTY_TREE_LIBRARY}  
    ${Boost_SYSTEM_LIBRARY}  
    ${Boost_SIGNALS_LIBRARY}  
    ${Boost_CHRONO_LIBRARY}  
    ${Boost_FILESYSTEM_LIBRARY}  
    ${Boost_THREAD_LIBRARY}  
    )


add_executable( market ${sources} )
target_link_libraries( market ${libraries} )

add_subdirectory( libs/scrypt )
add_subdirectory( libs/json )