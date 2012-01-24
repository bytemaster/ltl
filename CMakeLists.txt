FIND_PACKAGE( Wt REQUIRED )
INCLUDE_DIRECTORIES( .. )
INCLUDE_DIRECTORIES( ${CMAKE_SOURCE_DIR} )
INCLUDE_DIRECTORIES( ${Wt_INCLUDE_DIR} )

INCLUDE( SetupTargetMacros )

set( sources 
  date_time.cpp
  server.cpp
  identity.cpp
  asset.cpp
  action.cpp
  account.cpp
  transaction.cpp
  market.cpp
  rpc/session.cpp
  rpc/types.cpp
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

SETUP_LIBRARY( ltl SOURCES ${sources} 
                   LIBRARIES ${libraries} 
                   AUTO_INSTALL_HEADERS
                   LIBRARY_TYPE ${LIBRARY_BUILD_TYPE} )

add_executable( market main.cpp )
target_link_libraries( market ${libraries} ltl )
