file(GLOB HEADERS "include/eosio/rem_oracle_plugin/*.hpp")
add_library( rem_oracle_plugin
             rem_oracle_plugin.cpp
             ${HEADERS} )

target_link_libraries( rem_oracle_plugin appbase fc )
target_include_directories( rem_oracle_plugin PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
