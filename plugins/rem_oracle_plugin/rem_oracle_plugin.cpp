/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#include <eosio/rem_oracle_plugin/rem_oracle_plugin.hpp>

namespace eosio {
   static appbase::abstract_plugin& _rem_oracle_plugin = app().register_plugin<rem_oracle_plugin>();

class rem_oracle_plugin_impl {
   public:
};

rem_oracle_plugin::rem_oracle_plugin():my(new rem_oracle_plugin_impl()){}
rem_oracle_plugin::~rem_oracle_plugin(){}

void rem_oracle_plugin::set_program_options(options_description&, options_description& cfg) {
   cfg.add_options()
         ("option-name", bpo::value<string>()->default_value("default value"),
          "Option Description")
         ;
}

void rem_oracle_plugin::plugin_initialize(const variables_map& options) {
   try {
      if( options.count( "option-name" )) {
         // Handle the option
      }
   }
   FC_LOG_AND_RETHROW()
}

void rem_oracle_plugin::plugin_startup() {
   // Make the magic happen
}

void rem_oracle_plugin::plugin_shutdown() {
   // OK, that's enough magic
}

}
