/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#pragma once
#include <appbase/application.hpp>

namespace eosio {

using namespace appbase;

const char* coingecko_host = "api.coingecko.com";
const char* coingecko_endpoint = "/api/v3/coins/remme/tickers";

const char* cryptocompare_host = "min-api.cryptocompare.com";
const char* cryptocompare_endpoint = "/data/price";
const char* cryptocompare_params = "?fsym=REM&tsyms=USD,BTC,ETH&apikey=";

uint32_t update_price_period = 3600;  // seconds


/**
 *  This is a template plugin, intended to serve as a starting point for making new plugins
 */
class rem_oracle_plugin : public appbase::plugin<rem_oracle_plugin> {
public:
   rem_oracle_plugin();
   virtual ~rem_oracle_plugin();

   APPBASE_PLUGIN_REQUIRES()
   virtual void set_program_options(options_description&, options_description& cfg) override;

   void plugin_initialize(const variables_map& options);
   void plugin_startup();
   void plugin_shutdown();

private:
   std::unique_ptr<class rem_oracle_plugin_impl> my;
};

}
