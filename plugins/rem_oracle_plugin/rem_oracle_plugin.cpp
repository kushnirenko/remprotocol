/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#include <eosio/rem_oracle_plugin/rem_oracle_plugin.hpp>
#include <eosio/rem_oracle_plugin/http_client.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/wast_to_wasm.hpp>

#include <fc/variant.hpp>
#include <fc/io/json.hpp>
#include <fc/exception/exception.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/io/json.hpp>

#include <Inline/BasicTypes.h>
#include <IR/Module.h>
#include <IR/Validate.h>
#include <WAST/WAST.h>
#include <WASM/WASM.h>
#include <Runtime/Runtime.h>

#include <contracts.hpp>

#include <boost/optional/optional.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/lexical_cast.hpp>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/asio/ssl.hpp>

using boost::asio::ip::tcp;

namespace eosio {
   static appbase::abstract_plugin& _rem_oracle_plugin = app().register_plugin<rem_oracle_plugin>();

class rem_oracle_plugin_impl {
   public:
     std::string _cryptocompare_apikey;

     std::string make_request(const char* host, const char* endpoint) {
         boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
         ctx.set_default_verify_paths();

         boost::asio::io_service io_service;
         http_client c(io_service, ctx, host, endpoint);
         io_service.run();

         std::string response = c.get_response_body();
         return response;
     }

     double get_coingecko_rem_price(const char* coingecko_host, const char* remme_endpoint) {
         std::string response = make_request(coingecko_host, remme_endpoint);

         boost::iostreams::stream<boost::iostreams::array_source> stream(response.c_str(), response.size());
         namespace pt = boost::property_tree;
         pt::ptree root;
         pt::read_json(stream, root);
         double sum = 0;
         int counter = 0;
         for (pt::ptree::value_type &log : root.get_child("tickers")) {
             //const std::string& key = log.first; // key
             const boost::property_tree::ptree& subtree = log.second;

             boost::optional<std::string> target_opt = subtree.get_optional<std::string>("target");
             boost::optional<std::string> last_opt = subtree.get_optional<std::string>("last");
             //boost::optional<std::string> txid_opt = subtree.get_optional<std::string>("transactionHash");
             //cout << "t2: " << data_opt.get() << endl;

             if(target_opt && target_opt.get() == "USDT") {
                 sum += boost::lexical_cast<double>(last_opt.get());
                 counter++;
             }
             else
                 continue;
         }
         return sum/counter;
     }

     double get_cryptocompare_rem_price(const char* cryptocompare_host, const char* cryptocompare_endpoint) {
         std::string response = make_request(cryptocompare_host, cryptocompare_endpoint);

         boost::iostreams::stream<boost::iostreams::array_source> stream(response.c_str(), response.size());
         namespace pt = boost::property_tree;
         pt::ptree root;
         pt::read_json(stream, root);
         boost::optional<double> price_opt = root.get_optional<double>("USD");
         if (price_opt)
             return price_opt.get();
         else
             return 0;

     }

};

rem_oracle_plugin::rem_oracle_plugin():my(new rem_oracle_plugin_impl()){}
rem_oracle_plugin::~rem_oracle_plugin(){}

void rem_oracle_plugin::set_program_options(options_description&, options_description& cfg) {
  cfg.add_options()
        ("cryptocompare-apikey", bpo::value<std::string>()->default_value(""),
         "cryptocompare api key for reading REM token price")

        ("update_price_period", bpo::value<uint32_t>()->default_value(update_price_period), "")
        ;
}

void rem_oracle_plugin::plugin_initialize(const variables_map& options) {
  try {
    std::string cryptocompare_apikey = options.at( "cryptocompare-apikey" ).as<std::string>();
    my->_cryptocompare_apikey = cryptocompare_apikey;

    update_price_period = options.at( "update_price_period" ).as<uint32_t>();

  } FC_LOG_AND_RETHROW()

}

void rem_oracle_plugin::plugin_startup() {

}

void rem_oracle_plugin::plugin_shutdown() {

}

}
