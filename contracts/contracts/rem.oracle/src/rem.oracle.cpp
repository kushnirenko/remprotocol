/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.oracle/rem.oracle.hpp>
#include <rem.system/rem.system.hpp>

namespace eosio {
   oracle::oracle(name receiver, name code,  datastream<const char*> ds): contract(receiver, code, ds),
                                                                          remusd_tbl(_self, _self.value),
                                                                          price_data_tbl(_self, _self.value) {}

   void oracle::setprice(const name& producer, const uint64_t& price) {
      require_auth(producer);
      vector<name> _producers = eosio::get_active_producers();
      bool is_producer = std::find(_producers.begin(), _producers.end(), producer) != _producers.end();
      check(is_producer, "block producer authorization required");

   }
} /// namespace eosio

EOSIO_DISPATCH( eosio::oracle, (setprice) )
