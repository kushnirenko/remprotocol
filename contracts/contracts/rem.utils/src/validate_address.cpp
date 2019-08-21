/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.utils/rem.utils.hpp>

namespace eosio {
   void utils::validate_eth_address( string address ){
      if ( address.substr(0, 2) == "0x" ) { address = address.substr(2); }

      check( address.size() == 40, "invalid address length" );
      for (const auto& ch: address) {
         check(std::isxdigit(ch), "invalid symbol in ethereum address");
      }
   }

   void utils::add_chain( const name& chain_id, const asset& fee ) {
      swap_fee_table.emplace( _self, [&]( auto& row ) {
         row.chain = chain_id;
         row.fee = fee;
      });
   }
} /// namespace eosio
