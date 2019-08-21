/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.utils/rem.utils.hpp>

#include "validate_address.cpp"

namespace eosio {
   utils::utils(name receiver, name code,  datastream<const char*> ds): contract(receiver, code, ds),
   swap_fee_table(_self, _self.value) {
   if ( swap_fee_table.begin() == swap_fee_table.end() ) {
      add_chain(supported_chains.at("ETH"), asset{500000, core_symbol});
      }
   }

   void utils::validateaddr( const name& chain_id, const string& address ) {
      auto it = swap_fee_table.find( chain_id.value );
      check(it != swap_fee_table.end(), "not supported chain id");

      if ( supported_chains.at("ETH").value == chain_id.value ) {
         validate_eth_address(address);
      }
   }

   void utils::setswapfee( const name& chain_id, const asset& fee ){
      require_auth( _self );
      auto it = swap_fee_table.find( chain_id.value );

      check(it != swap_fee_table.end(), "not supported chain id");
      check(fee.is_valid(), "invalid fee");
      check( fee.amount > 0, "must transfer positive quantity" );
      check( fee.symbol == core_symbol, "symbol precision mismatch" );

      swap_fee_table.modify( *it, _self, [&]( auto& row ) {
         row.fee = fee;
      });
   }
} /// namespace eosio

EOSIO_DISPATCH( eosio::utils, (validateaddr)(setswapfee) )
