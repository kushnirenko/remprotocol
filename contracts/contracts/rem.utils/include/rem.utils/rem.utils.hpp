/**
 *  @copyright defined in eos/LICENSE.txt
 */

#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

#include <vector>
#include <map>
#include <string>

namespace eosio {

   using std::string;

   /**
    * @defgroup remswap rem.utils
    * @ingroup eosiocontracts
    *
    * rem.utils contract
    *
    * @details rem.utils contract defines the structures and actions that allow users to init token swap,
    * finish token swap, create new account and cancel token swap.
    * @{
    */
   class [[eosio::contract("rem.utils")]] utils : public contract {
   public:
      using contract::contract;
      utils(name receiver, name code,  datastream<const char*> ds);


      /**
       * Set block producers reward.
       *
       * @details Change amount of block producers reward, action permitted only for producers.
       *
       * @param quantity - the quantity of tokens to be rewarded.
       */
      [[eosio::action]]
      void validateaddr( const name& chain_id, const string& address );


      [[eosio::action]]
      void setswapfee( const name& chain_id, const asset& fee );

      using validate_address_action = action_wrapper<"validateaddr"_n, &utils::validateaddr>;

   private:
      static constexpr symbol core_symbol{"REM", 4};

      struct [[eosio::table]] swap_fee {
         name chain;
         asset fee;

         uint64_t primary_key()const { return chain.value; }

         // explicit serialization macro is not necessary, used here only to improve compilation time
         EOSLIB_SERIALIZE( swap_fee, (chain)(fee))
      };

      const std::map <string, name> supported_chain = {
              { "ETH", "ethropsten"_n },
      };

      typedef multi_index< "swapfee"_n, swap_fee> swap_fee_index;

      swap_fee_index swap_fee_table;

      void validate_eth_address( string address );
      void add_chain( const name& chain_id, const asset& fee );
   };
   /** @}*/ // end of @defgroup remswap rem.utils
} /// namespace eosio
