/**
 *  @copyright defined in eos/LICENSE.txt
 */

#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

#include <map>
#include <string>

namespace eosio {

   using std::string;

   /**
    * @defgroup eosioutils rem.utils
    * @ingroup eosiocontracts
    *
    * rem.utils contract
    *
    * @details rem.utils contract defines the structures and actions that allow users and contracts to use helpful
    * tools. Implement validation address another blockchain, set (from Remchain) swap fee.
    * @{
    */
   class [[eosio::contract("rem.utils")]] utils : public contract {
   public:
      utils(name receiver, name code,  datastream<const char*> ds);


      /**
       * Validate address.
       *
       * @details Validation blockchain address.
       *
       * @param name - the chain id validation for,
       * @param address - the address in the corresponding chain network.
       */
      [[eosio::action]]
      void validateaddr( const name& chain_id, const string& address );


      /**
       * Set swap fee.
       *
       * @details Set (from Remchain) swap fee.
       *
       * @param chain_id - the chain id changed fee for,
       * @param fee - the amount of tokens which will be a swap commission for correspond chain.
       */
      [[eosio::action]]
      void setswapfee( const name& chain_id, const asset& fee );

      using validate_address_action = action_wrapper<"validateaddr"_n, &utils::validateaddr>;
      using set_swapfee_action = action_wrapper<"setswapfee"_n, &utils::setswapfee>;

   private:
      static constexpr symbol core_symbol{"REM", 4};

      struct [[eosio::table]] swap_fee {
         name chain;
         asset fee;

         uint64_t primary_key()const { return chain.value; }

         // explicit serialization macro is not necessary, used here only to improve compilation time
         EOSLIB_SERIALIZE( swap_fee, (chain)(fee))
      };

      const std::map <string, name> supported_chains = {
              { "ETH", "ethropsten"_n },
      };

      typedef multi_index< "swapfee"_n, swap_fee> swap_fee_index;
      swap_fee_index swap_fee_table;

      void validate_eth_address(string address);
      void validate_eth_address_checksum(string checksum_address);
      string bytetohex(unsigned char *data, int len);
      std::array<unsigned char, 32> sha3_256(const string& address);
      void add_chain( const name& chain_id, const asset& fee );
   };
   /** @}*/ // end of @defgroup eosioutils rem.utils
} /// namespace eosio
