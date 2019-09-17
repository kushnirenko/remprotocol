/**
 *  @copyright defined in eos/LICENSE.txt
 */

#pragma once

#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/singleton.hpp>
#include <eosio/eosio.hpp>
#include <eosio/transaction.hpp>
#include <eosio/permission.hpp>

#include <time.h>
#include <numeric>

namespace eosio {

   using std::string;
   using std::vector;

   /**
    * @defgroup eosioauth rem.oracle
    * @ingroup eosiocontracts
    *
    * rem.oracle contract
    *
    * @details rem.oracle contract defines the structures and actions that allow users and contracts to use .
    * @{
    */
   class [[eosio::contract("rem.oracle")]] oracle : public contract {
   public:

      oracle(name receiver, name code,  datastream<const char*> ds);

      /**
       * Add authentication key.
       *
       * @details .
       *
       * @param user - the owner account to execute the addkey action for,
       * @param device_pubkey - the public key corresponding to the new authentication device.
       */
      [[eosio::action]]
      void setprice(const name& producer, const uint64_t& price);

   private:
      static constexpr symbol core_symbol{"REM", 4};
      static constexpr name system_account = "rem"_n;
      static constexpr name system_token_account = "rem.token"_n;

      struct [[eosio::table]] remusd {
         asset last_price;
         asset active_price;

         EOSLIB_SERIALIZE( remusd, (last_price)(last_price))
      };

      typedef singleton<"remusd"_n, remusd> remusd_inx;
      remusd_inx remusd_tbl;

      struct [[eosio::table]] price_data {
         uint64_t                   key;
         uint8_t                    round;
         uint64_t                   median;
         std::map<name, uint64_t>   price_points;
         block_timestamp            timestamp;

         uint64_t primary_key() const { return key; }
         uint64_t by_round() const { return round; }

         EOSLIB_SERIALIZE( price_data, (key)(round)(median)(price_points)(timestamp))
      };

      typedef multi_index<"pricedata"_n, price_data,
                         indexed_by<"byround"_n, const_mem_fun < price_data, uint64_t, &price_data::by_round>>
                         > price_data_inx;
      price_data_inx price_data_tbl;

      string join(vector <string> &&vec, string delim = string("*"));
      void to_rewards(const asset &quantity, const name& payer);
   };
   /** @}*/ // end of @defgroup eosioauth rem.oracle
} /// namespace eosio
