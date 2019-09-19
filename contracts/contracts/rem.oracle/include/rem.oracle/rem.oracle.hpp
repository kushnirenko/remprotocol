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

      [[eosio::action]]
      void cleartable();

   private:
      static constexpr symbol core_symbol{"REM", 4};
      static constexpr name system_account = "rem"_n;
      static constexpr name system_token_account = "rem.token"_n;

      struct [[eosio::table]] remusd {
         asset             price;
         block_timestamp   last_update;

         EOSLIB_SERIALIZE( remusd, (price))
      };

      typedef singleton<"remusd"_n, remusd> remusd_inx;
      remusd_inx remusd_tbl;

      struct [[eosio::table]] pricedata {
         uint64_t                   median = 0;
         std::map<name, uint64_t>   price_points;
         block_timestamp            last_update;

         pricedata(){}

         EOSLIB_SERIALIZE( pricedata, (median)(price_points)(last_update))
      };

      typedef singleton<"pricedata"_n, pricedata> pricedata_inx;

      pricedata_inx pricedata_tbl;
      pricedata price_data;

      string join(vector <string> &&vec, string delim = string("*"));
      vector<name> get_map_keys(const std::map<name, uint64_t>& map_in) const;
      void to_rewards(const asset &quantity, const name& payer);

      uint8_t get_majority_amount() const;
      vector<double> get_relevant_prices() const;
      bool is_producer( const name& user ) const;
      vector<name> get_active_producers() const;

      double get_subset_median(vector<double> points) const;
      double get_median(const vector<double>& sorted_points) const;
   };
   /** @}*/ // end of @defgroup eosioauth rem.oracle
} /// namespace eosio
