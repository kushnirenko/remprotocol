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

#include <numeric>

namespace eosio {

   using std::string;
   using std::vector;

   /**
    * @defgroup eosioauth rem.auth
    * @ingroup eosiocontracts
    *
    * rem.auth contract
    *
    * @details rem.auth contract defines the structures and actions that allow users and contracts to store public keys.
    * @{
    */
   class [[eosio::contract("rem.auth")]] auth : public contract {
   public:

      auth(name receiver, name code,  datastream<const char*> ds);

      /**
       * Add new authentication key action.
       *
       * @details Add new authentication key by user account.
       *
       * @param account - the owner account to execute the addkeyacc action for,
       * @param key - the public key that signed the payload,
       * @param signed_by_key - the signature that sign payload by key,
       * @param extra_key - the public key for authorization in external services,
       * @param payer_str - the account from which resources are debited.
       */
      [[eosio::action]]
      void addkeyacc(const name &account, const public_key &key, const signature &signed_by_key,
                     const string &extra_key, const string &payer_str);

      /**
       * Add new authentication key action.
       *
       * @details Add new authentication key by using correspond to account authentication key.
       *
       * @param account - the owner account to execute the addkeyacc action for,
       * @param new_key - the public key that will be added,
       * @param signed_by_new_key - the signature that sign payload by new_key,
       * @param extra_key - the public key for authorization in external services,
       * @param key - the public key which is tied to the corresponding account,
       * @param sign_by_key - the signature that sign payload by key,
       * @param payer_str - the account from which resources are debited.
       */
      [[eosio::action]]
      void addkeyapp(const name &account, const public_key &new_key, const signature &signed_by_new_key,
                     const string &extra_key, const public_key &key, const signature &signed_by_key,
                     const string &payer_str);

      /**
       * Transfer action.
       *
       * @details Allows `from` account to transfer to `to` account the `quantity` tokens.
       * One account is debited and the other is credited with quantity tokens.
       *
       * @param from - the account to transfer from,
       * @param to - the account to be transferred to,
       * @param quantity - the quantity of tokens to be transferred,
       * @param key - the public key which is tied to the corresponding account,
       * @param signed_by_key - the signature that sign payload by key,
       */
      [[eosio::action]]
      void transfer(const name &from, const name &to, const asset &quantity,
                    const public_key &key, const signature &signed_by_key);

      /**
       * Set block producers reward.
       *
       * @details Change amount of block producers reward, action permitted only for producers.
       *
       * @param quantity - the quantity of tokens to be rewarded.
       */
      [[eosio::action]]
      void setbpreward(const asset &quantity);


      [[eosio::action]]
      void cleartable( );

      using addkeyacc_action = action_wrapper<"addkeyacc"_n, &auth::addkeyacc>;
      using addkeyapp_action = action_wrapper<"addkeyapp"_n, &auth::addkeyapp>;
      using transfer_action = action_wrapper<"transfer"_n, &auth::transfer>;

   private:
      static constexpr symbol core_symbol{"REM", 4};
      static constexpr name system_account = "rem"_n;
      static constexpr name system_token_account = "rem.token"_n;
      const time_point key_lifetime = time_point(seconds(31104000)); // 360 days

      struct [[eosio::table]] authkeys {
         uint64_t          N;
         name              owner;
         public_key        key;
         string            extra_key;
         block_timestamp   not_valid_before;
         block_timestamp   not_valid_after;
         uint32_t          revoked_at;

         uint64_t primary_key() const { return N; }
         uint64_t by_name() const { return owner.value; }

         EOSLIB_SERIALIZE( authkeys, (N)(owner)(key)(extra_key)(not_valid_before)(not_valid_after)(revoked_at))
      };

      struct [[eosio::table]] prodsreward {
         asset quantity{100000, core_symbol};

         // explicit serialization macro is not necessary, used here only to improve compilation time
         EOSLIB_SERIALIZE( prodsreward, (quantity))
      };

      typedef multi_index<"authkeys"_n, authkeys,
                          indexed_by<"byname"_n, const_mem_fun < authkeys, uint64_t, &authkeys::by_name>>
                          > authkeys_inx;

      typedef singleton<"prodsreward"_n, prodsreward> p_reward;

      authkeys_inx authkeys_tbl;
      p_reward p_reward_table;
      prodsreward prods_reward;

      void _addkey( const name& account, const public_key& device_key, const string& extra_key, const name& payer);
      void require_app_auth( const checksum256 &digest, const name &user,
                             const public_key &sign_pub_key, const signature &signature );

      void to_rewards(const name& payer, const asset &quantity);

      string join(vector <string> &&vec, string delim = string("*"));
      checksum256 sha256(const string &str) {
         return eosio::sha256(str.c_str(), str.size());
      }
   };
   /** @}*/ // end of @defgroup eosioauth rem.auth
} /// namespace eosio