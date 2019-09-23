/**
 *  @copyright defined in eos/LICENSE.txt
 */

#pragma once

#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
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
       * Add new authentication key.
       *
       * @details Add new authentication key by user account.
       *
       * @param account - the owner account to execute the addkeyacc action for,
       * @param key - the public key that signed the payload,
       * @param signed_by_key - the signature that sign payload by key,
       * @param extra_key - the public key for authorization in external services,
       * @param payer_str - the account from which resources are deducted.
       */
      [[eosio::action]]
      void addkeyacc(const name &account, const public_key &key, const signature &signed_by_key,
                     const string &extra_key, const string &payer_str);

      /**
       * Add new device key.
       *
       * @details Add new authentication device.
       *
       * @param account - the owner account to execute the addkeyacc action for,
       * @param new_key - the public key that will be added,
       * @param signed_by_new_key - the signature that sign payload by new_key,
       * @param extra_key - the public key for authorization in external services,
       * @param key - the public key which is tied to the corresponding account,
       * @param sign_by_key - the signature that sign payload by key,
       * @param payer_str - the account from which resources are deducted.
       */
      [[eosio::action]]
      void addkeyapp(const name &account, const public_key &new_key, const signature &signed_by_new_key,
                     const string &extra_key, const public_key &key, const signature &signed_by_key,
                     const string &payer_str);


      [[eosio::action]]
      void addkeywrap(const name &account, const public_key &key, const string &extra_key, const name &payer);


      [[eosio::action]]
      void transfer( const name &from, const name &to, const asset &quantity,
                     const public_key &key, const signature &signed_by_key );


      [[eosio::action]]
      void cleartable( );

      using addkeyacc_action = action_wrapper<"addkeyacc"_n, &auth::addkeyacc>;
      using addkeyapp_action = action_wrapper<"addkeyapp"_n, &auth::addkeyapp>;
      using transfer_action = action_wrapper<"transfer"_n, &auth::transfer>;
      using addkeywrap_action = action_wrapper<"addkeywrap"_n, &auth::addkeywrap>;

   private:
      static constexpr symbol core_symbol{"REM", 4};
      static constexpr name system_account = "rem"_n;
      static constexpr name system_token_account = "rem.token"_n;
      const asset prods_reward{100000, core_symbol};
      const time_point key_lifetime = time_point(seconds(31104000)); // 360 days
      const uint32_t wait_confirm_sec = 86400; // 1 day
      const time_point wait_confirm_time = time_point(seconds(wait_confirm_sec));

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

         EOSLIB_SERIALIZE( authkeys, (key)(owner)(key)(extra_key)(not_valid_before)(not_valid_after)(revoked_at))
      };

      typedef multi_index<"authkeys"_n, authkeys,
                          indexed_by<"byname"_n, const_mem_fun < authkeys, uint64_t, &authkeys::by_name>>
                          > authkeys_inx;
      authkeys_inx authkeys_tbl;

      struct [[eosio::table]] wait_confirm {
         uint64_t              key;
         name                  owner;
         block_timestamp       init_time;
         block_timestamp       wait_time;
         name                  action_account;
         name                  action_name;
         vector<char>          action_data;
         vector<public_key>    provided_approvals;

         uint64_t primary_key() const { return key; }
         uint64_t by_name() const { return owner.value; }

         EOSLIB_SERIALIZE( wait_confirm, (key)(owner)(init_time)(wait_time)(action_account)
                                         (action_name)(action_data)(provided_approvals))
      };

      typedef multi_index<"wait"_n, wait_confirm,
                          indexed_by<"byname"_n, const_mem_fun < wait_confirm, uint64_t, &wait_confirm::by_name>>
                          > wait_confirm_idx;
      wait_confirm_idx wait_confirm_tbl;

      string join(vector <string> &&vec, string delim = string("*"));
      void to_rewards(const name& payer, const asset &quantity);
      void require_app_auth( const checksum256 &digest, const name &user,
                             const public_key &sign_pub_key, const signature &signature );

      template<class T>
      void boost_deferred_tx(const T& it, const action& acc, const public_key& device_key);
      void send_deferred_tx(const action &act, const uint32_t &delay, const uint128_t &id);

      void _addkey( const name& account, const public_key& device_key, const string& extra_key, const name& payer);

      void add_wait_action(const name &account, const name &action_account, const name &action_name,
                           const vector<char> action_data, const public_key &sign_pubkey, const time_point &ct);
      auto get_wait_action_it(const name &account, const name &action_account,
                              const name &action_name, const vector<char> &action_data);

      checksum256 sha256(const string &str) {
         return eosio::sha256(str.c_str(), str.size());
      }
   };
   /** @}*/ // end of @defgroup eosioauth rem.auth
} /// namespace eosio