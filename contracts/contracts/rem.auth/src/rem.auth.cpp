/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.auth/rem.auth.hpp>
#include <../../rem.swap/src/base58.cpp> // TODO: fix includes
#include <rem.system/rem.system.hpp>
#include <rem.token/rem.token.hpp>

namespace eosio {
   auth::auth(name receiver, name code,  datastream<const char*> ds)
   :contract(receiver, code, ds),
    authkeys_tbl(_self, _self.value),
    p_reward_table(_self, _self.value)
    {
       if ( !p_reward_table.exists() ) {
          p_reward_table.set(prodsreward{}, _self);
       }
       prods_reward = p_reward_table.get();
    };

   void auth::addkeyacc(const name &account, const string &key_str, const signature &signed_by_key,
                        const string &extra_key, const string &payer_str) {

      name payer = payer_str.empty() ? account : name(payer_str);
      require_auth(account);
      require_auth(payer);

      public_key key = string_to_public_key(key_str);
      checksum256 digest = sha256(join( { account.to_string(), key_str, extra_key, payer_str } ));
      eosio::assert_recover_key(digest, signed_by_key, key);

      _addkey(account, key, extra_key, payer);
   }

   auto auth::get_authkey_it(const name &account, const public_key &key) {
      auto authkeys_idx = authkeys_tbl.get_index<"byname"_n>();
      auto it = authkeys_idx.find(account.value);

      for(; it != authkeys_idx.end(); ++it) {
         auto ct = current_time_point();

         bool is_before_time_valid = ct > it->not_valid_before.to_time_point();
         bool is_after_time_valid = ct < it->not_valid_after.to_time_point();
         bool is_revoked = it->revoked_at;

         if (!is_before_time_valid || !is_after_time_valid || is_revoked) {
            continue;
         } else if (it->key == key) {
            break;
         }
      }
      return it;
   }

   void auth::addkeyapp(const name &account, const string &new_key_str, const signature &signed_by_new_key,
                        const string &extra_key, const string &key_str, const signature &signed_by_key,
                        const string &payer_str) {

      name payer = payer_str.empty() ? account : name(payer_str);
      checksum256 digest = sha256(join( { account.to_string(), new_key_str, extra_key, key_str, payer_str } ));

      public_key new_key = string_to_public_key(new_key_str);
      public_key key = string_to_public_key(key_str);
      check(assert_recover_key(digest, signed_by_new_key, new_key), "expected key different than recovered new key");
      check(assert_recover_key(digest, signed_by_key, key), "expected key different than recovered user key");
      require_app_auth(account, key);

      _addkey(account, new_key, extra_key, payer);
   }

   void auth::revokeacc(const name &account, const string &key_str) {
      require_auth(account);
      public_key key = string_to_public_key(key_str);
      _revoke(account, key);
   }

   void auth::revokeapp(const name &account, const string &key_str, const signature &signed_by_key) {
      public_key key = string_to_public_key(key_str);
      checksum256 digest = sha256(join( { account.to_string(), key_str } ));
      check(assert_recover_key(digest, signed_by_key, key), "expected key different than recovered user key");

      _revoke(account, key);
   }

   void auth::_revoke(const name &account, const public_key &key) {
      require_app_auth(account, key);

      auto it = get_authkey_it(account, key);

      time_point ct = current_time_point();
      authkeys_tbl.modify(*it, _self, [&](auto &r) {
         r.revoked_at = ct.sec_since_epoch();
      });
   }

   void auth::transfer(const name &from, const name &to, const asset &quantity,
                       const string &key_str, const signature &signed_by_key) {

      checksum256 digest = sha256(join( { from.to_string(), to.to_string(), quantity.to_string(), key_str } ));

      public_key key = string_to_public_key(key_str);
      require_app_auth(from, key);
      check(assert_recover_key(digest, signed_by_key, key), "expected key different than recovered user key");

      token::transfer_action transfer(system_token_account, {from, "active"_n});
      transfer.send(from, to, quantity, string("authentication app transfer"));
   }

   void auth::setbpreward(const asset &quantity) {
      require_auth( _self );
      check(quantity.symbol == core_symbol, "symbol precision mismatch");
      check(quantity.amount > 0, "amount must be a positive");

      p_reward_table.set(prodsreward{quantity}, _self);
   }

   void auth::_addkey(const name& account, const public_key& key,
                      const string& extra_key, const name& payer) {

      authkeys_tbl.emplace(_self, [&](auto &k) {
         k.N = authkeys_tbl.available_primary_key();
         k.owner = account;
         k.key = key;
         k.extra_key = extra_key;
         k.not_valid_before = current_time_point();
         k.not_valid_after = current_time_point() + key_lifetime;
         k.revoked_at = 0; // if not revoked == 0
      });
      to_rewards(payer, prods_reward.quantity);
   }

   void auth::require_app_auth(const name &account, const public_key &key) {
      auto authkeys_idx = authkeys_tbl.get_index<"byname"_n>();
      auto it = authkeys_idx.find(account.value);

      check(it != authkeys_idx.end(), "account has no linked app keys");

      it = get_authkey_it(account, key);
      check(it != authkeys_idx.end(), "account has no active app keys");
   }

   void auth::to_rewards(const name &payer, const asset &quantity) {
      eosiosystem::system_contract::torewards_action torewards(system_account, {payer, "active"_n});
      torewards.send(payer, quantity);
   }

   bool auth::assert_recover_key(const checksum256 &digest, const signature &sign, const public_key &key) {
      public_key expected_key = recover_key(digest, sign);
      return expected_key == key;
   }

   string auth::join( vector<string>&& vec, string delim ) {
      return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
                             [&delim](string& a, string& b) {
                                return a + delim + b;
                             });
   }

   void auth::cleartable( ) {
      require_auth(_self);
      for (auto _table_itr = authkeys_tbl.begin(); _table_itr != authkeys_tbl.end();) {
         _table_itr = authkeys_tbl.erase(_table_itr);
      }
   }
} /// namespace eosio

EOSIO_DISPATCH( eosio::auth, (addkeyacc)(addkeyapp)(revokeacc)(revokeapp)(transfer)(setbpreward)(cleartable) )
