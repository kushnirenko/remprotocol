/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.auth/rem.auth.hpp>
#include <rem.system/rem.system.hpp>
#include <rem.token/rem.token.hpp>

namespace eosio {
   auth::auth(name receiver, name code,  datastream<const char*> ds): contract(receiver, code, ds),
                                                                      authkeys_tbl(_self, _self.value),
                                                                      wait_confirm_tbl(_self, _self.value) {};

   void auth::addkey(const name& account, const public_key& device_key, const signature& sign_device_key,
                     const string& extra_key, const string& payer_str) {
      require_auth(account);
      name payer = payer_str.empty() ? account : name(payer_str);

      checksum256 digest = sha256(join( { account.to_string(), string(device_key.data.begin(),
                                          device_key.data.end()), extra_key, payer_str } ));
//      assert_recover_key(digest, sign_device_key, device_key);

      _addkey(account, device_key, extra_key, payer);
   }

   auto auth::get_wait_action_it(const name& account, const name& action_account, const name& action_name,
                                 const vector<char>& action_data) {
      auto wait_idx = wait_confirm_tbl.get_index<"byname"_n>();
      auto it = wait_idx.find(account.value);
      if (it == wait_idx.end()) { return it; }

      auto ct = current_time_point();
      for (; it != wait_idx.end(); ++it) {
         bool is_executed = ct > it->wait_time;
         bool is_equal_action_acc = it->action_account != action_account;
         bool is_equal_action_name = it->action_name != action_name;

         if (  is_executed || is_equal_action_acc || is_equal_action_name ) {
            continue;
         } else if (it->action_data == action_data) {
            break;
         }
      }
      return it;
   }

   void auth::appaddkey( const name& account, const public_key& toadd_key, const signature& sign_toadd_key,
                         const string& extra_key, const public_key& device_key, const signature& sign_device_key,
                         const string& payer_str ) {

      auto wait_idx = wait_confirm_tbl.get_index<"byname"_n>();
      checksum256 digest = sha256(join( { account.to_string(), string(toadd_key.data.begin(), toadd_key.data.end()),
                                          string(device_key.data.begin(), device_key.data.end()), extra_key,
                                          payer_str } ));
//      name payer = payer_str.empty() ? account : name(payer_str); // TODO: uncomment this when set privilege to acc
      name payer = _self; // TODO: delete this when acc will be privilege
      require_app_auth(digest, account, device_key, sign_device_key);
//      assert_recover_key(digest, sign_toadd_key, toadd_key);

      addkeywrap_action addkeywrap(_self, { _self, "active"_n });
      action addkey_action = addkeywrap.to_action(account, toadd_key, extra_key, payer);
      auto it = get_wait_action_it(account, _self, "addkeywrap"_n, addkey_action.data);

      if (it != wait_idx.end()) {
         boost_deferred_tx(it, addkey_action, device_key);
      } else {
         const time_point ct = current_time_point();
         add_wait_action(account, _self, "addkeywrap"_n, addkey_action.data, device_key, ct);
         send_deffered_tx(addkey_action, wait_confirm_sec, ct.sec_since_epoch() + account.value);
      }
   }

   template<class iter>
   void auth::boost_deferred_tx(const iter& it, const action& acc, const public_key& device_key) {
      bool is_already_approved = std::find( it->provided_approvals.begin(),
                                            it->provided_approvals.end(), device_key
                                            ) == it->provided_approvals.end();
      check(is_already_approved, "approval already exists");

      const time_point ct = current_time_point();
      uint32_t delta = it->wait_time.to_time_point().sec_since_epoch() - ct.sec_since_epoch();
      check(delta >= 0, "action already executed");

      print(delta / (it->provided_approvals.size() + 1));
      uint32_t wait_sec = delta / (it->provided_approvals.size() + 1);
      time_point wait_time = time_point(seconds(wait_sec));

      wait_confirm_tbl.modify(*it, _self, [&](auto &w) { // TODO: move _self to it->owner
         w.provided_approvals.push_back(device_key);
         w.wait_time = it->init_time.to_time_point() + wait_time;
      });

      uint128_t deferred_tx_id = it->init_time.to_time_point().sec_since_epoch() + it->owner.value;
      cancel_deferred(deferred_tx_id);
      send_deffered_tx(acc, wait_sec, deferred_tx_id);
   }

   void auth::addkeywrap( const name& account, const public_key& device_key,
                             const string& extra_key, const name& payer       ) {
      require_auth(_self);
      _addkey(account, device_key, extra_key, payer);
   }

   void auth::_addkey( const name& account, const public_key& device_key,
                       const string& extra_key, const name& payer        ) {

      authkeys_tbl.emplace(payer, [&](auto &k) {
         k.key = authkeys_tbl.available_primary_key();
         k.owner = account;
         k.device_key = device_key;
         k.app_key = extra_key;
         k.not_valid_before = current_time_point();
         k.not_valid_after = current_time_point() + key_lifetime;
         k.revoked_at = 0; // if not revoked == 0
      });
//      to_rewards(prods_reward, payer);
   }

   void auth::transfer( const name& from, const name& to, const asset& quantity,
                        const public_key& device_key, const signature& sign_device_key ) {

      auto wait_idx = wait_confirm_tbl.get_index<"byname"_n>();
      checksum256 digest = sha256(join( { from.to_string(), to.to_string(), quantity.to_string(),
                                          string(device_key.data.begin(), device_key.data.end()) } ));

      require_app_auth(digest, from, device_key, sign_device_key);

      token::transfer_action transfer(system_token_account, {from, "active"_n});
      action transfer_action = transfer.to_action(from, to, quantity, string("auth_app transfer"));
      auto it = get_wait_action_it(from, system_token_account, "transfer"_n, transfer_action.data);
      if (it != wait_idx.end()) {
         boost_deferred_tx(it, transfer_action, device_key);
      } else {
         const time_point ct = current_time_point();
         add_wait_action(from, system_token_account, "transfer"_n, transfer_action.data, device_key, ct);
         send_deffered_tx(transfer_action, wait_confirm_sec, ct.sec_since_epoch() + from.value);
      }
   }


   void auth::require_app_auth( const checksum256& digest,           const name& user,
                                const public_key& sign_pub_key, const signature& signature ) {

      auto authkeys_idx = authkeys_tbl.get_index<"byname"_n>();
      auto it = authkeys_idx.find(user.value);

      check(it != authkeys_idx.end(), "account has no linked app keys");

      for(; it != authkeys_idx.end(); ++it) {
         auto ct = current_time_point();

         bool is_before_time_valid = ct < it->not_valid_before.to_time_point();
         bool is_after_time_valid = ct < it->not_valid_before.to_time_point();
         bool is_revoked = it->revoked_at && it->revoked_at < ct.sec_since_epoch();

         if ( is_before_time_valid || is_after_time_valid || is_revoked) {
            continue;
         } else if (it->device_key == sign_pub_key) {
            break;
         }
      }
      check(it != authkeys_idx.end(), "account has no active app keys");
//      assert_recover_key(digest, signature, sign_pub_key);
   }

   void auth::send_deffered_tx( const action& act, const uint32_t& delay, const uint128_t& id ) {
      transaction t;
      t.actions.emplace_back(act);
      t.delay_sec = delay;
      t.send(id, _self);
   }

   void auth::add_wait_action( const name& account, const name& action_account, const name& action_name,
                               const vector<char> action_data, const public_key& sign_pubkey, const time_point& ct ) {
      wait_confirm_tbl.emplace(_self, [&](auto &w) { // TODO: MOVE _SELF TO ACCOUNT
         w.key = wait_confirm_tbl.available_primary_key();
         w.owner = account;
         w.init_time = ct;
         w.wait_time = ct + wait_confirm_time;
         w.action_account = action_account;
         w.action_name = action_name;
         w.action_data = action_data;
         w.provided_approvals.push_back(sign_pubkey);
      });
   }

   void auth::to_rewards(const asset &quantity, const name& payer) {
      eosiosystem::system_contract::torewards_action torewards(system_account, {payer, "active"_n});
      torewards.send(payer, quantity);
   }

   string auth::join( vector<string>&& vec, string delim ) {
      return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
                             [&delim](string& a, string& b) {
                                return a + delim + b;
                             });
   }

   void auth::cleartable( ) {

      for (auto _table_itr = wait_confirm_tbl.begin(); _table_itr != wait_confirm_tbl.end();) {
         _table_itr = wait_confirm_tbl.erase(_table_itr);
      }
   }
} /// namespace eosio

EOSIO_DISPATCH( eosio::auth, (addkey)(cleartable)(appaddkey)(addkeywrap)(transfer) )
