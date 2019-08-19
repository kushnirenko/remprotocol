/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.swap/rem.swap.hpp>

#include "base58.cpp"
#include "system_info.cpp"

namespace eosio {

   void swap::init( const name& rampayer, const string& txid, const string& swap_pubkey,
                    const asset& quantity, const string& return_address, const string& return_chain_id,
                    const block_timestamp& swap_timestamp ) {
      require_auth( rampayer );

      const asset min_account_stake = get_min_account_stake();
      const asset producers_reward = get_producers_reward();

      check_pubkey_prefix( swap_pubkey );
      validate_address( return_address );
      validate_chain_id( return_chain_id );
      check( quantity.is_valid(), "invalid quantity" );
      check( quantity.symbol == min_account_stake.symbol, "symbol precision mismatch" );
      check( quantity.amount > min_account_stake.amount + producers_reward.amount, "the quantity must be greater "
                                                                                   "than the swap fee" );
      time_point swap_timepoint = swap_timestamp.to_time_point();

      string swap_payload = join( { swap_pubkey.substr(3), txid, remchain_id, quantity.to_string(), return_address,
                                    return_chain_id, std::to_string( swap_timepoint.sec_since_epoch() ) } );

      checksum256 swap_hash = sha256( swap_payload );

      auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
      auto swap_hash_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

      check( time_point_sec(current_time_point()) < swap_timepoint + swap_lifetime, "swap lifetime expired" );

      const bool is_producer = is_block_producer(rampayer);
      if ( swap_hash_itr == swap_hash_idx.end() ) {
         swap_table.emplace(rampayer, [&]( auto& s ) {
             s.key = swap_table.available_primary_key();
             s.txid = txid;
             s.swap_id = swap_hash;
             s.swap_timestamp = swap_timestamp;
             s.status = static_cast<int8_t>(swap_status::INITIALIZED);
             if(is_producer) s.provided_approvals.push_back( rampayer );
         });
      }
      else {
         check( is_producer, "block producer authorization required" );
         check( swap_hash_itr->status != static_cast<int8_t>(swap_status::CANCELED), "swap already canceled" );

         const vector<name>& approvals = swap_hash_itr->provided_approvals;
         bool is_already_approved = std::find( approvals.begin(), approvals.end(), rampayer ) == approvals.end();

         check ( is_already_approved, "approval already exists" );

         swap_table.modify( *swap_hash_itr, rampayer, [&]( auto& s ) {
             s.provided_approvals.push_back( rampayer );
         });

         update_swaps( rampayer, quantity );
      }
   }

   void swap::finish( const name& rampayer, const name& receiver, const string& txid, const string& swap_pubkey_str,
                      asset& quantity, const string& return_address, const string& return_chain_id,
                      const block_timestamp& swap_timestamp, const signature& sign ) {

      require_auth( rampayer );

      const checksum256 swap_hash = get_swap_id(
              txid, swap_pubkey_str, quantity, return_address,
              return_chain_id, swap_timestamp
      );

      const checksum256 digest = get_digest_msg(
              receiver, {}, {}, txid, quantity,
              return_address, return_chain_id, swap_timestamp
      );

      validate_pubkey( sign, digest, swap_pubkey_str );
      validate_swap( swap_hash );

      auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
      auto swap_hash_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

      const time_point swap_timepoint = swap_hash_itr->swap_timestamp.to_time_point();
      check( time_point_sec(current_time_point()) < swap_timepoint + swap_active_lifetime,
             "swap has to be canceled after expiration" );

      const asset producers_reward = get_producers_reward();
      quantity.amount -= producers_reward.amount;
      to_rewards( producers_reward );
      transfer( receiver, quantity );

      swap_table.modify( *swap_hash_itr, rampayer, [&]( auto& s ) {
          s.status = static_cast<int8_t>(swap_status::FINISHED);
      });
   }

   void swap::finishnewacc( const name& rampayer, const name& receiver, const string& owner_pubkey_str,
                            const string& active_pubkey_str, const string& txid, const string& swap_pubkey_str,
                            asset& quantity, const string& return_address, const string& return_chain_id,
                            const block_timestamp& swap_timestamp, const signature& sign )  {

      require_auth( rampayer );

      const checksum256 swap_hash = get_swap_id(
            txid, swap_pubkey_str, quantity, return_address,
            return_chain_id, swap_timestamp
      );

      const checksum256 digest = get_digest_msg(
            receiver, owner_pubkey_str, active_pubkey_str,
            txid, quantity, return_address,
            return_chain_id, swap_timestamp
      );

      validate_pubkey( sign, digest, swap_pubkey_str );
      validate_swap( swap_hash );

      auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
      auto swap_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

      public_key owner_key = string_to_public_key( owner_pubkey_str );
      public_key active_key = string_to_public_key( active_pubkey_str );
      const asset min_account_stake = get_min_account_stake();
      const asset producers_reward = get_producers_reward();

      quantity.amount -= (min_account_stake.amount + producers_reward.amount);
      to_rewards( producers_reward );
      create_user( receiver, owner_key, active_key, min_account_stake );

//        eosiosystem::system_contract::torewards_action torewards("rem.system"_n, { _self, "active"_n });
//        torewards.send( _self, min_account_stake );

      transfer( receiver, quantity );
      swap_table.modify( *swap_itr, rampayer, [&]( auto& s ) {
          s.status = static_cast<int8_t>(swap_status::FINISHED);
      });
   }

   void swap::cancel( const name& rampayer, const string& txid, const string& swap_pubkey_str,
                      asset& quantity, const string& return_address, const string& return_chain_id,
                      const block_timestamp& swap_timestamp ) {

      require_auth( rampayer );
      time_point swap_timepoint = swap_timestamp.to_time_point();

      const checksum256 swap_hash = get_swap_id(
              txid, swap_pubkey_str, quantity, return_address,
              return_chain_id, swap_timestamp
      );

      auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
      auto swap_hash_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

      validate_swap( swap_hash );
      check( time_point_sec(current_time_point()) > swap_timepoint + swap_active_lifetime,
             "swap has to be canceled after expiration" );

      const asset producers_reward = get_producers_reward();
      quantity.amount -= producers_reward.amount;

      string retire_memo = return_chain_id + ' ' + return_address;
      to_rewards( producers_reward );
      retire_tokens( quantity, retire_memo );
      require_recipient(_self);

      swap_table.modify( *swap_hash_itr, rampayer, [&]( auto& s ) {
          s.status = static_cast<int8_t>(swap_status::CANCELED);
      });
   }

   void swap::setbpreward( const name& rampayer, const asset& quantity ) {
//      require_auth( _self );
      check( quantity.symbol == core_symbol, "symbol precision mismatch" );
      check( quantity.amount > 0, "amount must be a positive" );

      p_reward p_reward_tbl( _self, _self.value );
      p_reward_tbl.set(prodsreward{quantity}, rampayer);
   }

   checksum256 swap::get_swap_id( const string& txid, const string& swap_pubkey_str, const asset& quantity,
                                  const string& return_address, const string& return_chain_id,
                                  const block_timestamp& swap_timestamp ) {

      time_point swap_timepoint = swap_timestamp.to_time_point();

      string swap_payload = join( { swap_pubkey_str.substr(3), txid, remchain_id, quantity.to_string(), return_address,
                                    return_chain_id, std::to_string( swap_timepoint.sec_since_epoch() ) } );

      checksum256 swap_hash = sha256( swap_payload );
      return swap_hash;
   }

   checksum256 swap::get_digest_msg( const name& receiver, const string& owner_key, const string& active_key,
                                     const string& txid, const asset& quantity, const string& return_address,
                                     const string& return_chain_id, const block_timestamp& swap_timestamp ) {

      time_point swap_timepoint = swap_timestamp.to_time_point();

      string payload = join( { txid, remchain_id, quantity.to_string(), return_address,
                               return_chain_id, std::to_string( swap_timepoint.sec_since_epoch() ) } );

      string sign_payload = (owner_key.size() == 0) ? join({ receiver.to_string(), payload }) :
                                                      join({ receiver.to_string(), owner_key, active_key, payload });

      checksum256 digest = sha256( sign_payload );
      return digest;
   }

   void swap::validate_pubkey( const signature& sign, const checksum256& digest, const string& swap_pubkey_str ) {
      public_key swap_pubkey = string_to_public_key( swap_pubkey_str );
      assert_recover_key(digest, sign, swap_pubkey);
   }

   void swap::validate_swap( const checksum256& swap_hash ) {

      auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
      auto swap_hash_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

      check( swap_hash_itr != swap_hash_idx.end(), "swap doesn't exist" );
      check( swap_hash_itr->status != static_cast<int8_t>(swap_status::CANCELED), "swap already canceled" );
      check( swap_hash_itr->status != static_cast<int8_t>(swap_status::FINISHED), "swap already finished" );

      const time_point swap_timepoint = swap_hash_itr->swap_timestamp.to_time_point();
      check( time_point_sec(current_time_point()) < swap_timepoint + swap_lifetime, "swap lifetime expired" );
      check( is_swap_confirmed( swap_hash_itr->provided_approvals ), "not enough active producers approvals" );
   }

   void swap::validate_chain_id( string chain_id ) {
      std::transform( chain_id.begin(), chain_id.end(), chain_id.begin(), ::tolower);
      if ( chain_id != ethchain_id ) {
         check(false, "not supported chain id");
      }
   }

   void swap::validate_address( const string& address ) {
      for (const auto& ch: address) {
         // if not symbol, digit or ':' or '.' - not supported address
         if (!(ch == '.' || ch == ':' || std::isalpha(ch) || std::isdigit(ch))) {
            check(false, "not supported address");
         }
      }
   }

   void swap::update_swaps( const name& rampayer, const asset& quantity ) {
      for ( auto _table_itr = swap_table.begin(); _table_itr != swap_table.end(); ) {

         bool is_status_init = _table_itr->status == static_cast<int8_t>(swap_status::INITIALIZED);
         time_point swap_timepoint = _table_itr->swap_timestamp.to_time_point();
         if ( time_point_sec(current_time_point()) > swap_timepoint + swap_lifetime ) {
            _table_itr = swap_table.erase(_table_itr);

         } else if ( is_swap_confirmed( _table_itr->provided_approvals ) && is_status_init ) {
            issue_tokens( quantity );
            swap_table.modify( *_table_itr, rampayer, [&]( auto& s ) {
                s.status = static_cast<int8_t>(swap_status::ISSUED);
            });

         } else { ++_table_itr; }
      }
   }

   void swap::ontransfer(name from, name to, asset quantity, string memo) {
      if (to != _self || from == _self)
      {
         return;
      }
      const asset producers_reward = get_producers_reward();
      check(quantity.symbol == producers_reward.symbol, "symbol precision mismatch");
      check(quantity.amount > producers_reward.amount, "the quantity must be greater than the swap fee");
      auto space_pos = memo.find(' ');
      check( (space_pos != string::npos), "invalid memo" );

      string return_chain_id = memo.substr( 0, space_pos );
      check( return_chain_id.size() > 0, "wrong chain id" );
      validate_chain_id( return_chain_id );

      string return_address = memo.substr( space_pos + 1 );
      check( return_address.size() > 0, "wrong address" );
      validate_address( return_address );

      quantity.amount -= producers_reward.amount;

      string retire_memo = return_chain_id + ' ' + return_address;
      to_rewards( producers_reward );
      retire_tokens( quantity, retire_memo );
      require_recipient(_self);
   }

   void swap::transfer( const name& receiver, const asset& quantity) {
      action(
              permission_level{ _self, "active"_n },
              system_token_account, "transfer"_n,
              std::make_tuple( _self, receiver, quantity, string("atomic-swap") )
      ).send();
   }

   void swap::create_user( const name& user, const public_key& owner_key,
                           const public_key& active_key, const asset& min_account_stake ) {

      const key_weight owner_pubkey_weight{
            .key = owner_key,
            .weight = 1,
      };
      const key_weight active_pubkey_weight{
            .key = active_key,
            .weight = 1,
      };
      const authority owner{
            .threshold = 1,
            .keys = {owner_pubkey_weight},
            .accounts = {},
            .waits = {}
      };
      const authority active{
            .threshold = 1,
            .keys = {active_pubkey_weight},
            .accounts = {},
            .waits = {}
      };
      const newaccount new_account{
            .creator = _self,
            .name = user,
            .owner = owner,
            .active = active
      };

      action(
            permission_level{ _self, "active"_n, },
            system_account,
            "newaccount"_n,
            new_account
      ).send();

      action(
            permission_level{ _self, "active"_n},
            system_account,
            "delegatebw"_n,
            std::make_tuple(_self, user, min_account_stake, true)
      ).send();
   }

   void swap::to_rewards( const asset& quantity ) {
      action(
            permission_level{ _self, "active"_n },
            system_account, "torewards"_n,
            std::make_tuple( _self, quantity )
      ).send();
   }

   void swap::retire_tokens( const asset& quantity, const string& memo ) {
      action(
            permission_level{ _self, "active"_n },
            system_token_account, "retire"_n,
            std::make_tuple( quantity, memo )
      ).send();
   }

   void swap::issue_tokens( const asset& quantity ) {
      action(
            permission_level{ _self, "active"_n },
            system_token_account, "issue"_n,
            std::make_tuple( _self, quantity, string("swap issue tokens") )
      ).send();
   }
} /// namespace eosio
