/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.swap/rem.swap.hpp>

#include "base58.cpp"
#include "system_info.cpp"

namespace eosio {

    void swap::init( const name& rampayer, const string& txid, string& swap_pubkey,
                     const asset& quantity, const string& return_address, const string& return_chain_id,
                     const block_timestamp& swap_timestamp ) {

        require_auth( rampayer );

        const asset min_account_stake = get_min_account_stake();
        asset producers_reward = get_producers_reward();

        check_pubkey_pre( swap_pubkey );
        check( quantity.is_valid(), "invalid quantity" );
        check( quantity.symbol == min_account_stake.symbol, "symbol precision mismatch" );
        check( quantity.amount > min_account_stake.amount + producers_reward.amount, "the quantity must be greater "
                                                                                      "than the swap fee" );

        swap_pubkey = string( swap_pubkey.begin() + 3, swap_pubkey.end() );
        const time_point swap_timepoint = swap_timestamp.to_time_point();

        string swap_payload = join( { swap_pubkey, txid, remchain_id, quantity.to_string(), return_address,
                                      return_chain_id, std::to_string( swap_timepoint.sec_since_epoch() ) } );

        checksum256 swap_hash = hash( swap_payload );
        swap_index swap_table( _self, get_first_receiver().value );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );
        auto level = permission_level( rampayer, "active"_n );

        check( time_point_sec(current_time_point()) < swap_timepoint + swap_lifetime, "swap lifetime expired" );

        const bool is_producer = is_block_producer(rampayer);
        if ( swap_hash_itr == swap_hash_idx.end() ) {
            swap_table.emplace(rampayer, [&]( auto& s ) {
                s.key = swap_table.available_primary_key();
                s.txid = txid;
                s.swap_id = swap_hash;
                s.swap_timestamp = swap_timestamp;
                s.status = static_cast<int8_t>(swap_status::INITIALIZED);
                is_producer ? s.provided_approvals.push_back( level ) : void();
            });
        }
        else {
            check( is_producer, "authorization error" );
            check( swap_hash_itr->status != static_cast<int8_t>(swap_status::CANCELED), "swap already canceled" );

            const std::vector<permission_level>& approvals = swap_hash_itr->provided_approvals;
            bool is_already_approved = std::find_if(
                    approvals.begin(), approvals.end(), [&](const permission_level& l) { return l == level; }
                    ) == approvals.end();

            check ( is_already_approved, "approval already exist" );

            swap_table.modify( *swap_hash_itr, rampayer, [&]( auto& s ) {
                s.provided_approvals.push_back( level );
            });

            update_swaps( rampayer, quantity );
        }
    }

    // Debug function
    void swap::cleartable( const name& user ) {
        require_auth( user );

        swap_index swap_table( _self, get_first_receiver().value );

        for (auto _table_itr = swap_table.begin(); _table_itr != swap_table.end();) {
            _table_itr = swap_table.erase(_table_itr);
        }
    }

    void swap::finish( const name& rampayer, const name& receiver, const string& txid,
                       string& swap_pubkey_str, asset& quantity, const string& return_address,
                       const string& return_chain_id, const block_timestamp& swap_timestamp, const signature& sign ) {

        require_auth( rampayer );

        const checksum256 swap_hash = _get_swap_id(
                rampayer, receiver, txid, swap_pubkey_str,
                quantity, return_address, return_chain_id,
                swap_timestamp, sign, {}, {}
        );

        validate_swap( swap_hash );

        swap_index swap_table( _self, get_first_receiver().value );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

        const time_point swap_timepoint = swap_hash_itr->swap_timestamp.to_time_point();
        check( time_point_sec(current_time_point()) < swap_timepoint + swap_active_lifetime,
               "active swap lifetime expired, cancel swap, please" );

        const asset producers_reward = get_producers_reward();
        quantity.amount -= producers_reward.amount;
        to_rewards( producers_reward );
        _transfer( receiver, quantity );

        swap_table.modify( *swap_hash_itr, rampayer, [&]( auto& s ) {
            s.status = static_cast<int8_t>(swap_status::FINISHED);
        });
    }

    void swap::finishnewacc( const name& rampayer, const name& receiver, const string& owner_pubkey_str,
                             const string& active_pubkey_str, const string& txid, string& swap_pubkey_str,
                             asset& quantity, const string& return_address, const string& return_chain_id,
                             const block_timestamp& swap_timestamp, const signature& sign )  {

        require_auth( rampayer );

        const checksum256 swap_hash = _get_swap_id(
                rampayer, receiver, txid, swap_pubkey_str,
                quantity, return_address, return_chain_id,
                swap_timestamp, sign, owner_pubkey_str, active_pubkey_str
        );

        validate_swap( swap_hash );

        swap_index swap_table( _self, get_first_receiver().value );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

        public_key owner_key = string_to_public_key( owner_pubkey_str );
        public_key active_key = string_to_public_key( active_pubkey_str );
        const asset min_account_stake = get_min_account_stake();
        const asset producers_reward = get_producers_reward();

        quantity.amount -= (min_account_stake.amount + producers_reward.amount);
        to_rewards( producers_reward );
        create_user( receiver, owner_key, active_key, min_account_stake );

//        eosiosystem::system_contract::torewards_action torewards("rem.system"_n, { get_self(), "active"_n });
//        torewards.send( _self, min_account_stake );

        _transfer( receiver, quantity );
        swap_table.modify( *swap_itr, rampayer, [&]( auto& s ) {
            s.status = static_cast<int8_t>(swap_status::FINISHED);
        });
    }

    void swap::cancel( const name& rampayer, const string& txid, const string& swap_pubkey,
                       asset& quantity, const string& return_address, const string& return_chain_id,
                       const block_timestamp& swap_timestamp ) {

        require_auth( rampayer );
        const time_point swap_timepoint = swap_timestamp.to_time_point();

        string swap_payload = join( { swap_pubkey, txid, remchain_id, quantity.to_string(), return_address,
                                      return_chain_id, std::to_string( swap_timepoint.sec_since_epoch() ) } );

        checksum256 swap_hash = hash( swap_payload );
        swap_index swap_table( _self, get_first_receiver().value );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

        validate_swap( swap_hash );
        check( time_point_sec(current_time_point()) > swap_timepoint + swap_active_lifetime,
               "active swap lifetime not expired, wait one week" );

        const asset producers_reward = get_producers_reward();
        quantity.amount -= producers_reward.amount;

        to_rewards( producers_reward );
        _retire_tokens( quantity );

        swap_table.modify( *swap_hash_itr, rampayer, [&]( auto& s ) {
            s.status = static_cast<int8_t>(swap_status::CANCELED);
        });
    }

    void swap::setbprewards( const name& rampayer, const asset& quantity ) {
        auto level = permission_level( "rem.prods"_n, "active"_n );
        require_auth( level );
        check( quantity.symbol == core_symbol, "symbol precision mismatch" );
        check( quantity.amount > 0, "amount must be a positive" );

        swapfee_index swap_fee_table( _self, get_first_receiver().value );
        swap_fee_table.set(swapfee{quantity}, rampayer);
    }

    checksum256 swap::_get_swap_id( const name& rampayer, const name& receiver, const string& txid,
                                    string& swap_pubkey_str, asset& quantity, const string& return_address,
                                    const string& return_chain_id, const block_timestamp& swap_timestamp,
                                    const signature& sign, const string owner_key, const string active_key ) {

        const time_point swap_timepoint = swap_timestamp.to_time_point();

        string payload = join( { txid, remchain_id, quantity.to_string(), return_address,
                                 return_chain_id, std::to_string( swap_timepoint.sec_since_epoch() ) } );

        string sign_payload = (owner_key.size() == 0) ? join({ receiver.to_string(), payload }) :
                                                        join({ receiver.to_string(), owner_key, active_key, payload });

        public_key swap_pubkey = string_to_public_key( swap_pubkey_str );
        checksum256 digest = hash( sign_payload );
        assert_recover_key(digest, sign, swap_pubkey);

        swap_pubkey_str = string( swap_pubkey_str.begin() + 3, swap_pubkey_str.end() );
        string swap_payload = join({ swap_pubkey_str, payload });
        const checksum256 swap_hash = hash( swap_payload );
        return swap_hash;
    }

    void swap::validate_swap( const checksum256& swap_hash ) {

        swap_index swap_table( _self, get_first_receiver().value );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_data::get_swap_hash(swap_hash) );

        check( swap_hash_itr != swap_hash_idx.end(), "swap doesn't exist" );
        check( swap_hash_itr->status != static_cast<int8_t>(swap_status::CANCELED), "swap already canceled" );
        check( swap_hash_itr->status != static_cast<int8_t>(swap_status::FINISHED), "swap already finished" );

        const time_point swap_timepoint = swap_hash_itr->swap_timestamp.to_time_point();
        check( time_point_sec(current_time_point()) < swap_timepoint + swap_lifetime, "swap lifetime expired" );
//        check( is_swap_confirmed( swap_hash_itr->provided_approvals ), "not enough active approvals" );
    }

    void swap::update_swaps( const name& rampayer, const asset& quantity ) {
        swap_index swap_table( _self, get_first_receiver().value );
        for ( auto _table_itr = swap_table.begin(); _table_itr != swap_table.end(); ) {

            bool is_status_init = _table_itr->status == static_cast<int8_t>(swap_status::INITIALIZED);
            time_point swap_timepoint = _table_itr->swap_timestamp.to_time_point();
            if ( time_point_sec(current_time_point()) > swap_timepoint + swap_lifetime ) {
                _table_itr = swap_table.erase(_table_itr);

            } else if ( is_swap_confirmed( _table_itr->provided_approvals ) && is_status_init ) {
                _issue_tokens( quantity );
                swap_table.modify( *_table_itr, rampayer, [&]( auto& s ) {
                    s.status = static_cast<int8_t>(swap_status::ISSUED);
                });

            } else { ++_table_itr; }
        }
    }

    [[eosio::on_notify("rem.token::transfer")]]
    void swap::ontransfer(name from, name to, asset quantity, string memo) {
        if (to != get_self() || from == get_self())
        {
            return;
        }
        const asset producers_reward = get_producers_reward();
        check(quantity.symbol == producers_reward.symbol, "symbol precision mismatch");
        check(quantity.amount > producers_reward.amount, "the quantity must be greater than the swap fee");
        auto space_pos = memo.find(' ');
        check( (space_pos != string::npos), "not valid memo" );

        string return_chain_id = memo.substr( space_pos + 1 );
        check( return_chain_id.size() > 0, "wrong chain id" );
        string return_address = memo.substr( 0, space_pos );
        check( return_address.size() > 0, "wrong address" );

        quantity.amount -= producers_reward.amount;

        to_rewards( producers_reward );
        _retire_tokens( quantity );
    }

    void swap::_transfer( const name& receiver, const asset& quantity) {
        action(
                permission_level{ get_self(), "active"_n },
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
                permission_level{ get_self(), "active"_n },
                system_account, "torewards"_n,
                std::make_tuple( _self, quantity )
        ).send();
    }

    void swap::_retire_tokens( const asset& quantity ) {
        action(
                permission_level{ _self, "active"_n },
                system_token_account, "retire"_n,
                std::make_tuple( quantity, string("swap retire tokens") )
        ).send();
    }

    void swap::_issue_tokens( const asset& quantity ) {
        action(
                permission_level{ _self, "active"_n },
                system_token_account, "issue"_n,
                std::make_tuple( _self, quantity, string("swap issue tokens") )
        ).send();
    }
} /// namespace eosio
