/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.swap/rem.swap.hpp>

namespace eosio {

    void swap::init( const name& user, public_key swap_key, const string& trx_id,
                     asset& quantity, const time_point& swap_init_time ) {

        require_auth( user );
        swap_index swap_table( _self, get_first_receiver().value );

        check( quantity.is_valid(), "invalid quantity" );
        check( quantity.symbol == create_account_fee.symbol, "symbol precision mismatch" );
        check( quantity.amount > create_account_fee.amount, "the quantity must be greater "
                                                            "than the account creation fee" );

        uint32_t timepoint = swap_init_time.sec_since_epoch();

        std::vector<char> swap_payload( swap_key.data.begin(), swap_key.data.end() );
        string payload_str = trx_id + quantity.to_string() + std::to_string(timepoint);
        std::copy( payload_str.begin(), payload_str.end(), back_inserter(swap_payload));

        checksum256 swap_hash = hash( swap_payload.data() );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_hash );
        auto level = permission_level( user, "active"_n );

        check( time_point_sec(current_time_point()) < swap_init_time + swap_lifetime, "swap life time expired" );
        clearnup_expired_swaps();
        if ( swap_hash_itr == swap_hash_idx.end() ) {
            swap_table.emplace(user, [&]( auto& s ) {
                s.key = swap_table.available_primary_key();
                s.trx_id = trx_id;
                s.swap_hash = swap_hash;
                s.swap_init_time = swap_init_time;
                s.timepoint = timepoint;
                s.status = static_cast<uint8_t>(swap_status::INIT);
            });

//            if ( is_block_producer(user) ) {
//                swap_table.modify( *swap_hash_itr, user, [&]( auto& s ) {
//                    s.provided_approvals.push_back( approval{ level, current_time_point() } );
//                });
//            }
        }
        else {
//        check( is_block_producer(user), "authorization error" );
            check( swap_hash_itr->status != static_cast<uint8_t>(swap_status::FINISH), "swap already finished" );

            const std::vector<approval>& approvals = swap_hash_itr->provided_approvals;
            bool is_already_approval = std::find_if( approvals.begin(),
                                                     approvals.end(),
                                                     [&](const approval& a)
                                                     { return a.level == level; }
                                                     ) == approvals.end();

            check ( is_already_approval, "approval already exist" );

            swap_table.modify( *swap_hash_itr, user, [&]( auto& s ) {
                s.provided_approvals.push_back( approval{ level, current_time_point() } );
            });
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

    void swap::finish( const name& user, const name& receiver, const string& trx_id,
                       asset& quantity, const signature& sign, const time_point& swap_init_time ) {

        const checksum256 swap_hash = _get_swap_id(
                user, receiver,
                trx_id, quantity,
                sign, swap_init_time, {}
        );
        swap_index swap_table( _self, get_first_receiver().value );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_itr = swap_hash_idx.find( swap_hash );

        _transfer( receiver, quantity );
        swap_table.modify( *swap_itr, user, [&]( auto& s ) {
            s.status = static_cast<uint8_t>(swap_status::FINISH);
        });

    }

    void swap::finishnewacc( const name& user, const name& receiver, const string& trx_id,
                              asset& quantity, const signature& sign, const time_point& swap_init_time,
                              const public_key owner_key, const public_key active_key                   )  {

        const checksum256 swap_hash = _get_swap_id(
                user, receiver, trx_id, quantity,
                sign, swap_init_time, owner_key
        );
        swap_index swap_table( _self, get_first_receiver().value );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_itr = swap_hash_idx.find( swap_hash );

        create_user( receiver, owner_key, active_key );
        quantity.amount = quantity.amount - create_account_fee.amount;

        _transfer( receiver, quantity );
        swap_table.modify( *swap_itr, user, [&]( auto& s ) {
            s.status = static_cast<uint8_t>(swap_status::FINISH);
        });
    }

    checksum256 swap::_get_swap_id( const name& user, const name& receiver, const string& trx_id,
                                    asset& quantity, const signature& sign, const time_point& swap_init_time,
                                    const public_key  owner_key                                               ) {

        require_auth( user );
        swap_index swap_table( _self, get_first_receiver().value );

        std::vector<char> sing_payload;
        // if first byte of owner_key is '\0', key is empty
        if ( owner_key.data[0] != '\0'){
            std::copy(owner_key.data.begin(), owner_key.data.end(), back_inserter(sing_payload));
        }
        std::copy( receiver.to_string().begin(), receiver.to_string().end(), back_inserter(sing_payload));
        checksum256 digest = hash( sing_payload.data() );
        public_key swap_key = recover_key( digest, sign );

        const auto timepoint = swap_init_time.sec_since_epoch();

        std::vector<char> swap_payload( swap_key.data.begin(), swap_key.data.end() );

        string payload_str = trx_id + quantity.to_string() + std::to_string(timepoint);
        std::copy( payload_str.begin(), payload_str.end(), back_inserter(swap_payload));
        const checksum256 swap_hash = hash( swap_payload.data() );

        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_hash );

        check( swap_hash_itr != swap_hash_idx.end(), "swap doesn't exist" );
        check( swap_hash_itr->status != static_cast<uint8_t>(swap_status::FINISH), "swap already finished" );
        check( time_point_sec(current_time_point()) < swap_hash_itr->swap_init_time + swap_lifetime,
               "swap life time expired" );
//    check( swap_hash_itr->provided_approvals.size() < 15, "not enough approvals" );

        return swap_hash;
    }

    void swap::clearnup_expired_swaps() {
        swap_index swap_table( _self, get_first_receiver().value );

        for ( auto _table_itr = swap_table.begin(); _table_itr != swap_table.end();) {

            if ( time_point_sec(current_time_point()) > _table_itr->swap_init_time + swap_lifetime ) {
                auto _current_itr = _table_itr;
                _table_itr = swap_table.erase(_current_itr);
//                swap_table.erase( _current_itr );
//                increment_counter( _table_itr->swap_init_time, "erase")

            } else {
                _table_itr = next(_table_itr);
            }
        }
    }

    [[eosio::on_notify("eosio.token::transfer")]]
    void swap::initerc(name from, name to, asset quantity, string memo) {
        check(from == get_self() || to != get_self(), "not valid sender");
        check(quantity.symbol == create_account_fee.symbol, "not valid symbol");
        check(quantity.amount > create_account_fee.amount, "the quantity must be greater than the "
                                                           "transfer ETH fee");
        auto space_pos = memo.find(' ');
        check( (space_pos != string::npos), "not valid memo" );

        string eth_address = memo.substr( space_pos + 1 );
        string chain_id = memo.substr( 0, space_pos );
//        check(chain_id == eth_chain_id, "not correct chainID");
        check(eth_address.size() == 42 || eth_address.size() == 40, "not correct Ethereum address");

        erc20_swap_index swap_table( _self, get_first_receiver().value );
        swap_table.emplace(from, [&]( auto& s ) {
            s.key = swap_table.available_primary_key();
            s.user = from;
            s.eth_address = eth_address;
            s.swap_init_time = current_time_point();
            s.amount = quantity;
        });

    }

    void swap::_transfer( const name& receiver, const asset& quantity) {
//        swap_index swap_table( _self, get_first_receiver().value );
        action(
                permission_level{ get_self(), "active"_n },
                "eosio.token"_n, "transfer"_n,
                std::make_tuple( _self, receiver, quantity, string("atomic-swap") )
        ).send();
    }

    void swap::create_user( const name& user,
                             public_key owner_key,
                             public_key active_key ) {

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
                "eosio"_n,
                "newaccount"_n,
                new_account
        ).send();
    }

} /// namespace eosio

EOSIO_DISPATCH( eosio::swap,
                // rem.swap.cpp
                (init)(cleartable)(finish)(finishnewacc)(initerc)
)
