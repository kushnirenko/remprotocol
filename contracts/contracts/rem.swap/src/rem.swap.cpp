/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.swap/rem.swap.hpp>

namespace eosio {

    void swap::init( const name& user, const public_key& swap_key, const string& trx_id,
                     const string& chain_id, const string eth_address, const asset& quantity,
                     const uint32_t& swap_init_time ) {

        require_auth( user );
        swap_index swap_table( _self, get_first_receiver().value );

        check( quantity.is_valid(), "invalid quantity" );
        check( chain_id == remchain_id, "not correct chainID" );
        check( quantity.symbol == create_account_fee.symbol, "symbol precision mismatch" );
        check( quantity.amount > create_account_fee.amount, "the quantity must be greater "
                                                            "than the account creation fee" );

        const time_point swap_init_timepoint = time_point(seconds(swap_init_time));

        std::vector<char> swap_payload( swap_key.data.begin(), swap_key.data.end() );
        string payload_str = trx_id + chain_id + eth_address + quantity.to_string()
                             + std::to_string( swap_init_timepoint.sec_since_epoch() );
        std::copy( payload_str.begin(), payload_str.end(), back_inserter(swap_payload));

        checksum256 swap_hash = hash( swap_payload.data() );
        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_hash );
        auto level = permission_level( user, "active"_n );

        check( time_point_sec(current_time_point()) < swap_init_timepoint + swap_lifetime, "swap lifetime expired" );
        clearnup_expired_swaps();
        if ( swap_hash_itr == swap_hash_idx.end() ) {
            swap_table.emplace(user, [&]( auto& s ) {
                s.key = swap_table.available_primary_key();
                s.trx_id = trx_id;
                s.swap_hash = swap_hash;
                s.swap_init_time = swap_init_timepoint;
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
            check( swap_hash_itr->status != static_cast<uint8_t>(swap_status::CANCEL), "swap already canceled" );
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
                       const string& chain_id, const string eth_address, asset& quantity,
                       const signature& sign, const uint32_t& swap_init_time ) {

        const checksum256 swap_hash = _get_swap_id(
                user, receiver, trx_id,
                chain_id, eth_address, quantity,
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
                             const string& chain_id, const string eth_address, asset& quantity,
                             const signature& sign, const uint32_t& swap_init_time,
                             const public_key owner_key, const public_key active_key                   )  {

        const checksum256 swap_hash = _get_swap_id(
                user, receiver, trx_id, chain_id,
                eth_address, quantity, sign,
                swap_init_time, owner_key
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

    void swap::cancel( const name& user, const checksum256& swap_id ) {
        require_auth( user );
        swap_index swap_table( _self, get_first_receiver().value );

        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_id );

        check( swap_hash_itr != swap_hash_idx.end(), "swap doesn't exist" );
        check( swap_hash_itr->status != static_cast<uint8_t>(swap_status::CANCEL), "swap already canceled" );
        check( swap_hash_itr->status != static_cast<uint8_t>(swap_status::FINISH), "swap already finished" );
        check( time_point_sec(current_time_point()) < swap_hash_itr->swap_init_time + swap_lifetime,
               "swap lifetime expired" );
        check( time_point_sec(current_time_point()) > swap_hash_itr->swap_init_time + swap_active_lifetime,
               "active swap lifetime not expired, wait one week" );
        require_recipient( get_self() );
        require_recipient( user );

        swap_table.modify( *swap_hash_itr, user, [&]( auto& s ) {
            s.status = static_cast<uint8_t>(swap_status::CANCEL);
        });
    }

    checksum256 swap::_get_swap_id( const name& user, const name& receiver, const string& trx_id,
                                    const string& chain_id, const string eth_address, asset& quantity,
                                    const signature& sign, const uint32_t& swap_init_time,
                                    const public_key  owner_key ) {

        require_auth( user );
        swap_index swap_table( _self, get_first_receiver().value );

        const time_point swap_init_timepoint = time_point( seconds(swap_init_time) );

        std::vector<char> sing_payload;
        // if first byte of owner_key is '\0', key is empty
        if ( owner_key.data[0] != '\0'){
            std::copy(owner_key.data.begin(), owner_key.data.end(), back_inserter(sing_payload));
        }
        std::copy( receiver.to_string().begin(), receiver.to_string().end(), back_inserter(sing_payload));
        checksum256 digest = hash( sing_payload.data() );
        public_key swap_key = recover_key( digest, sign );

        std::vector<char> swap_payload( swap_key.data.begin(), swap_key.data.end() );

        string payload_str = trx_id + chain_id + eth_address + quantity.to_string()
                             + std::to_string( swap_init_timepoint.sec_since_epoch() );
        std::copy( payload_str.begin(), payload_str.end(), back_inserter(swap_payload));
        const checksum256 swap_hash = hash( swap_payload.data() );

        auto swap_hash_idx = swap_table.get_index<"byhash"_n>();
        const auto swap_hash_itr = swap_hash_idx.find( swap_hash );

        check( swap_hash_itr != swap_hash_idx.end(), "swap doesn't exist" );
        check( swap_hash_itr->status != static_cast<uint8_t>(swap_status::CANCEL), "swap already canceled" );
        check( swap_hash_itr->status != static_cast<uint8_t>(swap_status::FINISH), "swap already finished" );
        check( time_point_sec(current_time_point()) < swap_hash_itr->swap_init_time + swap_lifetime,
               "swap lifetime expired" );
        check( time_point_sec(current_time_point()) < swap_hash_itr->swap_init_time + swap_active_lifetime,
               "active swap lifetime expired, cancel swap, please" );
//    check( swap_hash_itr->provided_approvals.size() < 15, "not enough approvals" );

        return swap_hash;
    }

    void swap::clearnup_expired_swaps() {
        swap_index swap_table( _self, get_first_receiver().value );

        for ( auto _table_itr = swap_table.begin(); _table_itr != swap_table.end();) {

            if ( time_point_sec(current_time_point()) > _table_itr->swap_init_time + swap_lifetime ) {
                auto _current_itr = _table_itr;
                _table_itr = swap_table.erase(_current_itr);

            } else {
                _table_itr = next(_table_itr);
            }
        }
    }

    [[eosio::on_notify("eosio.token::transfer")]]
    void swap::ontransfer(name from, name to, asset quantity, string memo) {
        if (to != get_self() || from == get_self())
        {
            return;
        }
        check(quantity.symbol == create_account_fee.symbol, "symbol precision mismatch");
        check(quantity.amount > create_account_fee.amount, "the quantity must be greater than the "
                                                           "transfer ETH fee");
        auto space_pos = memo.find(' ');
        check( (space_pos != string::npos), "not valid memo" );

        string chain_id = memo.substr( space_pos + 1 );
        string eth_address = memo.substr( 0, space_pos );
//        check( chain_id == eth_chain_id, "not correct chainID" );
        check( eth_address.size() == 42 || eth_address.size() == 40, "not correct Ethereum address" );
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

        action(
                permission_level{ _self, "active"_n},
                "eosio"_n,
                "delegatebw"_n,
                std::make_tuple(_self, user, default_net_stake, default_cpu_stake, true)
        ).send();
    }

    size_t swap::from_hex(const string& hex_str, char* out_data, size_t out_data_len) {
        auto i = hex_str.begin();
        uint8_t* out_pos = (uint8_t*)out_data;
        uint8_t* out_end = out_pos + out_data_len;
        while (i != hex_str.end() && out_end != out_pos) {
            *out_pos = from_hex((char)(*i)) << 4;
            ++i;
            if (i != hex_str.end()) {
                *out_pos |= from_hex((char)(*i));
                ++i;
            }
            ++out_pos;
        }
        return out_pos - (uint8_t*)out_data;
    }

    checksum256 swap::hex_to_sha256(const string& hex_str) {
        check(hex_str.length() == 64, "invalid sha256");
        checksum256 checksum;
        from_hex(hex_str, (char*)checksum.data(), sizeof(checksum.data()));
        return checksum;
    }

    uint8_t swap::from_hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        check(false, "Invalid hex character");
        return 0;
    }

} /// namespace eosio
