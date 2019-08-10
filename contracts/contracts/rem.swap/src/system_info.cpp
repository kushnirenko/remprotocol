/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.swap/rem.swap.hpp>

namespace eosio {

    struct [[eosio::table("global"), eosio::contract("rem.system")]] eosio_global_state : eosio::blockchain_parameters {
        uint64_t free_ram()const { return max_ram_size - total_ram_bytes_reserved; }

        uint64_t             max_ram_size = 64ll*1024 * 1024 * 1024;
        uint64_t             min_account_stake = 1000000; //minimum stake for new created account 100'0000 REM
        uint64_t             total_ram_bytes_reserved = 0;
        int64_t              total_ram_stake = 0;

        //producer name and pervote factor
        std::vector<std::pair<eosio::name, double>> last_schedule;
        uint32_t last_schedule_version = 0;
        block_timestamp current_round_start_time;

        block_timestamp      last_producer_schedule_update;
        time_point           last_pervote_bucket_fill;
        int64_t              perstake_bucket = 0;
        int64_t              pervote_bucket = 0;
        int64_t              perblock_bucket = 0;
        uint32_t             total_unpaid_blocks = 0; /// all blocks which have been produced but not paid
        int64_t              total_producer_stake = 0;
        int64_t              total_activated_stake = 0;
        time_point           thresh_activated_stake_time;
        uint16_t             last_producer_schedule_size = 0;
        double               total_producer_vote_weight = 0; /// the sum of all producer votes
        double               total_active_producer_vote_weight = 0; /// the sum of top 21 producer votes
        block_timestamp      last_name_close;

        // explicit serialization macro is not necessary, used here only to improve compilation time
        EOSLIB_SERIALIZE_DERIVED( eosio_global_state, eosio::blockchain_parameters,
        (max_ram_size)(min_account_stake)(total_ram_bytes_reserved)(total_ram_stake)
        (last_schedule)(last_schedule_version)(current_round_start_time)
        (last_producer_schedule_update)(last_pervote_bucket_fill)
        (perstake_bucket)(pervote_bucket)(perblock_bucket)(total_unpaid_blocks)(total_producer_stake)
        (total_activated_stake)(thresh_activated_stake_time)
        (last_producer_schedule_size)(total_producer_vote_weight)(total_active_producer_vote_weight)(last_name_close) )
    };

    struct [[eosio::table, eosio::contract("rem.system")]] producer_info2 {
        name            owner;
        double          votepay_share = 0;
        time_point      last_votepay_share_update;

        uint64_t primary_key()const { return owner.value; }

        // explicit serialization macro is not necessary, used here only to improve compilation time
        EOSLIB_SERIALIZE( producer_info2, (owner)(votepay_share)(last_votepay_share_update) )
    };

    typedef eosio::multi_index< "producers2"_n, producer_info2 > producers_table;
    typedef eosio::singleton< "global"_n, eosio_global_state >   global_state_singleton;

    asset swap::get_min_account_stake() {
        global_state_singleton global( system_account, system_account.value );
        auto _gstate = global.get();
        return { static_cast<int64_t>( _gstate.min_account_stake ), core_symbol };
    }

    bool swap::is_block_producer( const name& user ) {
        producers_table _producers_table( system_account, system_account.value );
        return _producers_table.find( user.value ) != _producers_table.end();
    }

    std::vector<name> swap::get_active_producers() {
        producers_table _producers_table( system_account, system_account.value );
        std::vector<name> producers;
        for ( auto _table_itr = _producers_table.begin(); _table_itr != _producers_table.end(); ++_table_itr ) {
            producers.push_back( _table_itr->owner );
        }
        return producers;
    }
}
