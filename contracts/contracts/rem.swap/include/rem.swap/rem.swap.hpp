/**
 *  @copyright defined in eos/LICENSE.txt
 */

#pragma once

#include <eosio/action.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>
#include <eosio/permission.hpp>
#include <eosio/privileged.hpp>
#include <eosio/time.hpp>

#include <vector>
#include <string>

namespace eosiosystem {
    class system_contract;
}

namespace eosio {

    using std::string;

    /**
     * @defgroup remswap rem.swap
     * @ingroup eosiocontracts
     *
     * rem.swap contract
     *
     * @details rem.swap contract defines the structures and actions that allow users to init token swap,
     * finish token swap, create new account and cancel token swap.
     * @{
     */
    class [[eosio::contract("rem.swap")]] swap : public contract {
    public:
        using contract::contract;

        /**
         * Init swap action.
         *
         * @details Initiate token swap.
         *
         * @param user - the owner account to execute the init action for,
         * @param swap_key - the public key created for the token swap,
         * @param trx_id - the transaction transfer id in Ethereum blockchain,
         * @param quantity - the quantity of tokens in the transfer transaction,
         * @param swap_init_time - the timestamp transfer transaction in Ethereum blockchain.
         */
        [[eosio::action]]
        void init( const name& rampayer, const string& txid, const string& swap_key,
                   const asset& quantity, const string& return_address, const string& return_chain_id,
                   const block_timestamp& swap_timestamp );

        /**
         *  Debug action.
         */
        [[eosio::action]]
        void cleartable( const name& user );


        /**
         * Cancel token swap.
         *
         * @details Cancel already initialized token swap.
         *
         * @param user - the owner account to execute the cancel action for,
         * @param swap_id - hash of swap data ( swap_key, trx_id, chain_id, eth_address,
         * quantity, swap_init_time ).
         */
        [[eosio::action]]
        void cancel( const name& user, const checksum256& swap_id );


        /**
         * Finish token swap.
         *
         * @details Finish already approved token swap.
         *
         * @param user - the owner account to execute the finish action for,
         * @param receiver - the account to be swap finished to,
         * @param trx_id - the transaction transfer id in Ethereum blockchain,
         * @param quantity - the quantity of tokens to be swaped,
         * @param sign - the signature that sign by swap-key with data : name receiver account,
         * @param swap_init_time - the timestamp transfer transaction in Ethereum blockchain.
         */
        [[eosio::action]]
        void finish( const name& rampayer, const name& receiver, const string& txid,
                     const string& swap_pubkey_str, asset& quantity, const string& return_address,
                     const string& return_chain_id, const block_timestamp& swap_timestamp, const signature& sign );


        /**
         * Finish token swap.
         *
         * @details Finish already approved token swap and create new account.
         *
         * @param user - the owner account to execute the finish action for,
         * @param receiver - the account to be swap finished to,
         * @param trx_id - the transaction transfer id in Ethereum blockchain,
         * @param quantity - the quantity of tokens to be swapped,
         * @param sign - the signature that sign by swap-key with data : name receiver account,
         * owner_key, public_key,
         * @param swap_init_time - the timestamp transfer transaction in Ethereum blockchain,
         * @param owner_key - owner key account to create,
         * @param active_key - active key account to create.
         */
        [[eosio::action]]
        void finishnewacc( const name& rampayer, const name& receiver, const string& owner_pubkey_str,
                           const string& active_pubkey_str, const string& txid, const string& swap_pubkey_str,
                           asset& quantity, const string& return_address, const string& return_chain_id,
                           const block_timestamp& swap_timestamp, const signature& sign );


        [[eosio::on_notify("rem.token::transfer")]]
        void ontransfer( name from, name to, asset quantity, string memo );

        using init_swap_action = action_wrapper<"init"_n, &swap::init>;
        using finish_swap_action = action_wrapper<"finish"_n, &swap::finish>;
        using finish_swap_and_create_acc_action = action_wrapper<"finishnewacc"_n, &swap::finishnewacc>;
        using cancel_swap_action = action_wrapper<"cancel"_n, &swap::cancel>;

    private:
        enum class swap_status: uint8_t {
            INITIALIZED = 0,
            CANCELED = 1,
            FINISHED = 2
        };

        static constexpr symbol core_symbol{"REM", 4};
        static constexpr symbol RAMCORE_symbol{"RAMCORE", 4};
        static constexpr symbol RAM_symbol{"RAM", 0};
        const asset default_cpu_stake{2000000, core_symbol};
        const asset default_net_stake{500, core_symbol};
        const asset create_account_fee = {4000000, core_symbol};
        const uint32_t default_ram_amount_bytes{3446};
        const name system_account = "rem"_n;
        const string separator = "*";

        const string remchain_id = "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f";

        const time_point swap_lifetime = time_point(seconds(15552000)); // 180 days
        const time_point swap_active_lifetime = time_point(seconds(604800)); // 7 days

        struct approval {
            permission_level level;
            time_point       time;
        };

        struct [[eosio::table]] swap_data {
            uint64_t                key;
            string                  txid;
            checksum256             swap_hash;
            block_timestamp         swap_timestamp;
            uint8_t                 status;

            std::vector<approval>   provided_approvals;

            uint64_t primary_key()const { return key; }
            checksum256 by_swap_hash()const { return swap_hash; }

//	   	 	EOSLIB_SERIALIZE( swap_data, (key)(trx_id)(swap_hash)(swap_init_time)
//	   	 	                             (status)(provided_approvals) )
        };

        struct [[eosio::table, eosio::contract("rem.system")]] producer_info2 {
            name            owner;
            double          votepay_share = 0;
            time_point      last_votepay_share_update;

            uint64_t primary_key()const { return owner.value; }

            // explicit serialization macro is not necessary, used here only to improve compilation time
//            EOSLIB_SERIALIZE( producer_info2, (owner)(votepay_share)(last_votepay_share_update) )
        };

        struct permission_level_weight {
            permission_level permission;
            uint16_t weight;
        };

        struct key_weight {
            public_key key;
            uint16_t weight;
        };

        struct wait_weight {
            uint32_t wait_sec;
            uint16_t weight;
        };

        struct authority {
            uint32_t threshold;
            std::vector<key_weight> keys;
            std::vector<permission_level_weight> accounts;
            std::vector<wait_weight> waits;
        };

        struct newaccount {
            name creator;
            name name;
            authority owner;
            authority active;
        };

        typedef multi_index< "swaps"_n, swap_data, indexed_by <"byhash"_n,
                const_mem_fun< swap_data, checksum256, &swap_data::by_swap_hash >>
                > swap_index;

        typedef eosio::multi_index< "producers2"_n, producer_info2 > producers_table2;

        bool is_block_producer( const name& user ) {
//            std::vector<name> _producers = get_active_producers();
            name system_acc = "rem"_n;
            producers_table2 _producers_table( system_acc, system_acc.value );
            return _producers_table.find( user.value ) != _producers_table.end();
//            check(false, _producers.size());
//            return std::find(_producers.begin(), _producers.end(), user) != _producers.end();
        }

        std::vector<name> get_active_producers() {
            name system_acc = "rem"_n;
            producers_table2 _producers_table( system_acc, system_acc.value );
            std::vector<name> producers;
            for ( auto _table_itr = _producers_table.begin(); _table_itr != _producers_table.end(); ++_table_itr ) {
                producers.push_back( _table_itr->owner );
            }
            return producers;
        }

        bool is_swap_confirmed( const std::vector<approval>& provided_approvals );

        uint8_t from_hex(char c);
        checksum256 hex_to_sha256(const string& hex_str);
        size_t from_hex(const string& hex_str, char* out_data, size_t out_data_len);
        string to_hex(const char* d, uint32_t s);

        checksum256 hash(const string& str) {
            return sha256(str.c_str(), str.size());
        }

        string sha256_to_hex(const checksum256& sha256) {
            return to_hex((char*)sha256.data(), sizeof(sha256));
        }

        void to_reward_action( const asset& amount ) {
            action(
                    permission_level{ _self, "active"_n},
                    system_account,
                    "torewards"_n,
                    std::make_tuple(_self, amount)
            ).send();
        }

        void validate_swap( const checksum256& swap_hash );

        void cleanup_expired_swaps();

        void create_user( const name& user, public_key owner_key, public_key active_key );

        void _transfer( const name& receiver, const asset& quantity );
        checksum256 _get_swap_id( const name& rampayer, const name& receiver, const string& txid,
                                  const string& swap_pubkey_str, asset& quantity, const string& return_address,
                                  const string& return_chain_id, const block_timestamp& timestamp,
                                  const signature& sign, const string owner_key, const string active_key );
    };
    /** @}*/ // end of @defgroup remswap rem.swap
} /// namespace eosio
