/**
 *  @copyright defined in eos/LICENSE.txt
 */

#pragma once

#include <eosio/action.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>
#include <eosio/permission.hpp>
#include <eosio/singleton.hpp>
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
        void init( const name& rampayer, const string& txid, const string& swap_pubkey,
                   const asset& quantity, const string& return_address, const string& return_chain_id,
                   const block_timestamp& timestamp );

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
        void cancel( const name& rampayer, const string& txid, const string& swap_pubkey,
                     const asset& quantity, const string& return_address, const string& return_chain_id,
                     const block_timestamp& timestamp );


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
        enum class swap_status: int8_t {
            CANCELED = -1,
            INITIALIZED = 0,
            FINISHED = 1
        };

        static constexpr symbol core_symbol{"REM", 4};
        const name system_account = "rem"_n;
        const name system_token_account = "rem.token"_n;
        const string delimiter = "*";

        const string remchain_id = "93ece941df27a5787a405383a66a7c26d04e80182adf504365710331ac0625a7";

        const time_point swap_lifetime = time_point(seconds(15552000)); // 180 days
        const time_point swap_active_lifetime = time_point(seconds(604800)); // 7 days

        struct [[eosio::table]] swap_data {
            uint64_t                      key;
            string                        txid;
            checksum256                   swap_hash;
            block_timestamp               swap_timestamp;
            int8_t                        status;

            std::vector<permission_level> provided_approvals;

            uint64_t primary_key()const { return key; }
            checksum256 by_swap_hash()const { return swap_hash; }

	   	 	EOSLIB_SERIALIZE( swap_data, (key)(txid)(swap_hash)(swap_timestamp)
	   	 	                             (status)(provided_approvals) )
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

        typedef multi_index< "swaps2"_n, swap_data, indexed_by <"byhash"_n,
                const_mem_fun< swap_data, checksum256, &swap_data::by_swap_hash >>
                > swap_index;

        bool is_block_producer( const name& user );
        std::vector<name> get_active_producers();
        asset get_min_account_stake();

        bool is_swap_confirmed( const std::vector<permission_level>& provided_approvals );
        checksum256 _get_swap_id( const name& rampayer, const name& receiver, const string& txid,
                                  const string& swap_pubkey_str, asset& quantity, const string& return_address,
                                  const string& return_chain_id, const block_timestamp& timestamp,
                                  const signature& sign, const string owner_key, const string active_key );

        checksum256 hash(const string& str) {
            return sha256(str.c_str(), str.size());
        }

        void to_rewards( const asset& quantity ) {
            action(
                    permission_level{ get_self(), "active"_n },
                    system_account, "torewards"_n,
                    std::make_tuple( _self, quantity )
            ).send();
        }

        void _retire_tokens( const asset& quantity ) {
            action(
                    permission_level{ _self, "active"_n },
                    system_token_account, "retire"_n,
                    std::make_tuple( quantity, string("swap retire tokens") )
            ).send();
        }

        void _transfer( const name& receiver, const asset& quantity );

        void _issue_tokens( const asset& quantity ) {
            action(
                    permission_level{ _self, "active"_n },
                    system_token_account, "issue"_n,
                    std::make_tuple( _self, quantity, string("swap issue tokens") )
            ).send();
        }

        void validate_swap( const checksum256& swap_hash );
        void cleanup_expired_swaps();

        void create_user( const name& user, const public_key& owner_key,
                          const public_key& active_key, const asset& min_account_stake );
    };
    /** @}*/ // end of @defgroup remswap rem.swap
} /// namespace eosio
