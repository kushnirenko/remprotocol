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
#include <eosio/system.hpp>

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
     * finish token swap, create new account, init token swap to ERC20 - for REM tokens.
     * @{
     */
    class [[eosio::contract("rem.swap")]] swap : public contract {
    public:
        using contract::contract;

        /**
         * Init swap action.
         *
         * @details Initiate token swap with ERC20 REM ( ERC20 - > Remchain ).
         *
         * @param user - the owner account to execute the init action for.
         * @param swap_key - the public key created for the token swap.
         * @param trx_id - the transaction transfer id in Ethereum blockchain.
         * @param quantity - the quantity of tokens in the transfer transaction.
         * @param swap_init_time - the timestamp transfer transaction in Ethereum blockchain.
         */
        [[eosio::action]]
        void init( const name& user, const public_key& swap_key, const string& trx_id,
                   const asset& quantity, const uint32_t& swap_init_time );

        /**
         *  Debug action.
         */
        [[eosio::action]]
        void cleartable( const name& user );


        /**
         * Finish token swap with ERC20 REM.
         *
         * @details Finish already approved token swap ( from ERC20 - > Remchain ).
         *
         * @param user - the owner account to execute the finish action for,
         * @param receiver - the account to be swap finished to,
         * @param trx_id - the transaction transfer id in Ethereum blockchain,
         * @param quantity - the quantity of tokens to be swaped,
         * @param sign - the signature that sign by swap-key with data : name receiver account,
         * @param swap_init_time - the timestamp transfer transaction in Ethereum blockchain.
         */
        [[eosio::action]]
        void finish( const name& user, const name& receiver, const string& trx_id,
                     asset& quantity, const signature& sign, const uint32_t& swap_init_time );


        /**
         * Finish token swap with ERC20 REM.
         *
         * @details Finish already approved token swap ( from ERC20 - > Remchain ).
         *
         * @param user - the owner account to execute the finish action for,
         * @param receiver - the account to be swap finished to,
         * @param trx_id - the transaction transfer id in Ethereum blockchain,
         * @param quantity - the quantity of tokens to be swaped,
         * @param sign - the signature that sign by swap-key with data : name receiver account,
         * owner_key, public_key,
         * @param swap_init_time - the timestamp transfer transaction in Ethereum blockchain,
         * @param owner_key - owner key account to create,
         * @param active_key - active key account to create.
         */
        [[eosio::action]]
        void finishnewacc( const name& user, const name& receiver, const string& trx_id,
                           asset& quantity, const signature& sign, const uint32_t& swap_init_time,
                           const public_key owner_key, const public_key active_key                   );


        [[eosio::on_notify("eosio.token::transfer")]]
        void initerc( name from, name to, asset quantity, string memo );

        using init_swap_action = eosio::action_wrapper<"init"_n, &swap::init>;
        using finish_swap_action = eosio::action_wrapper<"finish"_n, &swap::finish>;
        using finish_swap_and_create_acc_action = eosio::action_wrapper<"finishwithacc"_n, &swap::finish>;

    private:
        enum class swap_status: uint8_t {
            INIT = 0,
            FINISH = 1
        };

        const asset create_account_fee = {200000, symbol("REM", 4)};
        const string remchain_id = "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f";
        const time_point swap_lifetime = time_point(seconds(15552000)); // 180 days

        struct approval {
            permission_level level;
            time_point       time;
        };

        struct [[eosio::table]] swap_data {
            uint64_t                key;
            string                  trx_id;
            checksum256             swap_hash;
            time_point              swap_init_time;
            uint8_t                 status;

            std::vector<approval>   provided_approvals;

            uint64_t primary_key()const { return key; }
            checksum256 by_swap_hash()const { return swap_hash; }

//	   	 	EOSLIB_SERIALIZE( swap_data, (key)(trx_id)(swap_hash)(swap_init_time)
//	   	 	                             (timepoint)(status)(provided_approvals) )
        };

        struct [[eosio::table]] swap_to_erc20 {
            uint64_t   key;
            name       user;
            string     eth_address;
            time_point swap_init_time;
            asset      amount;

            uint64_t primary_key()const { return key; }
            uint64_t by_name()const { return user.value; }
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

        typedef multi_index<"swapstoerc"_n, swap_to_erc20, indexed_by<"byname"_n,
                const_mem_fun< swap_to_erc20, uint64_t, &swap_to_erc20::by_name >>
                > erc20_swap_index;

        bool is_block_producer( const name& user ) {
            std::vector<name> _producers = get_active_producers();
            return std::find(_producers.begin(), _producers.end(), user) != _producers.end();
        }

        checksum256 hash(const string& str) {
            return sha256(const_cast<char*>(str.c_str()), str.size());
        }

        void clearnup_expired_swaps();

        void create_user( const name& user, public_key owner_key, public_key active_key );

        void _transfer( const name& receiver, const asset& quantity );
        checksum256 _get_swap_id( const name& user, const name& receiver, const string& trx_id,
                                  asset& quantity, const signature& sign, const uint32_t& swap_init_time,
                                  const public_key  owner_key                                               );
    };
    /** @}*/ // end of @defgroup remswap rem.swap
} /// namespace eosio
