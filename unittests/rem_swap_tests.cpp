/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#include <eosio/chain/abi_serializer.hpp>
#include <fc/crypto/signature.hpp>
#include <eosio/testing/tester.hpp>

#include <Runtime/Runtime.h>

#include <fc/variant_object.hpp>

#include <boost/test/unit_test.hpp>

#include <contracts.hpp>

#include <functional>
#include <numeric>
#include <set>

#ifdef NON_VALIDATING_TEST
#define TESTER tester
#else
#define TESTER validating_tester
#endif


using namespace eosio;
using namespace eosio::chain;
using namespace eosio::testing;
using namespace fc;

using mvo = fc::mutable_variant_object;

struct rem_genesis_account {
   account_name name;
   uint64_t     initial_balance;
};

struct init_data {
   name rampayer;
   string txid;
   string swap_pubkey;
   asset quantity;
   string return_address;
   string return_chain_id;
   block_timestamp_type swap_timestamp;
};

std::vector<rem_genesis_account> genesis_test( {
 {N(b1),        100'000'000'0000ll},
 {N(whale1),     40'000'000'0000ll},
 {N(whale2),     30'000'000'0000ll},
 {N(whale3),     20'000'000'0000ll},
 {N(proda),         500'000'0000ll},
 {N(prodb),         500'000'0000ll},
 {N(prodc),         500'000'0000ll},
 {N(prodd),         500'000'0000ll},
 {N(prode),         500'000'0000ll},
 {N(prodf),         500'000'0000ll},
 {N(prodg),         500'000'0000ll},
 {N(prodh),         500'000'0000ll},
 {N(prodi),         500'000'0000ll},
 {N(prodj),         500'000'0000ll},
 {N(prodk),         500'000'0000ll},
 {N(prodl),         500'000'0000ll},
 {N(prodm),         500'000'0000ll},
 {N(prodn),         500'000'0000ll},
 {N(prodo),         500'000'0000ll},
 {N(prodp),         500'000'0000ll},
 {N(prodq),         500'000'0000ll},
 {N(prodr),         500'000'0000ll},
 {N(prods),         500'000'0000ll},
 {N(prodt),         500'000'0000ll},
 {N(produ),         500'000'0000ll},
 {N(runnerup1),     200'000'0000ll},
 {N(runnerup2),     150'000'0000ll},
 {N(runnerup3),     100'000'0000ll},
});

const auto producer_candidates = {
        N(proda), N(prodb), N(prodc), N(prodd), N(prode), N(prodf), N(prodg),
        N(prodh), N(prodi), N(prodj), N(prodk), N(prodl), N(prodm), N(prodn),
        N(prodo), N(prodp), N(prodq), N(prodr), N(prods), N(prodt), N(produ)
};

const char* SYMBOL_CORE_NAME = "REM";
const std::string REMCHAIN_ID = "93ece941df27a5787a405383a66a7c26d04e80182adf504365710331ac0625a7";

eosio::chain::asset _core_from_string(const std::string& s) {
   return eosio::chain::asset::from_string(s + " " + SYMBOL_CORE_NAME);
}

symbol CORE_SYMBOL_STR(4, SYMBOL_CORE_NAME);

string join( vector<string>&& vec, string delim = string("*") ) {
   return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
                          [&delim](string& a, string& b) {
                             return a + delim + b;
                          });
}

class swap_tester : public TESTER {
public:
   swap_tester();

   void deploy_contract( bool call_init = true ) {
      set_code( config::system_account_name, contracts::rem_system_wasm() );
      set_abi( config::system_account_name, contracts::rem_system_abi().data() );
      if( call_init ) {
         base_tester::push_action(config::system_account_name, N(init),
                                  config::system_account_name,  mutable_variant_object()
                                          ("version", 0)
                                          ("core", CORE_SYMBOL_STR)
         );
      }
   }

   auto delegate_bandwidth( name from, name receiver, asset stake_quantity, uint8_t transfer = 1) {
      auto r = base_tester::push_action(config::system_account_name, N(delegatebw), from, mvo()
              ("from", from )
              ("receiver", receiver)
              ("stake_quantity", stake_quantity)
              ("transfer", transfer)
      );
      produce_block();
      return r;
   }

   void create_currency( name contract, name manager, asset maxsupply, const private_key_type* signer = nullptr ) {
      auto act =  mutable_variant_object()
              ("issuer",       manager )
              ("maximum_supply", maxsupply );

      base_tester::push_action(contract, N(create), contract, act );
   }

   auto issue( name contract, name manager, name to, asset amount ) {
      auto r = base_tester::push_action( contract, N(issue), manager, mutable_variant_object()
              ("to",      to )
              ("quantity", amount )
              ("memo", "")
      );
      produce_block();
      return r;
   }

   auto set_privileged( name account ) {
      auto r = base_tester::push_action(config::system_account_name, N(setpriv), config::system_account_name,  mvo()("account", account)("is_priv", 1));
      produce_block();
      return r;
   }

   auto init_swap( const name& rampayer, const string& txid, const string& swap_pubkey,
                   const asset& quantity, const string& return_address, const string& return_chain_id,
                   const block_timestamp_type& swap_timestamp ) {

      auto r = base_tester::push_action(N(rem.swap), N(init), rampayer, mvo()
              ("rampayer",  name(rampayer))
              ("txid",  txid)
              ("swap_pubkey",  swap_pubkey)
              ("quantity",  quantity)
              ("return_address",  return_address)
              ("return_chain_id",  return_chain_id)
              ("swap_timestamp",  swap_timestamp)
      );
      produce_block();
      return r;
   }

   auto finish_swap( const name& rampayer, const name& receiver, const string& txid, const string& swap_pubkey,
                     const asset& quantity, const string& return_address, const string& return_chain_id,
                     const block_timestamp_type& swap_timestamp, const fc::crypto::signature& sign ) {

      auto r = base_tester::push_action(N(rem.swap), N(finish), rampayer, mvo()
              ("rampayer",  name(rampayer))
              ("receiver",  name(receiver))
              ("txid",  txid)
              ("swap_pubkey_str",  swap_pubkey)
              ("quantity",  quantity)
              ("return_address",  return_address)
              ("return_chain_id",  return_chain_id)
              ("swap_timestamp",  swap_timestamp)
              ("sign",  sign)
      );
      produce_block();
      return r;
   }

   auto setbpreward( const name& rampayer, const asset& quantity ) {

      auto r = base_tester::push_action(N(rem.swap), N(setbpreward), rampayer, mvo()
              ("rampayer",  name(rampayer))
              ("quantity",  quantity)
      );
      produce_block();
      return r;
   }

   auto register_producer(name producer) {
      auto r = base_tester::push_action(config::system_account_name, N(regproducer), producer, mvo()
              ("producer",  name(producer))
              ("producer_key", get_public_key( producer, "active" ) )
              ("url", "" )
              ("location", 0 )
      );
      produce_block();
      return r;
   }

   auto updateauth(const name& account) {
      auto auth = authority(eosio::testing::base_tester::get_public_key(account.to_string(), "active"));
      auth.accounts.push_back( permission_level_weight{{account, config::rem_code_name}, 1} );

      auto r = base_tester::push_action( N(rem), N(updateauth), account, mvo()
              ( "account", account.to_string())
              ( "permission", "active" )
              ( "parent", "owner" )
              ( "auth", auth )
      );
      produce_blocks( 2 );
      return r;
   }

   fc::variant get_swap_info(const name& table, const string& type) {
      vector<char> data;
      const auto& db = control->db();
      const auto* t_id = db.find<chain::table_id_object, chain::by_code_scope_table>( boost::make_tuple( N(rem.swap), N(rem.swap), table ) );
      if ( !t_id ) {
         return fc::variant();
      }

      const auto& idx = db.get_index<chain::key_value_index, chain::by_scope_primary>();

      auto itr = idx.upper_bound( boost::make_tuple( t_id->id, std::numeric_limits<uint64_t>::max() ));
      if ( itr == idx.begin() ) {
         return fc::variant();
      }
      --itr;
      if ( itr->t_id != t_id->id ) {
         return fc::variant();
      }

      data.resize( itr->value.size() );
      memcpy( data.data(), itr->value.data(), data.size() );
      return data.empty() ? fc::variant() : abi_ser.binary_to_variant( type, data, abi_serializer_max_time );
   }

   asset get_balance( const account_name& act ) {
      return get_currency_balance(N(rem.token), CORE_SYMBOL_STR, act);
   }

   void set_code_abi(const account_name& account, const vector<uint8_t>& wasm, const char* abi, const private_key_type* signer = nullptr) {
      wdump((account));
      set_code(account, wasm, signer);
      set_abi(account, abi, signer);
      if (account == N(rem.swap)) {
         const auto& accnt = control->db().get<account_object,by_name>( account );
         abi_def abi_definition;
         BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi_definition), true);
         abi_ser.set_abi(abi_definition, abi_serializer_max_time);
      }
      produce_blocks();
   }

   abi_serializer abi_ser;
};

swap_tester::swap_tester() {
   // Create rem.msig, rem.token and rem.swap
   create_accounts({N(rem.msig), N(rem.token), N(rem.ram), N(rem.ramfee), N(rem.stake), N(rem.bpay), N(rem.spay), N(rem.vpay), N(rem.saving), N(rem.swap) });

   // Set code for the following accounts:
   //  - rem (code: rem.bios) (already set by tester constructor)
   //  - rem.msig (code: rem.msig)
   //  - rem.token (code: rem.token)
   set_code_abi(N(rem.msig),
                contracts::rem_msig_wasm(),
                contracts::rem_msig_abi().data());//, &rem_active_pk);
   set_code_abi(N(rem.token),
                contracts::rem_token_wasm(),
                contracts::rem_token_abi().data()); //, &rem_active_pk);
   set_code_abi(N(rem.swap),
                contracts::rem_swap_wasm(),
                contracts::rem_swap_abi().data()); //, &rem_active_pk);

   // Set privileged for rem.msig and rem.token
   set_privileged(N(rem.msig));
   set_privileged(N(rem.token));
   set_privileged(N(rem.swap));

   // Verify rem.msig and rem.token is privileged
   const auto& rem_msig_acc = get<account_metadata_object, by_name>(N(rem.msig));
   BOOST_TEST(rem_msig_acc.is_privileged() == true);
   const auto& rem_token_acc = get<account_metadata_object, by_name>(N(rem.token));
   BOOST_TEST(rem_token_acc.is_privileged() == true);
   const auto& rem_swap_acc = get<account_metadata_object, by_name>(N(rem.swap));
   BOOST_TEST(rem_swap_acc.is_privileged() == true);

   // Create SYS tokens in rem.token, set its manager as rem
   const auto max_supply     = _core_from_string("1000000000.0000"); /// 10x larger than 1B initial tokens
   const auto initial_supply = _core_from_string("100000000.0000");  /// 10x larger than 1B initial tokens

   create_currency(N(rem.token), N(rem.swap), max_supply);
   // Issue the genesis supply of 1 billion SYS tokens to rem.system
   issue(N(rem.token), N(rem.swap), N(rem.swap), initial_supply);

   auto actual = get_balance(N(rem.swap));

   BOOST_REQUIRE_EQUAL(initial_supply, actual);

   // Create genesis accounts
   for( const auto& account : genesis_test ) {
      create_account( account.name, N(rem.swap) );
   }

   deploy_contract();

   // Buy ram and stake cpu and net for each genesis accounts
   for( const auto& account : genesis_test ) {
      const auto stake_quantity = account.initial_balance - 1000;
      const auto r = delegate_bandwidth(N(rem.stake), account.name, asset(stake_quantity, CORE_SYMBOL_STR));
      BOOST_REQUIRE( !r->except_ptr );
   }

   // Register producers
   for( const auto& producer : producer_candidates ) {
      register_producer(producer);
   }
   // set permission code
   updateauth(N(rem.swap));
}

BOOST_AUTO_TEST_SUITE(swap_tests)

BOOST_FIXTURE_TEST_CASE( init_swap_test, swap_tester ) {
try {

   string swap_timestamp = "2020-01-01T00:00:00.000";
   init_data init_swap_data = {
           .rampayer = N(proda),
           .txid = "79b9563d89da12715c2ea086b38a5557a521399c87d40d84b8fa5df0fd478046",
           .swap_pubkey = "EOS5dorAyvqvG8znqAPjNGSsJsVf2eLv2xyv9veZAL5vseS2VVLsX",
           .quantity = asset::from_string("201.0000 REM"),
           .return_address = "9f21f19180c8692ebaa061fd231cd1b029ff2326",
           .return_chain_id = "ethropsten",
           .swap_timestamp = fc::time_point_sec::from_iso_string(swap_timestamp)
   };
   time_point swap_timepoint = init_swap_data.swap_timestamp.to_time_point();
   string swap_payload = join( { init_swap_data.swap_pubkey.substr(3), init_swap_data.txid, REMCHAIN_ID,
                                 init_swap_data.quantity.to_string(), init_swap_data.return_address,
                                 init_swap_data.return_chain_id, std::to_string( swap_timepoint.sec_since_epoch() ) } );
   string swap_id = fc::sha256::hash( swap_payload );

   init_swap( init_swap_data.rampayer, init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
   init_swap_data.return_address, init_swap_data.return_chain_id, init_swap_data.swap_timestamp );

   setbpreward( init_swap_data.rampayer, init_swap_data.quantity );

   auto data = get_swap_info(N(swaps), "swap_data");
   BOOST_REQUIRE_EQUAL(init_swap_data.txid, data["txid"].as_string());
   BOOST_REQUIRE_EQUAL(swap_id, data["swap_id"].as_string());
   BOOST_REQUIRE_EQUAL(swap_timestamp, data["swap_timestamp"].as_string());
   BOOST_REQUIRE_EQUAL("0", data["status"].as_string());
   BOOST_REQUIRE_EQUAL("proda", data["provided_approvals"].get_array()[0].as_string());

   // action's authorizing actor 'fail' does not exist
   BOOST_REQUIRE_THROW(init_swap( N(fail), init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                                  init_swap_data.return_address, init_swap_data.return_chain_id,
                                  init_swap_data.swap_timestamp), transaction_exception);
   // approval already exists
   BOOST_REQUIRE_THROW(init_swap( init_swap_data.rampayer, init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                                  init_swap_data.return_address, init_swap_data.return_chain_id,
                                  init_swap_data.swap_timestamp), eosio_assert_message_exception);
   // symbol precision mismatch
   BOOST_REQUIRE_THROW(init_swap( init_swap_data.rampayer, init_swap_data.txid, init_swap_data.swap_pubkey,
                                  asset::from_string("201.0000 SYS"), init_swap_data.return_address,
                                  init_swap_data.return_chain_id, init_swap_data.swap_timestamp),
                                  eosio_assert_message_exception);
   // the quantity must be greater than the swap fee
   BOOST_REQUIRE_THROW(init_swap( init_swap_data.rampayer, init_swap_data.txid, init_swap_data.swap_pubkey,
                                  asset::from_string("250.0000 REM"), init_swap_data.return_address,
                                  init_swap_data.return_chain_id, init_swap_data.swap_timestamp),
                                  eosio_assert_message_exception);
   // swap lifetime expired
   BOOST_REQUIRE_THROW(init_swap( init_swap_data.rampayer, init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                                  init_swap_data.return_address, init_swap_data.return_chain_id,
                                  fc::time_point_sec::from_iso_string("2019-01-13T18:09:16.000")), eosio_assert_message_exception);
   // block producer authorization required
   BOOST_REQUIRE_THROW(init_swap( N(rem.swap), init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                                  init_swap_data.return_address, init_swap_data.return_chain_id,
                                  init_swap_data.swap_timestamp), eosio_assert_message_exception);
   // not supported chain id
   BOOST_REQUIRE_THROW(init_swap( N(rem.swap), init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                                  init_swap_data.return_address, " ",
                                  init_swap_data.swap_timestamp), eosio_assert_message_exception);
   // not supported address
   BOOST_REQUIRE_THROW(init_swap( N(rem.swap), init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                                  " ", init_swap_data.return_chain_id,
                                  init_swap_data.swap_timestamp), eosio_assert_message_exception);
   // not supported address
   BOOST_REQUIRE_THROW(init_swap( N(rem.swap), init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                                  " ", init_swap_data.return_chain_id,
                                  init_swap_data.swap_timestamp), eosio_assert_message_exception);
   // not supported address
   BOOST_REQUIRE_THROW(init_swap( N(rem.swap), init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                                  "/&%$#!@)(|<>_-+=", init_swap_data.return_chain_id,
                                  init_swap_data.swap_timestamp), eosio_assert_message_exception);
   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( finish_swap_test, swap_tester ) {
try {

   string swap_timestamp = "2020-01-01T00:00:00.000";
   name receiver = N(prodb);
   init_data init_swap_data = {
           .rampayer = N(proda),
           .txid = "79b9563d89da12715c2ea086b38a5557a521399c87d40d84b8fa5df0fd478046",
           .swap_pubkey = "EOS5dorAyvqvG8znqAPjNGSsJsVf2eLv2xyv9veZAL5vseS2VVLsX",
           .quantity = asset::from_string("201.0000 REM"),
           .return_address = "9f21f19180c8692ebaa061fd231cd1b029ff2326",
           .return_chain_id = "ethropsten",
           .swap_timestamp = fc::time_point_sec::from_iso_string(swap_timestamp)
   };
   time_point swap_timepoint = init_swap_data.swap_timestamp.to_time_point();
   string swap_payload = join( { init_swap_data.swap_pubkey.substr(3), init_swap_data.txid, REMCHAIN_ID,
                                 init_swap_data.quantity.to_string(), init_swap_data.return_address,
                                 init_swap_data.return_chain_id, std::to_string( swap_timepoint.sec_since_epoch() ) } );
   string swap_id = fc::sha256::hash( swap_payload );

   for( const auto& producer : producer_candidates ) {
   init_swap( producer, init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
              init_swap_data.return_address, init_swap_data.return_chain_id, init_swap_data.swap_timestamp );
   }

   string sign_payload = join( { receiver.to_string(), init_swap_data.txid, REMCHAIN_ID, init_swap_data.quantity.to_string(),
                                 init_swap_data.return_address, init_swap_data.return_chain_id,
                                 std::to_string( swap_timepoint.sec_since_epoch() ) } );

   string swap_digest = fc::sha256::hash( sign_payload );
   string sign_str = "SIG_K1_JucDm1qudEDHzYCaJhSWKUPDSCgEkezCnKBJH9ma9WDafeV1SG9hEViyyeriHBH129QHJX74eJdSS62vFiSMqivqnttGLk";
   fc::crypto::signature sign(sign_str);


   finish_swap( N(proda), receiver, init_swap_data.txid, init_swap_data.swap_pubkey, init_swap_data.quantity,
                 init_swap_data.return_address, init_swap_data.return_chain_id, init_swap_data.swap_timestamp, sign );

   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_SUITE_END()
