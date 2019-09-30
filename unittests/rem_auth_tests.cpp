/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/testing/tester.hpp>

#include <Runtime/Runtime.h>

#include <fc/variant_object.hpp>
#include <fc/crypto/pke.hpp>

#include <boost/test/unit_test.hpp>

#include <contracts.hpp>

#ifdef NON_VALIDATING_TEST
#define TESTER tester
#else
#define TESTER validating_tester
#endif


using namespace eosio;
using namespace eosio::chain;
using namespace eosio::testing;
using namespace fc;

using mvo = mutable_variant_object;

struct rem_genesis_account {
   account_name name;
   uint64_t     initial_balance;
};

class rem_auth_tester : public TESTER {
public:
   rem_auth_tester();

   void deploy_contract( bool call_init = true ) {
      set_code( config::system_account_name, contracts::rem_system_wasm() );
      set_abi( config::system_account_name, contracts::rem_system_abi().data() );
      if( call_init ) {
         base_tester::push_action(config::system_account_name, N(init),
                                  config::system_account_name,  mutable_variant_object()
                                     ("version", 0)
                                     ("core", CORE_SYM_STR)
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

   auto transfer(const name& from, const name& to, const asset& quantity, const string& memo) {
      auto r = base_tester::push_action(N(rem.token), N(transfer), from, mvo()
         ("from", from)
         ("to", to)
         ("quantity", quantity)
         ("memo", memo)
      );
      produce_block();
      return r;
   }

   auto updateauth(const name &account, const name& code_account) {
      auto auth = authority(testing::base_tester::get_public_key(account.to_string(), "active"));
      auth.accounts.push_back(permission_level_weight{{code_account, config::rem_code_name}, 1});

      auto r = base_tester::push_action(N(rem), N(updateauth), account, mvo()
         ("account", account.to_string())
         ("permission", "active")
         ("parent", "owner")
         ("auth", auth)
      );
      produce_blocks();
      return r;
   }

   auto addkeyacc(const name &account, const crypto::public_key &key, const crypto::signature &signed_by_key,
                  const string &extra_key, const string &payer_str, const vector<permission_level> &auths) {
      auto r = base_tester::push_action(N(rem.auth), N(addkeyacc), auths, mvo()
         ("account",  account)
         ("key_str", key )
         ("signed_by_key", signed_by_key )
         ("extra_key", extra_key )
         ("payer_str", payer_str )
      );
      produce_block();
      return r;
   }

   auto addkeyapp(const name &account, const crypto::public_key &new_key, const crypto::signature &signed_by_new_key,
                  const string &extra_key, const crypto::public_key &key, const crypto::signature &signed_by_key,
                  const string &payer_str, const vector<permission_level> &auths) {
      auto r = base_tester::push_action(N(rem.auth), N(addkeyapp), auths, mvo()
         ("account",  account)
         ("new_key_str", new_key )
         ("signed_by_new_key", signed_by_new_key )
         ("extra_key", extra_key )
         ("key_str", key )
         ("signed_by_key", signed_by_key )
         ("payer_str", payer_str )
      );
      produce_block();
      return r;
   }

   auto revokeacc(const name &account, const crypto::public_key &key, const vector<permission_level>& auths) {
      auto r = base_tester::push_action(N(rem.auth), N(revokeacc), auths, mvo()
         ("account",  account)
         ("key_str", key )
      );
      produce_block();
      return r;
   }

   auto revokeapp(const name &account, const crypto::public_key &revoke_key, const crypto::public_key &key,
                  const crypto::signature &signed_by_key, const vector<permission_level>& auths) {
      auto r = base_tester::push_action(N(rem.auth), N(revokeapp), auths, mvo()
         ("account",  account)
         ("revoke_key_str", revoke_key )
         ("key_str", key )
         ("signed_by_key", signed_by_key )
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

   variant get_authkeys_tbl( const name& account ) {
      return get_singtable(N(rem.auth), N(authkeys), "authkeys");
   }

   variant get_singtable(const name& contract, const name &table, const string &type) {
      vector<char> data;
      const auto &db = control->db();
      const auto *t_id = db.find<table_id_object, by_code_scope_table>(
         boost::make_tuple(contract, contract, table));
      if (!t_id) {
         return variant();
      }

      const auto &idx = db.get_index<key_value_index, by_scope_primary>();

      auto itr = idx.upper_bound(boost::make_tuple(t_id->id, std::numeric_limits<uint64_t>::max()));
      if (itr == idx.begin()) {
         return variant();
      }
      --itr;
      if (itr->t_id != t_id->id) {
         return variant();
      }

      data.resize(itr->value.size());
      memcpy(data.data(), itr->value.data(), data.size());
      return data.empty() ? variant() : abi_ser.binary_to_variant(type, data, abi_serializer_max_time);
   }

   asset get_balance( const account_name& act ) {
      return get_currency_balance(N(rem.token), symbol(CORE_SYMBOL), act);
   }

   void set_code_abi(const account_name& account, const vector<uint8_t>& wasm, const char* abi, const private_key_type* signer = nullptr) {
      wdump((account));
      set_code(account, wasm, signer);
      set_abi(account, abi, signer);
      if (account == N(rem.auth)) {
         const auto& accnt = control->db().get<account_object,by_name>( account );
         abi_def abi_definition;
         BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi_definition), true);
         abi_ser.set_abi(abi_definition, abi_serializer_max_time);
      }
      produce_blocks();
   }

   string join(vector<string> &&vec, string delim = string("*")) {
      return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
                             [&delim](string &a, string &b) {
                                return a + delim + b;
                             });
   }

   abi_serializer abi_ser;
};

rem_auth_tester::rem_auth_tester() {
   // Create rem.msig and rem.token, rem.auth
   create_accounts({N(rem.msig), N(rem.token), N(rem.ram), N(rem.ramfee), N(rem.stake), N(rem.bpay), N(rem.spay), N(rem.vpay), N(rem.saving), N(rem.auth) });

   // Register producers
   const auto producer_candidates = {
      N(proda), N(prodb), N(prodc), N(prodd), N(prode), N(prodf), N(prodg),
      N(prodh), N(prodi), N(prodj), N(prodk), N(prodl), N(prodm), N(prodn),
      N(prodo), N(prodp), N(prodq), N(prodr), N(prods), N(prodt), N(produ)
   };
   // Set code for the following accounts:
   //  - rem (code: rem.bios) (already set by tester constructor)
   //  - rem.msig (code: rem.msig)
   //  - rem.token (code: rem.token)
   //  - rem.auth (code: rem.auth)
   set_code_abi(N(rem.msig),
                contracts::rem_msig_wasm(),
                contracts::rem_msig_abi().data());//, &rem_active_pk);
   set_code_abi(N(rem.token),
                contracts::rem_token_wasm(),
                contracts::rem_token_abi().data()); //, &rem_active_pk);
   set_code_abi(N(rem.auth),
                contracts::rem_auth_wasm(),
                contracts::rem_auth_abi().data()); //, &rem_active_pk);

   // Set privileged for rem.msig and rem.token
   set_privileged(N(rem.msig));
   set_privileged(N(rem.token));
   set_privileged(N(rem.auth));

   // Verify rem.msig and rem.token is privileged
   const auto& rem_msig_acc = get<account_metadata_object, by_name>(N(rem.msig));
   BOOST_TEST(rem_msig_acc.is_privileged() == true);
   const auto& rem_token_acc = get<account_metadata_object, by_name>(N(rem.token));
   BOOST_TEST(rem_token_acc.is_privileged() == true);
   const auto& rem_auth_acc = get<account_metadata_object, by_name>(N(rem.auth));
   BOOST_TEST(rem_auth_acc.is_privileged() == true);

   // Create SYS tokens in rem.token, set its manager as rem
   const auto max_supply     = core_from_string("1000000000.0000"); /// 10x larger than 1B initial tokens
   const auto initial_supply = core_from_string("100000000.0000");  /// 10x larger than 1B initial tokens

   create_currency(N(rem.token), config::system_account_name, max_supply);
   // Issue the genesis supply of 1 billion SYS tokens to rem.system
   issue(N(rem.token), config::system_account_name, config::system_account_name, initial_supply);

   auto actual = get_balance(config::system_account_name);
   BOOST_REQUIRE_EQUAL(initial_supply, actual);

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

   // Create genesis accounts
   for( const auto& account : genesis_test ) {
      create_account( account.name, config::system_account_name );
   }

   deploy_contract();

   // Buy ram and stake cpu and net for each genesis accounts
   for( const auto& account : genesis_test ) {
      const auto stake_quantity = account.initial_balance - 1000;

      const auto r = delegate_bandwidth(N(rem.stake), account.name, asset(stake_quantity));
      BOOST_REQUIRE( !r->except_ptr );
   }

   for( const auto& producer : producer_candidates ) {
      register_producer(producer);
   }
   updateauth(N(rem.auth), N(rem.auth));
}

BOOST_AUTO_TEST_SUITE(rem_auth_tests)

BOOST_FIXTURE_TEST_CASE( addkey_test, rem_auth_tester ) {
   try {
      name account = N(proda);
      vector<permission_level> auths_level = { permission_level{account, config::active_name} };
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key key_priv = crypto::private_key::generate();
      crypto::public_key key_pub = key_priv.get_public_key();
      string payer_str = "";
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      sha256 digest = sha256::hash(join( { account.to_string(), string(key_pub), extra_key, payer_str } ));

      auto signed_by_key = key_priv.sign(digest);

      // tokens to pay for torewards action
      transfer(config::system_account_name, account, core_from_string("500.0000"), "initial transfer");
      auto account_balance_before = get_balance(account);

      addkeyacc(account, key_pub, signed_by_key, extra_key, payer_str, auths_level);

      // account balance after addkeyacc should be a account_balance_before -  10.0000 tokens (torewards action)
      auto account_balance_after = get_balance(account);
      auto data = get_authkeys_tbl(account);

      auto ct = control->head_block_time();
      BOOST_REQUIRE_EQUAL(data["owner"].as_string(), account.to_string());
      BOOST_REQUIRE_EQUAL(data["key"].as_string(), string(key_pub));
      BOOST_REQUIRE_EQUAL(data["not_valid_before"].as_string(), string(ct));
      BOOST_REQUIRE_EQUAL(data["not_valid_after"].as_string(), string(ct + seconds(31104000))); // ct + 360 days
      BOOST_REQUIRE_EQUAL(data["extra_key"].as_string(), extra_key);
      BOOST_REQUIRE_EQUAL(data["revoked_at"].as_string(), "0"); // if not revoked == 0
      BOOST_REQUIRE_EQUAL(account_balance_before - core_from_string("10.0000"), account_balance_after); // producers reward = 10

      // action's authorizing actor 'fail' does not exist
      BOOST_REQUIRE_THROW(
         addkeyacc( account, key_pub, signed_by_key, extra_key, payer_str,
                 { permission_level{N(fail), config::active_name} } ),
                 transaction_exception);
      // Missing authority of prodb
      BOOST_REQUIRE_THROW(
         addkeyacc( account, key_pub, signed_by_key, extra_key, "prodb",
                 { permission_level{account, config::active_name} } ),
                 missing_auth_exception);
      // Missing authority of proda
      BOOST_REQUIRE_THROW(
         addkeyacc( account, key_pub, signed_by_key, extra_key, "prodb",
                    { permission_level{N(prodb), config::active_name} } ),
         missing_auth_exception);
      // action's authorizing actor '' does not exist
      BOOST_REQUIRE_THROW(
         addkeyacc( account, key_pub, signed_by_key, extra_key, "prodb", { permission_level{} } ),
                    transaction_exception);
      // Error expected key different than recovered key
      BOOST_REQUIRE_THROW(
         addkeyacc( account, get_public_key(N(prodb), "active"), signed_by_key, extra_key, payer_str, auths_level ),
                 crypto_api_exception);
      // overdrawn balance
      transfer(account, config::system_account_name, core_from_string("485.0000"), "too small balance test");
      BOOST_REQUIRE_THROW(
         addkeyacc( account, key_pub, signed_by_key, extra_key, payer_str, auths_level ),
                 eosio_assert_message_exception);
   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( appaddkey_with_another_payer_test, rem_auth_tester ) {
   try {
      name account = N(proda);
      name payer = N(prodb);
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key key_priv = crypto::private_key::generate();
      crypto::public_key key_pub = key_priv.get_public_key();
      vector<permission_level> auths_level = { permission_level{account, config::active_name},
                                               permission_level{payer, config::active_name} };
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      // tokens to pay for torewards action
      transfer(config::system_account_name, payer, core_from_string("500.0000"), "initial transfer");
      auto payer_balance_before = get_balance(payer);

      sha256 digest = sha256::hash(join( { account.to_string(), string(key_pub), extra_key, payer.to_string() } ));

      auto signed_by_key = key_priv.sign(digest);

      // add account (proda) key to the table with payer prodb
      addkeyacc(account, key_pub, signed_by_key, extra_key, payer.to_string(), auths_level);

      // payer balance after addkeyapp should be a account_balance_before -  10.0000 tokens (torewards action)
      auto payer_balance_after = get_balance(payer);
      auto data = get_authkeys_tbl(account);

      auto ct = control->head_block_time();
      BOOST_REQUIRE_EQUAL(data["owner"].as_string(), account.to_string());
      BOOST_REQUIRE_EQUAL(data["key"].as_string(), string(key_pub));
      BOOST_REQUIRE_EQUAL(data["not_valid_before"].as_string(), string(ct));
      BOOST_REQUIRE_EQUAL(data["not_valid_after"].as_string(), string(ct + seconds(31104000))); // ct + 360 days
      BOOST_REQUIRE_EQUAL(data["extra_key"].as_string(), extra_key);
      BOOST_REQUIRE_EQUAL(data["revoked_at"].as_string(), "0"); // if not revoked == 0
      BOOST_REQUIRE_EQUAL(payer_balance_before - core_from_string("10.0000"), payer_balance_after); // producers reward = 10

      // overdrawn balance
      transfer(payer, config::system_account_name, core_from_string("485.0000"), "too small balance test");
      BOOST_REQUIRE_THROW(
         addkeyacc( account, key_pub, signed_by_key, extra_key, payer.to_string(), auths_level ),
                    eosio_assert_message_exception);
   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( addkeyapp_test, rem_auth_tester ) {
   try {
      name account = N(proda);
      vector<permission_level> auths_level = { permission_level{N(prodb), config::active_name} }; // prodb as a executor
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key new_key_priv = crypto::private_key::generate();
      crypto::private_key key_priv = crypto::private_key::generate();
      crypto::public_key new_key_pub = new_key_priv.get_public_key();
      crypto::public_key key_pub = key_priv.get_public_key();
      string payer_str = "";
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      sha256 digest_addkeyacc = sha256::hash(join( { account.to_string(), string(key_pub), extra_key, payer_str } ));

      sha256 digest_addkeyapp = sha256::hash(join({ account.to_string(), string(new_key_pub), extra_key,
                                                    string(key_pub), payer_str }) );

      auto signed_by_key = key_priv.sign(digest_addkeyacc);
      auto signed_by_new_key_app = new_key_priv.sign(digest_addkeyapp);
      auto signed_by_key_app = key_priv.sign(digest_addkeyapp);

      // tokens to pay for torewards action
      transfer(config::system_account_name, account, core_from_string("500.0000"), "initial transfer");
      auto account_balance_before = get_balance(account);

      addkeyacc(account, key_pub, signed_by_key, extra_key, payer_str, { permission_level{account, config::active_name} });
      addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                key_pub, signed_by_key_app, payer_str, auths_level);

      // account balance after addkeyapp should be a account_balance_before -  10.0000 tokens (torewards action)
      auto account_balance_after = get_balance(account);
      auto data = get_authkeys_tbl(account);

      auto ct = control->head_block_time();
      BOOST_REQUIRE_EQUAL(data["owner"].as_string(), account.to_string());
      BOOST_REQUIRE_EQUAL(data["key"].as_string(), string(new_key_pub));
      BOOST_REQUIRE_EQUAL(data["not_valid_before"].as_string(), string(ct));
      BOOST_REQUIRE_EQUAL(data["not_valid_after"].as_string(), string(ct + seconds(31104000))); // ct + 360 days
      BOOST_REQUIRE_EQUAL(data["extra_key"].as_string(), extra_key);
      BOOST_REQUIRE_EQUAL(data["revoked_at"].as_string(), "0"); // if not revoked == 0
      BOOST_REQUIRE_EQUAL(account_balance_before - core_from_string("20.0000"), account_balance_after); // producers reward = 10

      // Missing required authority payer
      BOOST_REQUIRE_THROW(
         addkeyapp( account, new_key_pub, signed_by_new_key_app, extra_key,
                    key_pub, signed_by_key_app, "accountnum3", auths_level),
                    missing_auth_exception );
      // character is not in allowed character set for names
      BOOST_REQUIRE_THROW(
         addkeyapp( account, new_key_pub, signed_by_new_key_app, extra_key,
                    key_pub, signed_by_key_app, "dlas*fas.", auths_level),
                    eosio_assert_message_exception );
      // action's authorizing actor 'fail' does not exist
      BOOST_REQUIRE_THROW(
         addkeyapp( account, new_key_pub, signed_by_new_key_app, extra_key,
                    key_pub, signed_by_key_app, payer_str, { permission_level{N(fail), config::active_name} }),
                    transaction_exception );
      // action's authorizing actor '' does not exist
      BOOST_REQUIRE_THROW(
         addkeyapp( account, new_key_pub, signed_by_new_key_app, extra_key,
                    key_pub, signed_by_key_app, payer_str, { permission_level{} } ),
                    transaction_exception);
      // expected key different than recovered new key
      BOOST_REQUIRE_THROW(
         addkeyapp( account, get_public_key(N(prodb), "active"), signed_by_new_key_app, extra_key,
                    key_pub, signed_by_key_app, payer_str, auths_level ),
                    eosio_assert_message_exception);
      // expected key different than recovered user key
      BOOST_REQUIRE_THROW(
         addkeyapp( account, new_key_pub, signed_by_new_key_app, extra_key,
                    get_public_key(N(prodb)), signed_by_key_app, payer_str, auths_level ),
                    eosio_assert_message_exception);
//    overdrawn balance
      transfer(account, config::system_account_name, core_from_string("480.0000"), "too small balance test");
      BOOST_REQUIRE_THROW(
         addkeyapp( account, new_key_pub, signed_by_new_key_app, extra_key,
                    key_pub, signed_by_key_app, payer_str, auths_level ),
                    eosio_assert_message_exception);
   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( addkeyapp_require_app_auth_test, rem_auth_tester ) {
   try{
      name account = N(proda);
      vector<permission_level> auths_level = { permission_level{N(prodb), config::active_name} }; // prodb as a executor
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key new_key_priv = crypto::private_key::generate();
      crypto::public_key new_key_pub = new_key_priv.get_public_key();
      crypto::private_key key_priv = crypto::private_key::generate();
      crypto::public_key key_pub = key_priv.get_public_key();
      string payer_str = "";
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      sha256 digest_addkeyacc = sha256::hash(join( { account.to_string(), string(key_pub), extra_key, payer_str } ));

      sha256 digest_addkeyapp = sha256::hash(join({ account.to_string(), string(new_key_pub), extra_key,
                                                    string(key_pub), payer_str }) );

      auto signed_by_key = key_priv.sign(digest_addkeyacc);
      auto signed_by_new_key_app = new_key_priv.sign(digest_addkeyapp);
      auto signed_by_key_app = key_priv.sign(digest_addkeyapp);

      // tokens to pay for torewards action
      transfer(config::system_account_name, account, core_from_string("500.0000"), "initial transfer");

      // account has no linked app keys
      BOOST_REQUIRE_THROW(
         addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                   key_pub, signed_by_key_app, payer_str, auths_level),
                   eosio_assert_message_exception);

      // Add new key to account
      addkeyacc(account, key_pub, signed_by_key, extra_key, payer_str, { permission_level{account, config::active_name} });

      crypto::private_key nonexistkey_priv = crypto::private_key::generate();
      crypto::public_key nonexistkey_pub = nonexistkey_priv.get_public_key();
      sha256 nonexist_digest = sha256::hash(join({ account.to_string(), string(new_key_pub), extra_key,
                                                    string(nonexistkey_pub), payer_str }) );

      signed_by_new_key_app = new_key_priv.sign(nonexist_digest);
      auto signed_by_nonexistkey_app = nonexistkey_priv.sign(nonexist_digest);

      // account has no active app keys (nonexist key)
      BOOST_REQUIRE_THROW(
         addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                   nonexistkey_pub, signed_by_nonexistkey_app, payer_str, auths_level),
                   eosio_assert_message_exception);

      // key_lifetime 360 days
      produce_min_num_of_blocks_to_spend_time_wo_inactive_prod(fc::seconds(31104000));

      signed_by_new_key_app = new_key_priv.sign(digest_addkeyapp);
      // account has no active app keys (expired key)
      BOOST_REQUIRE_THROW(
         addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                   key_pub, signed_by_key_app, payer_str, auths_level),
                   eosio_assert_message_exception);

      addkeyacc(account, key_pub, signed_by_key, extra_key, payer_str, { permission_level{account, config::active_name} });
      revokeacc(account, key_pub, { permission_level{account, config::active_name} });

      // account has no active app keys (revoked)
      BOOST_REQUIRE_THROW(
         addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                   key_pub, signed_by_key_app, payer_str, auths_level),
                   eosio_assert_message_exception);
   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( addkeyapp_with_another_payer_test, rem_auth_tester ) {
   try {
      name account = N(proda);
      name payer = N(prodb);
      vector<permission_level> auths_level = { permission_level{payer, config::active_name} }; // prodb as a executor
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key new_key_priv = crypto::private_key::generate();
      crypto::private_key key_priv = crypto::private_key::generate();
      crypto::public_key new_key_pub = new_key_priv.get_public_key();
      crypto::public_key key_pub = key_priv.get_public_key();
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      sha256 digest_addkeyacc = sha256::hash(join( { account.to_string(), string(key_pub), extra_key, payer.to_string() } ));

      sha256 digest_addkeyapp = sha256::hash(join({ account.to_string(), string(new_key_pub), extra_key,
                                                    string(key_pub), payer.to_string() }) );

      auto signed_by_key = key_priv.sign(digest_addkeyacc);
      auto signed_by_new_key_app = new_key_priv.sign(digest_addkeyapp);
      auto signed_by_key_app = key_priv.sign(digest_addkeyapp);

      // tokens to pay for torewards action
      transfer(config::system_account_name, payer, core_from_string("500.0000"), "initial transfer");
      auto payer_balance_before = get_balance(payer);

      addkeyacc(account, key_pub, signed_by_key, extra_key, payer.to_string(),
                { permission_level{account, config::active_name}, permission_level{payer, config::active_name} });
      addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                key_pub, signed_by_key_app, payer.to_string(), auths_level);

      // account balance after addkeyapp should be a account_balance_before -  10.0000 tokens (torewards action)
      auto payer_balance_after = get_balance(payer);
      auto data = get_authkeys_tbl(account);

      auto ct = control->head_block_time();
      BOOST_REQUIRE_EQUAL(data["owner"].as_string(), account.to_string());
      BOOST_REQUIRE_EQUAL(data["key"].as_string(), string(new_key_pub));
      BOOST_REQUIRE_EQUAL(data["not_valid_before"].as_string(), string(ct));
      BOOST_REQUIRE_EQUAL(data["not_valid_after"].as_string(), string(ct + seconds(31104000))); // ct + 360 days
      BOOST_REQUIRE_EQUAL(data["extra_key"].as_string(), extra_key);
      BOOST_REQUIRE_EQUAL(data["revoked_at"].as_string(), "0"); // if not revoked == 0
      BOOST_REQUIRE_EQUAL(payer_balance_before - core_from_string("20.0000"), payer_balance_after); // producers reward = 10
   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( revokedacc_test, rem_auth_tester ) {
   try {
      name account = N(proda);
      vector<permission_level> auths_level = { permission_level{account, config::active_name} };
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key key_priv = crypto::private_key::generate();
      crypto::public_key key_pub = key_priv.get_public_key();
      string payer_str = "";
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      sha256 digest = sha256::hash(join( { account.to_string(), string(key_pub), extra_key, payer_str } ));

      auto signed_by_key = key_priv.sign(digest);

      // tokens to pay for torewards action
      transfer(config::system_account_name, account, core_from_string("500.0000"), "initial transfer");
      auto account_balance_before = get_balance(account);

      addkeyacc(account, key_pub, signed_by_key, extra_key, payer_str, auths_level);
      time_point ct = control->head_block_time();

      revokeacc(account, key_pub, { permission_level{account, config::active_name} });

      auto account_balance_after = get_balance(account);
      auto data = get_authkeys_tbl(account);

      BOOST_REQUIRE_EQUAL(data["owner"].as_string(), account.to_string());
      BOOST_REQUIRE_EQUAL(data["key"].as_string(), string(key_pub));
      BOOST_REQUIRE_EQUAL(data["not_valid_before"].as_string(), string(ct));
      BOOST_REQUIRE_EQUAL(data["not_valid_after"].as_string(), string(ct + seconds(31104000))); // ct + 360 days
      BOOST_REQUIRE_EQUAL(data["extra_key"].as_string(), extra_key);
      BOOST_REQUIRE_EQUAL(data["revoked_at"].as_string(), std::to_string(ct.sec_since_epoch()) ); // if not revoked == 0
      BOOST_REQUIRE_EQUAL(account_balance_before - core_from_string("10.0000"), account_balance_after); // producers reward = 10

      // Missing required authority account
      BOOST_REQUIRE_THROW(
         revokeacc(account, key_pub, { permission_level{N(prodb), config::active_name} }), missing_auth_exception
      );

      crypto::private_key nonexistkey_priv = crypto::private_key::generate();
      crypto::public_key nonexistkey_pub = key_priv.get_public_key();
      // account has no active app keys
      BOOST_REQUIRE_THROW(
         revokeacc(account, nonexistkey_pub, auths_level), eosio_assert_message_exception
      );
      // account has no active app keys (revoke again same key)
      BOOST_REQUIRE_THROW(
         revokeacc(account, key_pub, auths_level), eosio_assert_message_exception
      );

   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( revokedapp_test, rem_auth_tester ) {
   try {
      name account = N(proda);
      vector<permission_level> auths_level = { permission_level{N(prodb), config::active_name} };
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key revoke_key_priv = crypto::private_key::generate();
      crypto::public_key revoke_key_pub = revoke_key_priv.get_public_key();
      string payer_str = "";
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      sha256 addkeyacc_digest = sha256::hash(join( { account.to_string(), string(revoke_key_pub), extra_key, payer_str } ));
      sha256 revokeapp_digest = sha256::hash(join( { account.to_string(), string(revoke_key_pub), string(revoke_key_pub) } ));

      auto signed_by_addkey = revoke_key_priv.sign(addkeyacc_digest);
      auto signed_by_revkey = revoke_key_priv.sign(revokeapp_digest);

      // tokens to pay for torewards action
      transfer(config::system_account_name, account, core_from_string("500.0000"), "initial transfer");
      auto account_balance_before = get_balance(account);

      addkeyacc(account, revoke_key_pub, signed_by_addkey, extra_key, payer_str, { permission_level{account, config::active_name} });
      time_point ct = control->head_block_time();

      // revoke key and sign digest by revoke key
      revokeapp(account, revoke_key_pub, revoke_key_pub, signed_by_revkey, auths_level);

      auto account_balance_after = get_balance(account);
      auto data = get_authkeys_tbl(account);

      BOOST_REQUIRE_EQUAL(data["owner"].as_string(), account.to_string());
      BOOST_REQUIRE_EQUAL(data["key"].as_string(), string(revoke_key_pub));
      BOOST_REQUIRE_EQUAL(data["not_valid_before"].as_string(), string(ct));
      BOOST_REQUIRE_EQUAL(data["not_valid_after"].as_string(), string(ct + seconds(31104000))); // ct + 360 days
      BOOST_REQUIRE_EQUAL(data["extra_key"].as_string(), extra_key);
      BOOST_REQUIRE_EQUAL(data["revoked_at"].as_string(), std::to_string(ct.sec_since_epoch()) ); // if not revoked == 0
      BOOST_REQUIRE_EQUAL(account_balance_before - core_from_string("10.0000"), account_balance_after); // producers reward = 10

      // add new key to test revokeapp throw
      addkeyacc(account, revoke_key_pub, signed_by_addkey, extra_key, payer_str, { permission_level{account, config::active_name} });

      // action's authorizing actor '' does not exist
      BOOST_REQUIRE_THROW(
         revokeapp(account, revoke_key_pub, revoke_key_pub,signed_by_revkey, { permission_level{} }), transaction_exception
      );
      // expected key different than recovered user key
      crypto::private_key nonexistkey_priv = crypto::private_key::generate();
      crypto::public_key nonexistkey_pub = nonexistkey_priv.get_public_key();
      BOOST_REQUIRE_THROW(
         revokeapp(account, nonexistkey_pub, revoke_key_pub, signed_by_revkey, auths_level), eosio_assert_message_exception
      );
      // account has no active app keys (revoke nonexist key)
      revokeapp_digest = sha256::hash(join( { account.to_string(), string(nonexistkey_pub), string(revoke_key_pub) }));
      signed_by_revkey = revoke_key_priv.sign(revokeapp_digest);
      BOOST_REQUIRE_THROW(
         revokeapp(account, nonexistkey_pub, revoke_key_pub,signed_by_revkey, auths_level), eosio_assert_message_exception
      );
      // account has no active app keys (revoke again same key)
      revokeapp_digest = sha256::hash(join( { account.to_string(), string(revoke_key_pub), string(revoke_key_pub) } ));
      signed_by_revkey = revoke_key_priv.sign(revokeapp_digest);
      revokeapp(account, revoke_key_pub, revoke_key_pub, signed_by_revkey, auths_level);
      BOOST_REQUIRE_THROW(
         revokeapp(account, revoke_key_pub, revoke_key_pub, signed_by_revkey, auths_level), eosio_assert_message_exception
      );
   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( revokedapp_and_sign_by_another_key_test, rem_auth_tester ) {
   try {
      name account = N(proda);
      vector<permission_level> auths_level = { permission_level{N(prodb), config::active_name} };
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key key_priv = crypto::private_key::generate();
      crypto::public_key key_pub = key_priv.get_public_key();
      crypto::private_key revoke_key_priv = crypto::private_key::generate();
      crypto::public_key revoke_key_pub = revoke_key_priv.get_public_key();
      string payer_str = "";
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      sha256 addkeyacc_digest = sha256::hash(join( { account.to_string(), string(key_pub), extra_key, payer_str } ));
      sha256 revokeapp_digest = sha256::hash(join( { account.to_string(), string(revoke_key_pub), string(key_pub) } ));

      auto signed_by_addkey = key_priv.sign(addkeyacc_digest);
      auto signed_by_revkey = key_priv.sign(revokeapp_digest);

      // tokens to pay for torewards action
      transfer(config::system_account_name, account, core_from_string("500.0000"), "initial transfer");
      auto account_balance_before = get_balance(account);

      // Add key_pub
      addkeyacc(account, key_pub, signed_by_addkey, extra_key, payer_str, { permission_level{account, config::active_name} });
      // Add revoke_key_pub
      addkeyacc_digest = sha256::hash(join( { account.to_string(), string(revoke_key_pub), extra_key, payer_str } ));
      signed_by_addkey = revoke_key_priv.sign(addkeyacc_digest);
      produce_blocks();
      addkeyacc(account, revoke_key_pub, signed_by_addkey, extra_key, payer_str, { permission_level{account, config::active_name} });
      time_point ct = control->head_block_time();


      // revoke key and sign digest by key
      revokeapp(account, revoke_key_pub, key_pub, signed_by_revkey, auths_level);

      auto account_balance_after = get_balance(account);
      auto data = get_authkeys_tbl(account);

      BOOST_REQUIRE_EQUAL(data["owner"].as_string(), account.to_string());
      BOOST_REQUIRE_EQUAL(data["key"].as_string(), string(revoke_key_pub));
      BOOST_REQUIRE_EQUAL(data["not_valid_before"].as_string(), string(ct));
      BOOST_REQUIRE_EQUAL(data["not_valid_after"].as_string(), string(ct + seconds(31104000))); // ct + 360 days
      BOOST_REQUIRE_EQUAL(data["extra_key"].as_string(), extra_key);
      BOOST_REQUIRE_EQUAL(data["revoked_at"].as_string(), std::to_string(ct.sec_since_epoch()) ); // if not revoked == 0
      BOOST_REQUIRE_EQUAL(account_balance_before - core_from_string("20.0000"), account_balance_after); // producers reward = 10
   } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( revoke_require_app_auth_test, rem_auth_tester ) {
   try {
      name account = N(proda);
      vector<permission_level> auths_level = { permission_level{N(prodb), config::active_name} }; // prodb as a executor
      // set account permission rem@code to the rem.auth (allow to execute the action on behalf of the account to rem.auth)
      updateauth(account, N(rem.auth));
      crypto::private_key new_key_priv = crypto::private_key::generate();
      crypto::public_key new_key_pub = new_key_priv.get_public_key();
      crypto::private_key key_priv = crypto::private_key::generate();
      crypto::public_key key_pub = key_priv.get_public_key();
      string payer_str = "";
      string extra_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZDXel8Nh0xnGOo39XE3Jqdi6iQpxRs\n"
                         "/r82O1HnpuJFd/jyM3iWInPZvmOnPCP3/Nx4fRNj1y0U9QFnlfefNeECAwEAAQ==";

      sha256 digest_addkeyacc = sha256::hash(join( { account.to_string(), string(key_pub), extra_key, payer_str } ));

      sha256 digest_addkeyapp = sha256::hash(join({ account.to_string(), string(new_key_pub), extra_key,
                                                    string(key_pub), payer_str }) );

      auto signed_by_key = key_priv.sign(digest_addkeyacc);
      auto signed_by_new_key_app = new_key_priv.sign(digest_addkeyapp);
      auto signed_by_key_app = key_priv.sign(digest_addkeyapp);

      // tokens to pay for torewards action
      transfer(config::system_account_name, account, core_from_string("500.0000"), "initial transfer");

      // account has no linked app keys
      BOOST_REQUIRE_THROW(
         addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                   key_pub, signed_by_key_app, payer_str, auths_level),
                   eosio_assert_message_exception);

      // Add new key to account
      addkeyacc(account, key_pub, signed_by_key, extra_key, payer_str, { permission_level{account, config::active_name} });

      crypto::private_key nonexistkey_priv = crypto::private_key::generate();
      crypto::public_key nonexistkey_pub = nonexistkey_priv.get_public_key();
      sha256 nonexist_digest = sha256::hash(join({ account.to_string(), string(new_key_pub), extra_key,
                                                   string(nonexistkey_pub), payer_str }) );

      signed_by_new_key_app = new_key_priv.sign(nonexist_digest);
      auto signed_by_nonexistkey_app = nonexistkey_priv.sign(nonexist_digest);

      // account has no active app keys (nonexist key)
      BOOST_REQUIRE_THROW(
         addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                   nonexistkey_pub, signed_by_nonexistkey_app, payer_str, auths_level),
                   eosio_assert_message_exception);

      // key_lifetime 360 days
      produce_min_num_of_blocks_to_spend_time_wo_inactive_prod(fc::seconds(31104000));

      signed_by_new_key_app = new_key_priv.sign(digest_addkeyapp);
      // account has no active app keys (expired key)
      BOOST_REQUIRE_THROW(
         addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                   key_pub, signed_by_key_app, payer_str, auths_level),
                   eosio_assert_message_exception);

      addkeyacc(account, key_pub, signed_by_key, extra_key, payer_str, { permission_level{account, config::active_name} });
      revokeacc(account, key_pub, { permission_level{account, config::active_name} });

      // account has no active app keys (revoked)
      BOOST_REQUIRE_THROW(
         addkeyapp(account, new_key_pub, signed_by_new_key_app, extra_key,
                   key_pub, signed_by_key_app, payer_str, auths_level),
                   eosio_assert_message_exception);
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_SUITE_END()
