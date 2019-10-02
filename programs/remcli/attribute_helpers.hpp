#pragma once
#include <set>
#include <string>
#include <vector>

#include <eosio/chain/chain_id_type.hpp>
#include <fc/variant.hpp>
#include <fc/io/json.hpp>


std::string decodeAttribute(const std::string& hex, int32_t type)
{
   if (hex.empty()) {
      return "";
   }

   std::vector<char> data(hex.size() / 2);
   fc::from_hex(hex, data.data(), data.size());
   fc::variant v;

   switch (type)
   {
      case 0:
         v = fc::raw::unpack<bool>(data);
         break;
      case 1:
         v = fc::raw::unpack<int32_t>(data);
         break;
      case 2:
         v = fc::raw::unpack<int64_t>(data);
         break;
      case 3:
         //TODO: check if we need to use chain_id_type instead of fc::sha256
         v = fc::raw::unpack<std::pair<fc::sha256, eosio::name>>(data);
         break;
      case 4:
         v = fc::raw::unpack<std::string>(data);
         break;
      case 5:
         v = fc::raw::unpack<std::string>(data);
         break;
      case 6:
         v = fc::raw::unpack<std::string>(data);
         break;
      case 7:
         v = fc::raw::unpack<std::string>(data);
         break;
      case 8:
         v = fc::raw::unpack<std::vector<char>>(data);
         break;
      case 9:
         v = fc::raw::unpack<std::set<std::pair<eosio::name, std::string>>>(data);
         break;
      default:
         //TODO: change exception type
         EOS_ASSERT( false, eosio::chain::chain_type_exception, "Unknown attribute type" );
   }
   return fc::json::to_pretty_string(v);
}


std::vector<char> encodeAttribute(const std::string& json, int32_t type)
{
   const auto v = fc::json::from_string(json);
   std::vector<char> bytes;

   if (type == 0) {
      bool b;
      fc::from_variant(v, b);
      bytes = fc::raw::pack(b);
   }
   else if (type == 1) {
      int32_t i;
      fc::from_variant(v, i);
      bytes = fc::raw::pack(i);
   }
   else if (type == 2) {
      int64_t i;
      fc::from_variant(v, i);
      bytes = fc::raw::pack(i);
   }
   else if (type == 3) {
      std::pair<eosio::chain::chain_id_type, eosio::name> p(eosio::chain::chain_id_type(""), eosio::name(0));
      fc::from_variant(v, p);
      bytes = fc::raw::pack(p);
   }
   else if (type == 4) {
      std::string s;
      fc::from_variant(v, s);
      bytes = fc::raw::pack(s);
   }
   else if (type == 5) {
      std::string s;
      fc::from_variant(v, s);
      bytes = fc::raw::pack(s);
   }
   else if (type == 6) {
      std::string s;
      fc::from_variant(v, s);
      bytes = fc::raw::pack(s);
   }
   else if (type == 7) {
      std::string s;
      fc::from_variant(v, s);
      bytes = fc::raw::pack(s);
   }
   else if (type == 8) {
      std::vector<char> vec;
      fc::from_variant(v, vec);
      bytes = fc::raw::pack(vec);
   }
   else if (type == 9) {
      std::set<std::pair<eosio::name, std::string>> s;
      fc::from_variant(v, s);
      bytes = fc::raw::pack(s);
   }

   //TODO: change exception type
   EOS_ASSERT( !bytes.empty(), eosio::chain::chain_type_exception, "Unknown attribute type" );
   return bytes;
}
