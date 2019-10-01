#pragma once
#include <string>
#include <vector>

#include <fc/variant.hpp>
#include <fc/io/json.hpp>


template<typename T>
std::string decodeAttribute(const std::string& hex)
{
   std::vector<char> data(hex.size() / 2);
   fc::from_hex(hex, data.data(), data.size());
   const auto v = fc::raw::unpack<T>(data);
   return fc::json::to_pretty_string(v);
}