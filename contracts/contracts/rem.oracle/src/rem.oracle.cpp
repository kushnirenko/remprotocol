/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.oracle/rem.oracle.hpp>
#include <rem.system/rem.system.hpp>

namespace eosio {
   oracle::oracle(name receiver, name code,  datastream<const char*> ds)
   :contract(receiver, code, ds),
   remusd_tbl(_self, _self.value),
   pricedata_tbl(_self, _self.value) {
      price_data = pricedata_tbl.exists() ? pricedata_tbl.get() : pricedata{};
   }

   void oracle::setprice(const name& producer, const uint64_t& price) {
      require_auth(producer);
      vector<name> _producers = eosio::get_active_producers();
      bool is_producer = std::find(_producers.begin(), _producers.end(), producer) != _producers.end();
      check(is_producer, "block producer authorization required");

      price_data.price_points[producer] = price;
      price_data.last_update = current_time_point();
      pricedata_tbl.set(price_data, producer);
   }

   uint64_t oracle::get_median(vector<int> points) {
      uint8_t majority = (points.size() * 2 / 3) + 1;
      std::sort(points.begin(), points.end());

      vector<uint64_t> delta;
      size_t q = 0;
      for (size_t i = majority; i <= points.size(); ++i) {
         delta.push_back(points[i] - points[q]);
         ++q;
      }
      uint64_t min_delta = std::min_element(delta.begin(), delta.end());
      auto it = std::find(delta.begin(), delta.end(), min_delta);
      int idx_min_delta = std::distance(delta.begin(), it);
   }

   vector<name> oracle::get_map_keys(const std::map<name, uint64_t>& map_in)const {
      vector<name> keys;

      transform(map_in.begin(), map_in.end(), back_inserter(keys),
         [](auto const& pair) {
            return pair.first;
      });
      return keys;
   }

   void oracle::cleartable() {
      pricedata_tbl.remove();
   }
} /// namespace eosio

EOSIO_DISPATCH( eosio::oracle, (setprice)(cleartable) )
