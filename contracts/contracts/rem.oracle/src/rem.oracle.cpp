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
      rem_usd = remusd_tbl.exists() ? remusd_tbl.get() : remusd{};
   }

   void oracle::setprice(const name& producer, const double& price) {
      require_auth(producer);
      vector<name> _producers = eosio::get_active_producers();
      bool is_active_producer = std::find(_producers.begin(), _producers.end(), producer) != _producers.end();
      check(is_producer(producer), "block producer authorization required");

      price_data.price_points[producer] = price;
      price_data.last_update = current_time_point();

      if (is_active_producer) {
         vector<double> points = get_relevant_prices();
         auto majority_amount = get_majority_amount();
         if (points.size() > majority_amount) {
            price_data.median = get_subset_median(points);
            rem_usd.price = price_data.median;
            rem_usd.last_update = current_time_point();
            remusd_tbl.set(rem_usd, producer);
         }
      }
      pricedata_tbl.set(price_data, producer);
   }

   vector<double> oracle::get_relevant_prices() const {
      vector<name> _producers = eosio::get_active_producers();
      vector<double> relevant_prices;
      for (const auto& prod: _producers) {
         bool is_exist_point = price_data.price_points.find(prod) != price_data.price_points.end();
         if (is_exist_point) {
            relevant_prices.push_back(price_data.price_points.at(prod));
         }
      }
      return relevant_prices;
   }

   double oracle::get_subset_median(vector<double> points) const {
      std::sort(points.begin(), points.end());
      uint8_t majority = get_majority_amount();
      uint8_t subset = 0;
      double minDelta = points[majority] - points[0];
      double crt;

      for (uint8_t i = majority + 1; i < points.size(); ++i) {
         crt = points[i] - points[i - majority];
         if (minDelta > crt) {
            minDelta = crt;
            subset = i - majority;
         }
      }
      double median = get_median(vector<double>(points.begin() + subset, points.begin() + subset + majority));

      return median;
   }

   double oracle::get_median(const vector<double>& sorted_points) const {
      if (sorted_points.size() % 2 == 0) {
         return (sorted_points[sorted_points.size() / 2] + sorted_points[sorted_points.size() / 2 - 1]) / 2;
      }
      return sorted_points[sorted_points.size() / 2];
   }

   uint8_t oracle::get_majority_amount() const {
      uint8_t prods_size = eosio::get_active_producers().size();
      return (prods_size * 2 / 3) + 1;
   }

   bool oracle::is_producer( const name& user ) const {
      eosiosystem::producers_table _producers_table( system_account, system_account.value );
      return _producers_table.find( user.value ) != _producers_table.end();
   }

   vector<name> oracle::get_active_producers() const {
      eosiosystem::producers_table _producers_table( system_account, system_account.value );
      vector<name> producers;
      for ( auto _table_itr = _producers_table.begin(); _table_itr != _producers_table.end(); ++_table_itr ) {
         producers.push_back( _table_itr->owner );
      }
      return producers;
   }

   vector<name> oracle::get_map_keys(const std::map<name, uint64_t>& map_in) const {
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
