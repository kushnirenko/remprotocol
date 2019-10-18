/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.oracle/rem.oracle.hpp>
#include <rem.system/rem.system.hpp>

namespace eosio {

   oracle::oracle(name receiver, name code, datastream<const char*> ds)
   :contract(receiver, code, ds),
    remprice_tbl(_self, _self.value),
    pricedata_tbl(_self, _self.value),
    supported_pairs_tbl(_self, _self.value)
    {
      suppdpairs_data = supported_pairs_tbl.exists() ? supported_pairs_tbl.get() : suppdpairs{};
    }

   void oracle::setprice(const name &producer, std::map<name, double> &pairs_data) {
      require_auth(producer);
      check(is_producer(producer), "block producer authorization required");

      vector<name> _producers = eosio::get_active_producers();
      bool is_active_producer = std::find(_producers.begin(), _producers.end(), producer) != _producers.end();
      check_supported_pairs(pairs_data);

      auto data_it = pricedata_tbl.find(producer.value);
      time_point ct = current_time_point();

      if (data_it != pricedata_tbl.end()) {
         uint64_t time_delta = ct.sec_since_epoch() / 3600;
         uint64_t frequency = data_it->last_update.to_time_point().sec_since_epoch() / 3600;
         check(time_delta > frequency, "the frequency of price changes should not exceed 1 time during the current hour");

         pricedata_tbl.modify(*data_it, producer, [&](auto &p) {
            p.pairs_data = pairs_data;
            p.last_update = ct;
         });
      } else {
         pricedata_tbl.emplace(producer, [&](auto &p) {
            p.producer = producer;
            p.pairs_data = pairs_data;
            p.last_update = ct;
         });
      }

      if (is_active_producer) {
         std::map<name, vector<double>> points = get_relevant_prices();
         auto majority_amount = get_majority_amount();
         uint32_t amount_points = points.begin()->second.size();

         if (amount_points > majority_amount) {
            for (const auto &point: points) {
               double median = get_subset_median(point.second);

               auto price_it = remprice_tbl.find(point.first.value);
               if (price_it != remprice_tbl.end()) {
                  remprice_tbl.modify(*price_it, producer, [&](auto &p) {
                     p.price        = median;
                     p.price_points = point.second;
                     p.last_update  = ct;
                  });
               } else {
                  remprice_tbl.emplace(producer, [&](auto &p) {
                     p.pair         = point.first;
                     p.price        = median;
                     p.price_points = point.second;
                     p.last_update  = ct;
                  });
               }
            }
         }
      }
   }

   void oracle::addsuppdpair(const name &pair) {
      require_auth(_self);

      check(suppdpairs_data.pairs.find(pair) == suppdpairs_data.pairs.end(), "the pair is already supported");
      suppdpairs_data.pairs.insert(pair);
      supported_pairs_tbl.set(suppdpairs_data, _self);
   }

   std::map<name, vector<double>> oracle::get_relevant_prices() const {
      vector <name> _producers = eosio::get_active_producers();
      std::map<name, vector<double>> points_data;

      for (const auto &producer: _producers) {
         auto it = pricedata_tbl.find(producer.value);
         if (it != pricedata_tbl.end()) {

            for (const auto &pair: suppdpairs_data.pairs) {

               if (it->pairs_data.count(pair) == 0) {
                  break;
               }
               points_data[pair].push_back(it->pairs_data.at(pair));
            }
         }
      }
      return points_data;
   }

   double oracle::get_subset_median(vector<double> points) const {
      std::sort(points.begin(), points.end());
      uint8_t majority = get_majority_amount();
      // because the array starts from zero and the last of majority producer in the array will have index array[majority -1]
      // the subset index of the majority producers in the set [..(majority)....], indicates which index the set of the
      // majority is shifted from begin in sorted array points, wheare point - producer
      uint8_t subset = 0;
      double minDelta = points.at(majority - 1) - points.at(0);
      double crt_delta;

      for (uint8_t i = majority; i < points.size(); ++i) {
         crt_delta = points.at(i) - points.at(i - majority + 1);
         if (minDelta > crt_delta) {
            minDelta = crt_delta;
            subset = i - majority + 1;
         }
      }
      double median = get_median(vector<double>(points.begin() + subset, points.begin() + subset + majority));

      return median;
   }

   double oracle::get_median(const vector<double>& sorted_points) const {
      if (sorted_points.size() % 2 == 0) {
         return (sorted_points.at(sorted_points.size() / 2) + sorted_points.at(sorted_points.size() / 2 - 1)) / 2;
      }
      return sorted_points.at(sorted_points.size() / 2);
   }

   uint8_t oracle::get_majority_amount() const {
      uint8_t prods_size = eosio::get_active_producers().size();
      return (prods_size * 2 / 3) + 1;
   }

   bool oracle::is_producer( const name& user ) const {
      eosiosystem::producers_table _producers_table( system_account, system_account.value );
      return _producers_table.find( user.value ) != _producers_table.end();
   }

   void oracle::check_supported_pairs(const std::map<name, double> &pairs) {
      check(pairs.size() == suppdpairs_data.pairs.size(), "incorrect pairs");
      for(const auto &pair: pairs) {
         auto it = suppdpairs_data.pairs.find(pair.first);
         check(it != suppdpairs_data.pairs.end(), "unsupported pairs");
      }
   }

   void oracle::cleartable() {
      supported_pairs_tbl.remove();
   }
} /// namespace eosio

EOSIO_DISPATCH( eosio::oracle, (setprice)(addsuppdpair)(cleartable) )
