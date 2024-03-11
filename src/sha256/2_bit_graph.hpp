#ifndef _sha256_graph_hpp_INCLUDED
#define _sha256_graph_hpp_INCLUDED

#include "util.hpp"
#include <cassert>
#include <cinttypes>
#include <climits>
#include <cstdint>
#include <iostream>
#include <list>
#include <map>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

namespace SHA256 {
inline vector<int> *
shortest_antecedent (unordered_set<vector<int> *> &antecedents) {
  assert (!antecedents.empty ());
  unsigned long shortest_length = UINT64_MAX;
  vector<int> *shortest_antecedent = NULL;
  for (auto &antecedent : antecedents) {
    assert (antecedent != NULL);
    if (antecedent->size () < shortest_length) {
      shortest_length = antecedent->size ();
      shortest_antecedent = antecedent;
    }
  }
  assert (shortest_antecedent != NULL);
  return shortest_antecedent;
}

struct TwoBitGraphEdgeValue {
  uint8_t diff;
  unordered_set<vector<int> *> antecedents[2];
};
// This graph data structure is written for linear equations between two
// GF(2) variables. Each edge captures the relationship
// (equality/inequality) of two variables, along with the antecedent.
class TwoBitGraph {
  unordered_map<uint32_t, unordered_set<uint32_t>> adj_list;
  // Each edge holds a xor difference and the antecedent of the equation
  map<pair<uint32_t, uint32_t>, TwoBitGraphEdgeValue> edge_values;

public:
  bool add_edge (uint32_t vertex, uint32_t vertex2, uint8_t diff,
                 vector<int> *antecedent,
                 vector<vector<int> *> *blocking_antecedents = NULL) {
    assert (antecedent != NULL);
    auto vertex_it = adj_list.find (vertex);
    auto vertex2_it = adj_list.find (vertex2);
    auto edge_value_it = edge_values.find ({vertex, vertex2});
    auto edge_value_it2 = edge_values.find ({vertex2, vertex});

    // Add the vertices if they don't exist
    if (vertex_it == adj_list.end ()) {
      auto result = adj_list.insert ({vertex, {}});
      vertex_it = result.first;
    }
    if (vertex2_it == adj_list.end ()) {
      auto result = adj_list.insert ({vertex2, {}});
      vertex2_it = result.first;
    }

    // Add the edge
    vertex_it->second.insert (vertex2);
    vertex2_it->second.insert (vertex);

    // Add the edge values instances if they don't exist
    if (edge_value_it == edge_values.end ()) {
      TwoBitGraphEdgeValue new_value;
      new_value.diff = diff;
      new_value.antecedents[diff].insert (antecedent);
      edge_value_it =
          edge_values.insert ({{vertex, vertex2}, new_value}).first;
      edge_value_it2 =
          edge_values.insert ({{vertex2, vertex}, new_value}).first;
    } else {
      // Update existing edge value instance
      edge_value_it->second.antecedents[diff].insert (antecedent);
      edge_value_it2->second.antecedents[diff].insert (antecedent);
    }

    // See if the existing and new edge contradicts (opposite diff.)
    bool is_conflict = false;
    if (!edge_value_it->second.antecedents[diff == 1 ? 0 : 1].empty ()) {
      is_conflict = true;
      // Populate the blocking antecedents
      assert (!edge_value_it->second.antecedents[0].empty ());
      assert (!edge_value_it->second.antecedents[1].empty ());
      *blocking_antecedents = {
          shortest_antecedent (edge_value_it->second.antecedents[0]),
          shortest_antecedent (edge_value_it->second.antecedents[1])};
    }

    return is_conflict;
  }

  void remove_edge (uint32_t vertex, uint32_t vertex2, uint8_t diff,
                    vector<int> *antecedent) {
    auto edge_value_it = edge_values.find ({vertex, vertex2});
    auto edge_value_it2 = edge_values.find ({vertex2, vertex});
    assert (edge_value_it != edge_values.end ());
    assert (edge_value_it2 != edge_values.end ());
    auto &edge_value = edge_value_it->second;
    auto &edge_value2 = edge_value_it2->second;
    edge_value.antecedents[diff].erase (antecedent);
    edge_value2.antecedents[diff].erase (antecedent);

    auto zero_diff_antecedents_count = edge_value.antecedents[0].size ();
    auto one_diff_antecedents_count = edge_value.antecedents[1].size ();

    // Update the diff
    if (zero_diff_antecedents_count == 0 && one_diff_antecedents_count >= 1)
      edge_value.diff = 1;
    else if (zero_diff_antecedents_count >= 1 &&
             one_diff_antecedents_count == 0)
      edge_value.diff = 0;

    // Keep the edge value if there is still an edge
    if ((zero_diff_antecedents_count + one_diff_antecedents_count) >= 1)
      return;

    // Delete the edge
    adj_list[vertex].erase (vertex2);
    adj_list[vertex2].erase (vertex);
    // Delete the vertices with 0 degree
    if (adj_list[vertex].empty ())
      adj_list.erase (vertex);
    if (adj_list[vertex2].empty ())
      adj_list.erase (vertex2);

    // Delete the edge values
    edge_values.erase ({vertex, vertex2});
    edge_values.erase ({vertex2, vertex});
  }

  // !Debug
  unordered_set<vector<int> *> get_antecedents (uint32_t v1, uint32_t v2) {
    if (edge_values.find ({v1, v2}) == edge_values.end ())
      return {};
    auto &edge_value = edge_values[{v1, v2}];
    return edge_value.antecedents[edge_value.diff];
  }

  // Find the shortest inconsistent cycle between two directly connected
  // vertices.
  list<uint32_t> shortest_inconsistent_cycle (
      uint32_t start, uint32_t dest,
      vector<vector<int> *> *blocking_antecedents = NULL) {
    // Start and dest must be directly connected
    assert (adj_list[start].find (dest) != adj_list[start].end ());

    queue<uint32_t> queue;
    unordered_set<uint32_t> visited;
    unordered_map<uint32_t, uint32_t> prev_vertex;
    list<uint32_t> shortest_cycle;

    queue.push (start);

    while (!queue.empty ()) {
      uint32_t current_vertex = queue.front ();
      queue.pop ();
      // We want to re-visit the destination to find multiple cycles
      if (current_vertex != dest)
        visited.insert (current_vertex);

      // Visit the neighbors
      unordered_set<uint32_t> neighbors = adj_list[current_vertex];
      for (uint32_t neighbor : neighbors) {
        // Skip if already visited
        if (visited.find (neighbor) != visited.end ())
          continue;

        // We don't want to go beyond the destination
        if (neighbor != dest)
          queue.push (neighbor);

        // Add to the trail
        prev_vertex[neighbor] = current_vertex;

        // Analyze for contradictions if we reached the destination
        if (current_vertex != start && neighbor == dest) {
          // Sum of differences in GF(2)
          uint8_t diff_sum = edge_values[{start, dest}].diff ^
                             edge_values[{current_vertex, dest}].diff;
          list<uint32_t> path = {current_vertex, dest};
          vector<unordered_set<vector<int> *> *> path_antecedents;
          uint32_t path_start = current_vertex;
          uint32_t current_path_vertex = path_start;
          while (current_path_vertex != start) {
            auto v1 = prev_vertex[current_path_vertex];
            auto v2 = current_path_vertex;

            assert (edge_values.find ({v1, v2}) != edge_values.end ());
            auto &edge_value = edge_values[{v1, v2}];
            auto &path_vertex_antecedents =
                edge_value.antecedents[edge_value.diff];
            assert (!path_vertex_antecedents.empty ());
            path_antecedents.push_back (&path_vertex_antecedents);
            uint8_t diff = edge_value.diff;
            diff_sum ^= diff;

            current_path_vertex = prev_vertex[current_path_vertex];
            assert (current_path_vertex != 0);
            path.push_front (current_path_vertex);
          }

          // Shortest inconsistent cycle detected.
          if (diff_sum == 1) {
            shortest_cycle = path;
            if (blocking_antecedents != NULL) {
              // Direct edge between the start and dest. vertices
              auto &direct_edge = edge_values[{start, dest}];
              auto &direct_edge_antecedents =
                  direct_edge.antecedents[direct_edge.diff];
              assert (!direct_edge_antecedents.empty ());

              auto &path_start_dest_edge = edge_values[{path_start, dest}];
              auto &path_start_dest_edge_antecedents =
                  path_start_dest_edge
                      .antecedents[path_start_dest_edge.diff];
              assert ((!path_start_dest_edge_antecedents.empty ()));
              *blocking_antecedents = {
                  shortest_antecedent (direct_edge_antecedents),
                  shortest_antecedent (path_start_dest_edge_antecedents)};
              for (auto &a : path_antecedents) {
                assert (!a->empty ());
                blocking_antecedents->push_back (shortest_antecedent (*a));
              }
            }

            // Since it's the first through BFS, it must be the shortest.
            return shortest_cycle;
          }
        }
      }
    }

    return {};
  }

  void print () {
    set<pair<uint32_t, uint32_t>> visited;

    for (auto &entry : adj_list) {
      auto v1 = entry.first;
      auto &neighbors = entry.second;
      for (auto &v2 : neighbors) {
        if (visited.find ({v1, v2}) != visited.end ())
          continue;
        assert (edge_values.find ({v1, v2}) != edge_values.end ());
        auto &edge_value = edge_values[{v1, v2}];
        auto diff = edge_value.diff;
        auto &antecedents = edge_value.antecedents[edge_value.diff];
        string antecedents_str;
        for (auto &antecedent : antecedents) {
          assert (antecedent != NULL);
          for (auto &lit : *antecedent)
            antecedents_str += to_string (lit) + " ";
          antecedents_str += ";";
        }
        printf ("%d->%d[color=\"%s\",label=\"%s\"];", v1, v2,
                diff == 1 ? "red" : "black", antecedents_str.c_str ());
        visited.insert ({v1, v2});
        visited.insert ({v2, v1});
      }
    }
    printf ("\n");
  }
};
} // namespace SHA256

#endif