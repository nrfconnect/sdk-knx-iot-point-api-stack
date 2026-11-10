/*
 * libFuzzer harness for oc_core_find_next_go_table_index_with_ga()
 * (api/oc_knx_fp.c).
 *
 * Every received s-mode group-communication telegram carries a group address
 * that is matched against the Group Object Table via this function to find
 * the local resource(s) it targets - pre-authentication for unsecured
 * multicast, and it walks caller-owned variable-length GA arrays per entry.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "api/oc_knx_fp.h"

#define MAX_ENTRIES 8
#define MAX_GA_PER_ENTRY 6

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* Layout: 4 bytes target GA, then repeating (int32 id, uint8 ga_count,
   * ga_count * uint32 ga values) records, one per table slot. */
  if (size < 4) {
    return 0;
  }

  uint32_t target_ga;
  memcpy(&target_ga, data, sizeof(target_ga));
  data += sizeof(target_ga);
  size -= sizeof(target_ga);

  int total = oc_core_get_group_object_table_total_size();
  int slots = total < MAX_ENTRIES ? total : MAX_ENTRIES;

  uint32_t ga_bufs[MAX_ENTRIES][MAX_GA_PER_ENTRY];
  int used_slots = 0;

  for (int i = 0; i < slots; i++) {
    oc_group_object_table_t *e = oc_core_get_group_object_table_entry(i);
    e->id = -1;
    e->ga = NULL;
    e->ga_len = 0;

    if (size < sizeof(int32_t) + 1) {
      continue;
    }

    int32_t id;
    memcpy(&id, data, sizeof(id));
    data += sizeof(id);
    size -= sizeof(id);

    uint8_t ga_count = data[0] % (MAX_GA_PER_ENTRY + 1);
    data += 1;
    size -= 1;

    if (size < ga_count * sizeof(uint32_t)) {
      break;
    }

    for (uint8_t g = 0; g < ga_count; g++) {
      memcpy(&ga_bufs[i][g], data, sizeof(uint32_t));
      data += sizeof(uint32_t);
      size -= sizeof(uint32_t);
    }

    e->id = id;
    e->ga = ga_bufs[i];
    e->ga_len = ga_count;
    used_slots = i + 1;
  }

  for (int current = -2; current <= slots; current++) {
    oc_core_find_next_go_table_index_with_ga(target_ga, current);
  }

  /* Leave the shared table in a clean, empty state for the next iteration. */
  for (int i = 0; i < used_slots; i++) {
    oc_group_object_table_t *e = oc_core_get_group_object_table_entry(i);
    e->id = -1;
    e->ga = NULL;
    e->ga_len = 0;
  }

  return 0;
}
