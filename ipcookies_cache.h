#define IPCOOKIE_CACHE_SIZE 65536

typedef struct ipcookie_cache_struct {
  uint16_t entry_count;
  uint8_t padding[14];
  struct ipcookie_entry entries[IPCOOKIE_CACHE_SIZE];
} ipcookie_cache_t;

ipcookie_entry_t *ipcookie_cache_entry_find_by_address(ipcookie_cache_t *ipck, struct in6_addr *peer);
ipcookie_entry_t *ipcookie_cache_entry_allocate(ipcookie_cache_t *ipck, struct in6_addr *peer);



