#ifndef IDX_LEN
// To prevent LSP errors when viewing this file.
// In actual generated code, IDX_LEN will be defined
// and this will not be executed by the preprocessor.
#define MAX_CANDIDATE_BUF_LEN 0
#define MAX_MATCH_BUF_LEN 0
#define NUM_TARGET_HASHES 0
#define HASH_BITS 64
#define HASH_FUNCTION murmur64a_sum
#define IDX_LEN 0
#endif

typedef char i8;
typedef unsigned char u8;
typedef short i16;
typedef unsigned short u16;
typedef int i32;
typedef unsigned int u32;
typedef long i64;
typedef unsigned long u64;

#if HASH_BITS == 64
typedef u64 hash_t;
#elif HASH_BITS == 32
typedef u32 hash_t;
#else
#error "HASH_BITS must be 64 or 32"
#endif

// splitmix64 to improve bloom filter effectiveness.
u64 splitmix64(u64 x) {
    u64 z = x + 0x9e3779b97f4a7c15ul;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ul;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebul;
    return z ^ (z >> 31);
}

// Hash functions. d is string as u64 array, n is the number
// of bytes.
//
// We're using u64s so we are guaranteed to have the correct
// alignment when casting to u64 in the murmurhash main loop.
// For unaligned data, the only alternative would be bitwise-oring
// the bytes together, which is quite a lot slower (~30% in
// my testing).
u64 murmur64a_sum(const u64 *d, u32 n) {
#define SEED 0ul
#define MIX 0xc6a4a7935bd1e995ul
#define SHIFTS 47ul

  u64 hash = SEED ^ ((u64)n * MIX);
  
  while (n >= 8) {
    u64 key = *d;
    d += 1;
    n -= 8;

    key *= MIX;
    key ^= key >> SHIFTS;
    key *= MIX;

    hash ^= key;
    hash *= MIX;
  }

  if (n&7) {
    switch (n&7) {
    case 7: hash ^= *d & 0x00fffffffffffffful; break;
    case 6: hash ^= *d & 0x0000fffffffffffful; break;
    case 5: hash ^= *d & 0x000000fffffffffful; break;
    case 4: hash ^= *d & 0x00000000fffffffful; break;
    case 3: hash ^= *d & 0x0000000000fffffful; break;
    case 2: hash ^= *d & 0x000000000000fffful; break;
    case 1: hash ^= *d & 0x00000000000000fful; break;
    }
    hash *= MIX;
  }

  hash ^= hash >> SHIFTS;
  hash *= MIX;
  hash ^= hash >> SHIFTS;

  return hash;

#undef SEED
#undef MIX
#undef SHIFTS
}
u32 murmur64a_thin_sum(const u64 *d, u32 n) {
  return (u32)(murmur64a_sum(d, n) >> 32);
}
u64 datalib_hash_sum(const u64 *d, u32 n) {
  const u8 *b = (u8*)d;
  u32 hash = 5381;
  for (u32 i = 0; i < n; i++) {
    hash = hash*33 + (u32)b[i];
  }
  hash -= 5381;

  // Datalib is technically a 32-bit hash,
  // but we also pack the length since it's
  // known for all the target hashes.
  //
  // Since we have a lot of zeroes in the
  // high 32 bits, we use splitmix to shuffle
  // the bits, improving bloom filter performance.
  return splitmix64(((u64)n << 32) | (u64)hash);
}

void* memcpy_pc(void* dest, __constant void* src, size_t n) {
  char *d = dest;
  __constant char *s = src;
  while (n--) *d++ = *s++;
  return dest;
}
void* memcpy_pg(void* dest, __global const void* src, size_t n) {
  char *d = dest;
  __global const char *s = src;
  while (n--) *d++ = *s++;
  return dest;
}
__global void* memcpy_gp(__global void* dest, const void* src, size_t n) {
  __global char *d = dest;
  const char *s = src;
  while (n--) *d++ = *s++;
  return dest;
}

// Bloom filter to rule out most candidates.
bool bitmap_test(hash_t hash, __global const u32 *hash_bitmap) {
#define BITS 24
  u32 hl = (u32)hash;
  u32 idxl = hl >> (32-(BITS-4));
  u32 bitl = 1 << (hl & 31);
  if (!(hash_bitmap[idxl] & bitl)) return false;
#if HASH_BITS == 64
  u32 hh = (u32)(hash >> 32);
  u32 idxh = hh >> (32-(BITS-4));
  u32 bith = 1 << (hh & 31);
  if (!(hash_bitmap[idxh] & bith)) return false;
#endif
  return true;
#undef BITS
}

// More expensive check if a candidate actually matches
// a target hash.
bool binary_search(hash_t hash, __global const hash_t *target_hashes) {
  u32 lo = 0;
  u32 hi = NUM_TARGET_HASHES;
  while (lo < hi) {
    u32 mid = (lo + hi) >> 1;
    if (target_hashes[mid] < hash)
      lo = mid + 1;
    else
      hi = mid;
  }
  return lo < NUM_TARGET_HASHES && target_hashes[lo] == hash;
}

// Tries the string as a match for a target hash.
// If it is a match, it is written to the match buffer.
//
// Returns false if the try filled up the match buffer
// fully and the kernel function should exit.
bool try(const u64 *s, u32 n, const size_t id, __global const u32 *hash_bitmap, __global const hash_t *target_hashes, __global char *matches, __global u32 *matches_lens) {
  hash_t h = HASH_FUNCTION(s, n);
#ifndef DEBUG_ACCEPT_ALL_AS_MATCH
  // We check the bitmap first (fast, may give false matches)
  // and then do a binary search (slow, tells us exactly
  // whether we have a match).
  if (!bitmap_test(h, hash_bitmap)    ) return true;
  if (!binary_search(h, target_hashes)) return true;
#endif
  if (matches_lens[id]+n+1 > MAX_MATCH_BUF_LEN)
    return false;
  __global char *m = matches + id*MAX_MATCH_BUF_LEN + matches_lens[id];
  memcpy_gp(m, s, n);
  m[n] = 0;
  matches_lens[id] += n+1;
  return true;
}
