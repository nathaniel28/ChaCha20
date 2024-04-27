#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <immintrin.h>

#define ROTL32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) \
	a += b; d ^= a; d = ROTL32(d, 16); \
	c += d; b ^= c; b = ROTL32(b, 12); \
	a += b; d ^= a; d = ROTL32(d, 8); \
	c += d; b ^= c; b = ROTL32(b, 7)

static inline __attribute__((always_inline)) void chacha20_init_state(uint32_t *state, const uint32_t *key, const uint32_t counter, const uint32_t *nonce) {
	state[0] = 0x61707865;
	state[1] = 0x3320646e;
	state[2] = 0x79622d32;
	state[3] = 0x6b206574;
	state[4] = key[0];
	state[5] = key[1];
	state[6] = key[2];
	state[7] = key[3];
	state[8] = key[4];
	state[9] = key[5];
	state[10] = key[6];
	state[11] = key[7];
	state[12] = counter;
	state[13] = nonce[0];
	state[14] = nonce[1];
	state[15] = nonce[2];
}

static inline __attribute__((always_inline)) void chacha20_inner_block(uint32_t *state) {
	// column rounds
	QR(state[0], state[4], state[8], state[12]);
	QR(state[1], state[5], state[9], state[13]);
	QR(state[2], state[6], state[10], state[14]);
	QR(state[3], state[7], state[11], state[15]);
	// diagonal rounds
	QR(state[0], state[5], state[10], state[15]);
	QR(state[1], state[6], state[11], state[12]);
	QR(state[2], state[7], state[8], state[13]);
	QR(state[3], state[4], state[9], state[14]);
}

typedef uint32_t v16i32 __attribute__((vector_size(512)));

static inline __attribute__((always_inline)) void chacha20_block(uint32_t *state) {
	uint32_t working_state[16];
	for (int i = 0; i < 16; i++) {
		working_state[i] = state[i];
	}
	for (int i = 0; i < 10; i++) {
		chacha20_inner_block(working_state);
	}
	__m512i vstate = _mm512_loadu_epi32(state);
	__m512i vworking_state = _mm512_loadu_epi32(working_state);
	vstate = _mm512_add_epi32(vstate, vworking_state);
	_mm512_storeu_epi32(state, vstate);
	/*
	for (int i = 0; i < 16; i++) {
		state[i] += working_state[i];
	}
	*/
}

uint32_t chacha20_encrypt(const uint32_t *key, const uint32_t counter, const uint32_t *nonce, void *_plaintext, void *_store, size_t cnt) {
	uint8_t *plaintext = _plaintext;
	uint8_t *store = _store;
	uint32_t state[16];
	const size_t lp = cnt / sizeof state + 1;
	for (size_t i = 0; i < lp; i++) {
		chacha20_init_state(state, key, counter + i, nonce);
		chacha20_block(state);
		const uint8_t *key_stream = (uint8_t *) state;
		const size_t chunk = cnt < sizeof state ? cnt : sizeof state;
		const size_t blk_offset = i * sizeof state;
		for (size_t j = 0; j < chunk; j++) {
			const size_t offset = j + blk_offset;
			store[offset] = plaintext[offset] ^ key_stream[j];
		}
		cnt -= sizeof state;
	}
	explicit_bzero(state, sizeof state);
	return counter + lp;
}

// in key u32[8]
// inout _counter u32[1]
// in nonce u32[3]
ssize_t chacha20_encrypt_file_overwrite(int fd, const uint32_t *key, uint32_t *_counter, const uint32_t *nonce) {
	uint8_t buf[4096];
	ssize_t n;
	ssize_t wrote = 0;
	uint32_t counter = *_counter;
	while ((n = read(fd, buf, sizeof buf)) > 0) {
		counter = chacha20_encrypt(key, counter, nonce, buf, buf, n);
		if (lseek(fd, -n, SEEK_CUR) == -1)
			return -wrote;
		ssize_t m = write(fd, buf, n);
		if (m == -1)
			return -wrote;
		wrote += m;
		if (n != m)
			return -wrote;
	}
	*_counter = counter;
	return wrote;
}

#endif
