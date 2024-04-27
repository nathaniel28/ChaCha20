#include <fcntl.h>

#include "chacha20.h"

int main() {
	int fd = open("dat", O_RDWR);
	if (fd == -1)
		return 0;
	uint32_t key[8] = { 0x1ed1c7b5, 0x0497be4e, 0x41e32726, 0x4f82f4f7, 0xd63f64b4, 0xaeb4bc33, 0x59da47d2, 0xecb40afd };
	uint32_t nonce[3] = { 0x2833b28c, 0x3bdc965c, 0x7ef92d6f };
	uint32_t counter = 1;
	return chacha20_encrypt_file_overwrite(fd, key, &counter, nonce);
}
