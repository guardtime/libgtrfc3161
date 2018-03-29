#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "tsconvert.h"

bool save_file(const char *file_name, const unsigned char *data, size_t length) {
	int fd = -1;

	if (file_name == NULL || data == NULL)
		return false;

	fd = open(file_name, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return false;

	if (write(fd, data, length) != (int)length) {
		close(fd);
		unlink(file_name);
		return false;
	}

	if (ftruncate(fd, length) != 0) {
		close(fd);
		unlink(file_name);
		return false;
	}


	close(fd);
	return true;
}

unsigned char *load_file(const char *file_name, size_t *length) {
	int fd =- 1;
	bool success = false;
	unsigned char *data;

	if (file_name == NULL || length == NULL)
		return NULL;

	fd = open(file_name, O_RDONLY);
	if (fd == -1)
		return NULL;

	unsigned size = lseek(fd, 0L, SEEK_END);
	lseek(fd, 0L, SEEK_SET);

	if (!(data = (unsigned char*)KSI_malloc(size))) {
		close(fd);
		return NULL;
	}

	if (read(fd, data, size) != (int)size)
		goto cleanup;

	*length = size;
	success = true;

cleanup:
	if (fd != -1)
		close(fd);

	if (!success) {
		KSI_free(data);
		return NULL;
	}

	return data;
}


int main(int argc, char **argv) {
	int res = LEGACY_UNKNOWN_ERROR;
	unsigned char *buffer = NULL, *outbuf = NULL;
	size_t file_size = 0;
	KSI_Signature *ksi_signature = NULL;
	KSI_CTX *ctx = NULL;

	if (argc != 3) {
		fprintf(stderr, "Not enough arguments\n\nUsage: %s <inputfile> <outputfile>\n", argv[0]);
		res = LEGACY_INVALID_CMD_PARAM;
		goto cleanup;
	}

	if (!(buffer = load_file(argv[1], &file_size))) {
		fprintf(stderr, "Failed to read data from %s: %s", argv[1], strerror(errno));
		res = LEGACY_IO_ERROR;
		goto cleanup;
	}

	res = KSI_CTX_new(&ctx);
	if (res != KSI_OK) goto cleanup;

	res = convert_signature(ctx, buffer, file_size, &ksi_signature);
	if (res != LEGACY_OK) goto cleanup;

	res = KSI_Signature_serialize(ksi_signature, &outbuf, &file_size);
	if (res != KSI_OK) goto cleanup;

	if (strlen(argv[2]) == 1 && argv[2][0] == '-') {
		if (write(1, outbuf, file_size) != file_size) {
			fprintf(stderr, "Error \"%s\" writing signature to standard output", strerror(errno));
			res = LEGACY_IO_ERROR;
			goto cleanup;
		}
	}
	else {
		if (!save_file(argv[2], outbuf, file_size)) {
			fprintf(stderr, "Failed to write data to %s: %s", argv[1], strerror(errno));
			res = LEGACY_IO_ERROR;
			goto cleanup;
		}
	}
	
	res = LEGACY_OK;

cleanup:

	KSI_free(buffer);
	KSI_free(outbuf);
	KSI_Signature_free(ksi_signature);
	KSI_CTX_free(ctx);

	return res;
}
