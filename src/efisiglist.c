/* Copyright 2012 Red Hat, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author(s): Peter Jones <pjones@redhat.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <popt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "efitypes.h"
#include "siglist.h"

struct hash_param {
	char *name;
	const efi_guid_t *guid;
	int size;
};

static struct hash_param hash_params[] = {
	{.name = "sha256",
	 .guid = &efi_guid_sha256,
	 .size = 32,
	},
	{.name = "sha1",
	 .guid = &efi_guid_sha1,
	 .size = 20,
	},
};
static int n_hash_params = sizeof (hash_params) / sizeof (hash_params[0]);

int
set_hash_parameters(char *value, char *name, int *hash_number)
{
	if (strcmp(name, "help")) {
		for (int i = 0; i < n_hash_params; i++) {
			if (!strcmp(name, hash_params[i].name)) {
				*hash_number = i;
				return 0;
			}
		}
	} else {
		printf("Supported hashes:");
		for (int i = 0; i < n_hash_params; i++)
			printf(" %s", hash_params[i].name);
		printf("\n");
		return 0;
	}
	return -1;
}

static int8_t hexchar_to_bin(char hex)
{
	if (hex >= '0' && hex <= '9')
		return hex - '0';
	if (hex >= 'A' && hex <= 'F')
		return hex - 'A' + 10;
	if (hex >= 'a' && hex <= 'f')
		return hex - 'a' + 10;
	return -1;
}

static uint8_t *
hex_to_bin(char *hex, size_t size)
{
	uint8_t *ret = calloc(1, size+1);
	if (!ret)
		return NULL;

	for (int i = 0, j = 0; i < size*2; i+= 2, j++) {
		uint8_t val;

		val = hexchar_to_bin(hex[i]);
		if (val < 0) {
out_of_range:
			free(ret);
			errno = ERANGE;
			return NULL;
		}
		ret[j] = (val & 0xf) << 4;
		val = hexchar_to_bin(hex[i+1]);
		if (val < 0)
			goto out_of_range;
		ret[j] |= val & 0xf;
	};
	return ret;
}

int
main(int argc, char *argv[])
{
	poptContext optCon;
	efi_guid_t owner = efi_guid_redhat_2;
	int rc;
	char *outfile = NULL;
	char *hash = NULL;
	char *hash_type = "sha256";
	char *certfile = NULL;
	int certfd = -1;
	void *cert_data = NULL;
	size_t cert_size = 0;

	int add = 1;

	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{"outfile", 'o', POPT_ARG_STRING,
			&outfile, 0, "output filename", "<outfile>" },
		{"add", 'a', POPT_ARG_VAL, &add, 1,
			"add hash or certificate to list", NULL },
		{"remove", 'r', POPT_ARG_VAL, &add, 0,
			"remove hash or certificate from list", NULL },
		{"hash", 'h', POPT_ARG_STRING, &hash, 0,
			"hash value to add", "<hash>" },
		{"hash-type", 't', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&hash_type, 0, "hash type to add", "<hash-type>" },
		{"certificate", 'c', POPT_ARG_STRING,
			&certfile, 0, "certificate to add", "<certfile>" },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT)) {
		fprintf(stderr,
			"efisiglist: poptReadDefaultConfig failed: %s\n",
			poptStrerror(rc));
		exit(1);
	}

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1) {
		fprintf(stderr, "efisiglist: Invalid argument: %s: %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
		exit(1);
	}

	if (poptPeekArg(optCon)) {
		fprintf(stderr, "efisiglist: Invalid Argument: \"%s\"\n",
			poptPeekArg(optCon));
		exit(1);
	}

	if (hash && certfile) {
		fprintf(stderr, "efisiglist: hash and certfile cannot be "
			"specified at the same time\n");
		exit(1);
	}

	int outfd = -1;

	if (!outfile) {
		fprintf(stderr, "efisiglist: no output file specified\n");
		exit(1);
	}
	outfd = open(outfile, O_RDWR|O_APPEND|O_CREAT, 0644);
	if (outfd < 0) {
		fprintf(stderr, "efisiglist: could not open \"%s\": %m\n",
			outfile);
		exit(1);
	}

	int hash_index = -1;
	if (hash) {
		rc = set_hash_parameters(hash, hash_type, &hash_index);
		if (rc < 0) {
			fprintf(stderr, "efisiglist: invalid hash type: "
				"\"%s\"\n", hash_type);
			set_hash_parameters(hash, "help", &hash_index);
			exit(1);
		} else if (rc == 0 && hash_index == -1) {
			exit(0);
		}

		int x = strlen(hash);
		if (x != hash_params[hash_index].size * 2) {
			fprintf(stderr, "efisiglist: hash \"%s\" requires "
				"a %d-bit value, but supplied value is "
				"%d bits\n", hash_params[hash_index].name,
				hash_params[hash_index].size * 8, x * 4);
			exit(1);
		}
	} else if (certfile) {
		certfd = open(certfile, O_RDONLY, 0644);
		if (certfd < 0) {
			fprintf(stderr, "efisiglist: could not open \"%s\": "
				"%m\n", certfile);
			exit(1);
		}

		struct stat sb;
		if (fstat(certfd, &sb) < 0) {
			fprintf(stderr, "efisiglist: could not get the size "
				"of \"%s\": %m\n", certfile);
			exit(1);
		}
		cert_size = sb.st_size;

		cert_data = mmap(NULL, cert_size, PROT_READ, MAP_PRIVATE,
				 certfd, 0);
		if (cert_data == MAP_FAILED) {
			fprintf(stderr, "efisiglist: could not map \"%s\": "
				"%m\n", certfile);
			exit(1);
		}
	}

	if (add) {
		if (hash) {
			signature_list *sl = signature_list_new(
					hash_params[hash_index].guid);
			if (!sl) {
				fprintf(stderr, "efisiglist: could not "
					"allocate signature list: %m\n");
				unlink(outfile);
				exit(1);
			}
			uint8_t *binary_hash = hex_to_bin(hash,
				hash_params[hash_index].size);
			if (!binary_hash) {
				fprintf(stderr, "efisiglist: could not "
					"parse hash \"%s\": %m\n", hash);
				unlink(outfile);
				exit(1);
			}
			rc = signature_list_add_sig(sl, owner, binary_hash,
				hash_params[hash_index].size);
			if (rc < 0) {
				fprintf(stderr,"efisiglist: could not add "
					"hash to list: %m\n");
				unlink(outfile);
				exit(1);
			}

			void *blah;
			size_t size = 0;
			rc = signature_list_realize(sl, &blah, &size);
			if (rc < 0) {
				fprintf(stderr, "efisiglist: Could not realize "
					"signature list: %m\n");
				unlink(outfile);
				exit(1);
			}
			rc = write(outfd, blah, size);
			if (rc < 0) {
				fprintf(stderr, "efisiglist: Could not write "
					"signature list: %m\n");
				unlink(outfile);
				exit(1);
			}
			close(outfd);
			exit(0);
		} else if (certfile) {
			efi_guid_t sig_type = efi_guid_x509_cert;
			signature_list *sl = signature_list_new(&sig_type);
			if (!sl) {
				fprintf(stderr, "efisiglist: could not "
					"allocate signature list: %m\n");
				unlink(outfile);
				exit(1);
			}
			rc = signature_list_add_sig(sl, owner, cert_data,
				cert_size);
			if (rc < 0) {
				fprintf(stderr,"efisiglist: could not add "
					"cert to list: %m\n");
				unlink(outfile);
				exit(1);
			}

			void *blah;
			size_t size = 0;
			rc = signature_list_realize(sl, &blah, &size);
			if (rc < 0) {
				fprintf(stderr, "efisiglist: Could not realize "
					"signature list: %m\n");
				unlink(outfile);
				exit(1);
			}
			rc = write(outfd, blah, size);
			if (rc < 0) {
				fprintf(stderr, "efisiglist: Could not write "
					"signature list: %m\n");
				unlink(outfile);
				exit(1);
			}

			munmap(cert_data, cert_size);
			close(certfd);
			close(outfd);
			exit(0);
		}
	}
	exit(1);

	return 0;
}
