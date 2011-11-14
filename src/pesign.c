/*
 * Copyright 2011 Red Hat, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <popt.h>

int main(int argc, char *argv[])
{
	int rc;
	char *infile = NULL, *outfile = NULL;
	int infd, outfd;
	poptContext optCon;
	struct poptOption options[] = {
		{"in", 'i', POPT_ARG_STRING, &infile, 0, NULL, NULL },
		{"out", 'o', POPT_ARG_STRING, &outfile, 0, NULL, NULL },
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1) {
		fprintf(stderr, "pesign: Invalid argument: %s\n",
			poptStrerror(rc));
		exit(1);
	}

	if (!infile)
		infd = STDIN_FILENO;
	if (!outfile)
		outfd = STDOUT_FILENO;

	printf("infd: %d outfd: %d\n", infd, outfd);

	close(infd);
	close(outfd);
	return 0;
}
