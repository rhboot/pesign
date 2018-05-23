/*
 * Copyright 2012 Red Hat, Inc.
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

#include <limits.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#include "pesign.h"

#include <seccomon.h>
#include <secitem.h>
#include <secport.h>
#include <pk11pub.h>

#include <prtypes.h>
#include <prerror.h>
#include <prprf.h>

static void echoOff(int fd)
{
    if (isatty(fd)) {
	struct termios tio;
	tcgetattr(fd, &tio);
	tio.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

static void echoOn(int fd)
{
    if (isatty(fd)) {
	struct termios tio;
	tcgetattr(fd, &tio);
	tio.c_lflag |= ECHO;
	tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

static PRBool SEC_BlindCheckPassword(char *cp)
{
    if (cp != NULL) {
	return PR_TRUE;
    }
    return PR_FALSE;
}

static char *SEC_GetPassword(FILE *input, FILE *output, char *prompt,
			       PRBool (*ok)(char *))
{
    int infd  = fileno(input);
    int isTTY = isatty(infd);
    char phrase[200] = {'\0'};      /* ensure EOF doesn't return junk */

    for (;;) {
	/* Prompt for password */
	if (isTTY) {
	    echoOff(infd);
	    fprintf(output, "%s", prompt);
            fflush (output);
	}

	fgets ( phrase, sizeof(phrase), input);

	if (isTTY) {
	    fprintf(output, "\n");
	    echoOn(infd);
	}

	/* stomp on newline */
	phrase[PORT_Strlen(phrase)-1] = 0;

	/* Validate password */
	if (!(*ok)(phrase)) {
	    /* Not weird enough */
	    if (!isTTY) return 0;
	    fprintf(output, "Password must be at least 8 characters long with one or more\n");
	    fprintf(output, "non-alphabetic characters\n");
	    continue;
	}
	return (char*) PORT_Strdup(phrase);
    }
}

static char consoleName[] = { "/dev/tty" };

static char *
SECU_GetPasswordString(void *arg UNUSED,
		       char *prompt UNUSED)
{
    char *p = NULL;
    FILE *input, *output;

    /* open terminal */
    input = fopen(consoleName, "r");
    if (input == NULL) {
	fprintf(stderr, "Error opening input terminal %s for read\n",
		consoleName);
	return NULL;
    }

    output = fopen(consoleName, "w");
    if (output == NULL) {
	fclose(input);
	fprintf(stderr, "Error opening output terminal %s for write\n",
		consoleName);
	return NULL;
    }

    p = SEC_GetPassword (input, output, prompt, SEC_BlindCheckPassword);

    fclose(input);
    fclose(output);

    return p;
}

/*
 *  p a s s w o r d _ h a r d c o d e 
 *
 *  A function to use the password passed in the -f(pwfile) argument
 *  of the command line.  
 *  After use once, null it out otherwise PKCS11 calls us forever.?
 *
 */
static char *
SECU_FilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char* phrases, *phrase;
    PRFileDesc *fd;
    PRInt32 nb;
    char *pwFile = arg;
    int i;
    const long maxPwdFileSize = 4096;
    char* tokenName = NULL;
    int tokenLen = 0;

    if (!pwFile)
	return 0;

    if (retry) {
	return 0;  /* no good retrying - the files contents will be the same */
    }

    phrases = PORT_ZAlloc(maxPwdFileSize);

    if (!phrases) {
        return 0; /* out of memory */
    }
 
    fd = PR_Open(pwFile, PR_RDONLY, 0);
    if (!fd) {
	fprintf(stderr, "No password file \"%s\" exists.\n", pwFile);
        PORT_Free(phrases);
	return NULL;
    }

    nb = PR_Read(fd, phrases, maxPwdFileSize);
  
    PR_Close(fd);

    if (nb == 0) {
        fprintf(stderr,"password file contains no data\n");
        PORT_Free(phrases);
        return NULL;
    }

    if (slot) {
        tokenName = PK11_GetTokenName(slot);
        if (tokenName) {
            tokenLen = PORT_Strlen(tokenName);
        }
    }
    i = 0;
    do
    {
        int startphrase = i;
        int phraseLen;

        /* handle the Windows EOL case */
        while (phrases[i] != '\r' && phrases[i] != '\n' && i < nb) i++;
        /* terminate passphrase */
        phrases[i++] = '\0';
        /* clean up any EOL before the start of the next passphrase */
        while ( (i<nb) && (phrases[i] == '\r' || phrases[i] == '\n')) {
            phrases[i++] = '\0';
        }
        /* now analyze the current passphrase */
        phrase = &phrases[startphrase];
        if (!tokenName)
            break;
        if (PORT_Strncmp(phrase, tokenName, tokenLen)) continue;
        phraseLen = PORT_Strlen(phrase);
        if (phraseLen < (tokenLen+1)) continue;
        if (phrase[tokenLen] != ':') continue;
        phrase = &phrase[tokenLen+1];
        break;

    } while (i<nb);

    phrase = PORT_Strdup((char*)phrase);
    PORT_Free(phrases);
    return phrase;
}

char *
get_password_passthrough(PK11SlotInfo *slot UNUSED,
			 PRBool retry, void *arg)
{
	if (retry)
		return NULL;

	if (!arg)
		return arg;

	char *ret = strdup(arg);
	if (!ret) {
		fprintf(stderr, "Failed to allocate memory\n");
		exit(1);
	}
	return ret;
}

char *
get_password_fail(PK11SlotInfo *slot UNUSED,
		  PRBool retry UNUSED,
		  void *arg UNUSED)
{
	return NULL;
}

char *
SECU_GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char prompt[255];
    secuPWData *pwdata = (secuPWData *)arg;
    secuPWData pwnull = { PW_NONE, 0 };
    secuPWData pwxtrn = { PW_EXTERNAL, "external" };
    char *pw;

    if (pwdata == NULL)
	pwdata = &pwnull;

    if (PK11_ProtectedAuthenticationPath(slot)) {
	pwdata = &pwxtrn;
    }
    if (retry && pwdata->source != PW_NONE) {
	PR_fprintf(PR_STDERR, "Incorrect password/PIN entered.\n");
	return NULL;
    }

    switch (pwdata->source) {
    case PW_NONE:
	sprintf(prompt, "Enter Password or Pin for \"%s\":",
	                 PK11_GetTokenName(slot));
	return SECU_GetPasswordString(NULL, prompt);
    case PW_FROMFILE:
	/* Instead of opening and closing the file every time, get the pw
	 * once, then keep it in memory (duh).
	 */
	pw = SECU_FilePasswd(slot, retry, pwdata->data);
	pwdata->source = PW_PLAINTEXT;
	pwdata->data = PL_strdup(pw);
	/* it's already been dup'ed */
	return pw;
    case PW_EXTERNAL:
	sprintf(prompt,
	        "Press Enter, then enter PIN for \"%s\" on external device.\n",
		PK11_GetTokenName(slot));
	(void) SECU_GetPasswordString(NULL, prompt);
	/* Fall Through */
    case PW_PLAINTEXT:
	return PL_strdup(pwdata->data);
    default:
	break;
    }

    PR_fprintf(PR_STDERR, "Password check failed:  No password found.\n");
    return NULL;
}

#if 0
#warning investigate killing readpw
#endif
char *
readpw(PK11SlotInfo *slot UNUSED,
       PRBool retry UNUSED,
       void *arg UNUSED)
{
	struct termios sio, tio;
	char line[LINE_MAX], *p;

	memset(line, '\0', sizeof (line));

	if (tcgetattr(fileno(stdin), &sio) < 0) {
		fprintf(stderr, "Could not read password from standard input.\n");
		return NULL;
	}
	tio = sio;
	tio.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(stdin), 0, &tio) < 0) {
		fprintf(stderr, "Could not read password from standard input.\n");
		return NULL;
	}

	fprintf(stdout, "Enter passphrase for private key: ");
	if (fgets(line, sizeof(line), stdin) == NULL) {
		fprintf(stdout, "\n");
		tcsetattr(fileno(stdin), 0, &sio);
		return NULL;
	}
	fprintf(stdout, "\n");
	tcsetattr(fileno(stdin), 0, &sio);

	p = line + strcspn(line, "\r\n");
	if (p == NULL)
		p = line + strcspn(line, "\n");
	if (p != NULL)
		*p = '\0';

	char *ret = strdup(line);
	memset(line, '\0', sizeof (line));
	if (!ret) {
		fprintf(stderr, "Could not read passphrase.\n");
		return NULL;
	}
	return ret;
}
