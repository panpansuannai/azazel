/*
  This program was contributed by Shane Watts
  [modifications by AGM and kukuk]

  You need to add the following (or equivalent) to the
  /etc/pam.d/check_user file:
  # check authorization
  auth       required     pam_unix.so
  account    required     pam_unix.so
 */

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdlib.h>
#include <stdio.h>

/*
int misc_conv(int num_msg, const struct pam_message **msg,
              struct pam_response** resp, void *appdata_ptr) {
    printf("misc_conv, num_msg: %d\n", num_msg);
    return 0;
}
*/
static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[])
{
    pam_handle_t *pamh=NULL;
    int retval;
    const char *user="nobody";

    if(argc == 2) {
        user = argv[1];
    }

    if(argc > 2) {
        fprintf(stderr, "Usage: check_user [username]\n");
        exit(1);
    }

    retval = pam_start("pam_demo", user, &conv, &pamh);

    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */

    /* This is where we have been authorized or not. */

    if (retval == PAM_SUCCESS) {
        fprintf(stdout, "Authenticated\n");
    } else {
        fprintf(stdout, "Not Authenticated\n");
    }

    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        fprintf(stderr, "check_user: failed to release authenticator\n");
        exit(1);
    }

    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */
}

