/*
 * pam_ciba is the PAM service module that runs pam-ciba on systems whose PAM
 * has no pam_exec. pam_sm_authenticate runs the program named by the first
 * module option (default /opt/pam-ciba/pam-ciba) with the argument
 * "authenticate" and the environment PAM_USER, PAM_RHOST, PAM_RUSER, PAM_TTY,
 * PAM_SERVICE and PAM_TYPE, and returns PAM_SUCCESS when it exits 0,
 * PAM_AUTH_ERR otherwise.
 * Further module options are passed to the program before "authenticate".
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define	PAM_CIBA_PROGRAM	"/opt/pam-ciba/pam-ciba"
#define	PAM_CIBA_MAX_ARGS	16

extern char **environ;

static const char *
item(pam_handle_t *pamh, int type)
{
	const void *value = NULL;

	if (pam_get_item(pamh, type, (void *)&value) != PAM_SUCCESS ||
	    value == NULL)
		return ("");
	return ((const char *)value);
}

static void
run(const char *program, int argc, const char **argv, const char *user,
    const char *rhost, const char *ruser, const char *tty, const char *service)
{
	char *args[PAM_CIBA_MAX_ARGS + 3];
	static char *empty[] = { NULL };
	int count = 0;
	int fd;
	int i;

	args[count++] = (char *)program;
	for (i = 1; i < argc && i <= PAM_CIBA_MAX_ARGS; i++)
		args[count++] = (char *)argv[i];
	args[count++] = "authenticate";
	args[count] = NULL;

	environ = empty;
	if (setenv("PAM_USER", user, 1) != 0 ||
	    setenv("PAM_RHOST", rhost, 1) != 0 ||
	    setenv("PAM_RUSER", ruser, 1) != 0 ||
	    setenv("PAM_TTY", tty, 1) != 0 ||
	    setenv("PAM_SERVICE", service, 1) != 0 ||
	    setenv("PAM_TYPE", "auth", 1) != 0)
		_exit(126);

	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		_exit(126);
	(void) dup2(fd, STDIN_FILENO);
	(void) dup2(fd, STDOUT_FILENO);
	(void) dup2(fd, STDERR_FILENO);
	closefrom(STDERR_FILENO + 1);

	(void) execv(program, args);
	_exit(127);
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *program = PAM_CIBA_PROGRAM;
	const char *user;
	const char *rhost;
	const char *ruser;
	const char *tty;
	const char *service;
	struct sigaction dfl;
	struct sigaction saved;
	pid_t child;
	pid_t reaped;
	int status = 0;

	(void) flags;

	if (argc > 0 && argv[0] != NULL && argv[0][0] == '/')
		program = argv[0];

	user = item(pamh, PAM_USER);
	if (user[0] == '\0') {
		syslog(LOG_AUTH | LOG_ERR, "pam_ciba: no PAM_USER");
		return (PAM_AUTH_ERR);
	}
	rhost = item(pamh, PAM_RHOST);
	ruser = item(pamh, PAM_RUSER);
	tty = item(pamh, PAM_TTY);
	service = item(pamh, PAM_SERVICE);

	(void) memset(&dfl, 0, sizeof (dfl));
	dfl.sa_handler = SIG_DFL;
	(void) sigemptyset(&dfl.sa_mask);
	if (sigaction(SIGCHLD, &dfl, &saved) != 0)
		return (PAM_SYSTEM_ERR);

	child = fork();
	if (child < 0) {
		(void) sigaction(SIGCHLD, &saved, NULL);
		syslog(LOG_AUTH | LOG_ERR, "pam_ciba: fork: %s", strerror(errno));
		return (PAM_SYSTEM_ERR);
	}
	if (child == 0)
		run(program, argc, argv, user, rhost, ruser, tty, service);

	do {
		reaped = waitpid(child, &status, 0);
	} while (reaped < 0 && errno == EINTR);
	(void) sigaction(SIGCHLD, &saved, NULL);

	if (reaped == child && WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return (PAM_SUCCESS);

	syslog(LOG_AUTH | LOG_NOTICE, "pam_ciba: sign-in refused for %s", user);
	return (PAM_AUTH_ERR);
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void) pamh;
	(void) flags;
	(void) argc;
	(void) argv;
	return (PAM_IGNORE);
}
