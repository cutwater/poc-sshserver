#include <stdio.h>
#include <stdlib.h>

#include <poll.h>
#include <signal.h>
#include <pty.h>
#include <utmp.h>
#include <sys/wait.h>

#include <libssh/server.h>
#include <libssh/callbacks.h>

#define KEYS_DIR "/home/cutwater/temp/"

#define USER "myuser"
#define PASSWORD "mypassword"
#define BUF_SIZE 1048576
#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)

struct channel_data {
    pid_t pid;
    socket_t pty_master;
    socket_t pty_slave;
    socket_t child_stdin;
    socket_t child_stdout;
    socket_t child_stderr;
    ssh_event event;
    struct winsize* winsize;
};

struct session_data {
    ssh_channel channel;
    int auth_attemnts;
    int authenticated;
};

static void set_default_keys(ssh_bind bind) {
    if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY,
                             KEYS_DIR "ssh_host_rsa_key") != SSH_OK) {
        fprintf(stderr, "Error: %s\n", ssh_get_error(bind));
    }
    if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_DSAKEY,
                             KEYS_DIR "ssh_host_dsa_key") != SSH_OK) {
        fprintf(stderr, "Error: %s\n", ssh_get_error(bind));
    }
}

static int pty_request(ssh_session session, ssh_channel channel,
                       const char* term, int cols, int rows, int py, int px,
                       void* userdata) {
    (void) session;
    (void) channel;
    (void) term;

    struct channel_data* cdata = (struct channel_data*) userdata;

    cdata->winsize->ws_row = (unsigned short) rows;
    cdata->winsize->ws_col = (unsigned short) cols;
    cdata->winsize->ws_xpixel = (unsigned short) px;
    cdata->winsize->ws_ypixel = (unsigned short) py;

    if (openpty(&cdata->pty_master, &cdata->pty_slave,
                NULL, NULL, cdata->winsize) != 0) {
        fprintf(stderr, "Failed to open pty.\n");
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int pty_resize(ssh_session session, ssh_channel channel,
                      int cols, int rows, int py, int px,
                      void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    (void) session;
    (void) channel;

    struct channel_data* cdata = (struct channel_data*) userdata;

    cdata->winsize->ws_row = (unsigned short) rows;
    cdata->winsize->ws_col = (unsigned short) cols;
    cdata->winsize->ws_xpixel = (unsigned short) px;
    cdata->winsize->ws_ypixel = (unsigned short) py;

    if (cdata->pty_master != -1) {
        return ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);
    }

    return SSH_ERROR;
}

static int exec_pty(const char* mode, const char* command,
                    struct channel_data* cdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);
    cdata->pid = fork();
    if (cdata->pid < 0) {
        fprintf(stderr, "DEBUG: fork-2, pid: %d\n", getpid());
        close(cdata->pty_master);
        close(cdata->pty_slave);
        fprintf(stderr, "Failed to fork\n");
        return SSH_ERROR;
    } else if (cdata->pid == 0) {
        close(cdata->pty_master);
        if (login_tty(cdata->pty_slave) != 0) {
            exit(1);
        }
        execl("/bin/sh", "sh", mode, command, NULL);
        exit(0);
    } else {
        close(cdata->pty_slave);
        cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
    }
    return SSH_OK;
}

static int exec_nopty(const char* command, struct channel_data* cdata) {
    fprintf(stderr, "DEBUG: %s('%s', <cdata>)\n", __FUNCTION__, command);

    int in[2], out[2], err[2];

    if (pipe(in) != 0) {
        goto stdin_failed;
    }

    if (pipe(out) != 0) {
        goto stdout_failed;
    }

    if (pipe(err) != 0) {
        goto stderr_failed;
    }

    cdata->pid = fork();
    if (cdata->pid < 0) {
        goto fork_failed;
    } else if (cdata->pid == 0) {
        fprintf(stderr, "DEBUG: exec_nopty fork() -> %d", getpid());
        /* Finish the plumbing in the child process */
        close(in[1]);
        close(out[0]);
        close(err[0]);
        dup2(in[0], STDIN_FILENO);
        dup2(out[1], STDOUT_FILENO);
        dup2(err[1], STDERR_FILENO);
        close(in[0]);
        close(out[1]);
        close(err[1]);
        execl("/bin/sh", "sh", "-c", command, NULL);
        exit(0);
    }

    close(in[0]);
    close(out[1]);
    close(err[1]);

    cdata->child_stdin = in[1];
    cdata->child_stdout = out[0];
    cdata->child_stderr = err[0];

    return SSH_OK;

fork_failed:
    close(err[0]);
    close(err[1]);
stderr_failed:
    close(out[0]);
    close(out[1]);
stdout_failed:
    close(in[0]);
    close(in[1]);
stdin_failed:
    return SSH_ERROR;
}

static int exec_request(ssh_session session, ssh_channel channel,
                        const char* command, void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    (void) session;
    (void) channel;

    struct channel_data* cdata = (struct channel_data*) userdata;

    if (cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-c", command, cdata);
    }

    return exec_nopty(command, cdata);
}

static int shell_request(ssh_session session, ssh_channel channel,
                         void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    (void) session;
    (void) channel;

    struct channel_data* cdata = (struct channel_data*) userdata;

    if (cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-l", NULL, cdata);
    }
    return SSH_OK;
}

static int subsystem_request(ssh_session session, ssh_channel channel,
                             const char* subsystem, void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    (void) session;
    (void) channel;
    (void) subsystem;
    (void) userdata;

    return SSH_ERROR;
}

static int auth_password(ssh_session session, const char* user,
                         const char* password, void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    (void) session;

    struct session_data* sdata = (struct session_data*) userdata;

    if (strcmp(user, USER) == 0 && strcmp(password, PASSWORD) == 0) {
        sdata->authenticated = 1;
        return SSH_AUTH_SUCCESS;
    }

    ++ sdata->auth_attemnts;
    return SSH_AUTH_DENIED;
}

static ssh_channel channel_open(ssh_session session, void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    struct session_data* sdata = (struct session_data*) userdata;

    sdata->channel = ssh_channel_new(session);
    return sdata->channel;
}

static int data_function(ssh_session session, ssh_channel channel, void* data,
                         uint32_t len, int is_stderr, void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    (void) session;
    (void) channel;
    (void) is_stderr;

    struct channel_data* cdata = (struct channel_data*) userdata;

    if (len == 0 || cdata->pid < 1 || kill(cdata->pid, 0) < 0) {
        return 0;
    }

    return (int) write(cdata->child_stdin, (char*) data, len);
}

static int process_stdout(socket_t fd, int revents, void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    char buf[BUF_SIZE];
    ssh_channel channel = (ssh_channel) userdata;

    int n = -1;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = (int) read(fd, buf, BUF_SIZE);
        if (n > 0) {
            ssh_channel_write(channel, buf, (uint32_t)n);
        }
    }

    return n;
}

static int process_stderr(socket_t fd, int revents, void* userdata) {
    fprintf(stderr, "DEBUG: %s\n", __FUNCTION__);

    char buf[BUF_SIZE];
    ssh_channel channel = (ssh_channel) userdata;

    int n = -1;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = (int) read(fd, buf, BUF_SIZE);
        if (n > 0) {
            ssh_channel_write_stderr(channel, buf, (uint32_t)n);
        }
    }

    return n;
}

static void handle_session(ssh_event event, ssh_session session) {
    struct winsize wsize = {
        .ws_row = 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    struct channel_data cdata = {
        .pid = 0,
        .pty_master = -1,
        .pty_slave = -1,
        .child_stdin = -1,
        .child_stdout = -1,
        .child_stderr = -1,
        .event = NULL,
        .winsize = &wsize
    };

    struct session_data sdata = {
        .channel = NULL,
        .auth_attemnts = 0,
        .authenticated = 0
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &cdata,
        .channel_pty_request_function = pty_request,
        .channel_pty_window_change_function = pty_resize,
        .channel_shell_request_function = shell_request,
        .channel_exec_request_function = exec_request,
        .channel_data_function = data_function,
        .channel_subsystem_request_function = subsystem_request,
    };

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &sdata,
        .auth_password_function = auth_password,
        .channel_open_request_session_function = channel_open,
    };

    ssh_callbacks_init(&channel_cb);
    ssh_callbacks_init(&server_cb);

    ssh_set_server_callbacks(session, &server_cb);

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "Error (ssh_handle_key_exchange): %s\n", ssh_get_error(session));
        return;
    }

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
    ssh_event_add_session(event, session);

    int n = 0;
    while (sdata.authenticated == 0 || sdata.channel == NULL) {
        /* If the user has used up all attempts, or if he hasn't been able
         * authenticate in 10 seconds (n * 100ms), than disconnect. */
        if (sdata.auth_attemnts >= 3 || n >= 100) {
            return;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "Error (ssh_event_dopoll): %s\n",
                    ssh_get_error(session));
            return;
        }
        ++n;
    }

    ssh_set_channel_callbacks(sdata.channel, &channel_cb);

    int rc = 0;
    do {
        if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
            ssh_channel_close(sdata.channel);
        }

        if (cdata.event != NULL || cdata.pid != 0) {
            continue;
        }

        /* Executed only once when child process starts. */
        printf("%d %d\n", cdata.child_stdout, cdata.child_stderr);
        cdata.event = event;
        if (cdata.child_stdout != -1) {
            if (ssh_event_add_fd(event, cdata.child_stdout, POLLIN,
                                 process_stdout, sdata.channel) != SSH_OK) {
                fprintf(stderr, "Failed to register stdout to poll context.\n");
                ssh_channel_close(sdata.channel);
            }
        }

        /* If stderr valid, and stderr to be mentioned by the poll event. */
        if (cdata.child_stderr != -1) {
            if (ssh_event_add_fd(event, cdata.child_stderr, POLLIN,
                                 process_stderr, sdata.channel) != SSH_OK) {
                fprintf(stderr, "Failed to register stderr to poll context.\n");
                ssh_channel_close(sdata.channel);
            }
        }
    } while(ssh_channel_is_open(sdata.channel)
            && (cdata.pid != 0 || waitpid(cdata.pid, &rc, WNOHANG)));

    close(cdata.pty_master);
    close(cdata.child_stdin);
    close(cdata.child_stdout);
    close(cdata.child_stderr);

    ssh_event_remove_fd(event, cdata.child_stdout);
    ssh_event_remove_fd(event, cdata.child_stderr);

    /* If the child process exited. */
    if (kill(cdata.pid, 0) < 0 && WIFEXITED(rc)) {
        rc = WEXITSTATUS(rc);
        ssh_channel_request_send_exit_status(sdata.channel, rc);
    } else if (cdata.pid > 0) {
        kill(cdata.pid, SIGKILL);
    }

    /* Wait up to 5 seconds for the client to terminate the session. */
    for (n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) {
        ssh_event_dopoll(event, 100);
    }
}

static void sigchld_handler(int signo) {
    (void) signo;

    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char** argv) {
    /* Set up SIGCHLD handler. */
    fprintf(stderr, "DEBUG: main process, pid: %d\n", getpid());

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        fprintf(stderr, "Failed to register SIGCHLD handler.\n");
        return EXIT_FAILURE;
    }

    ssh_init();
    ssh_bind bind = ssh_bind_new();

    set_default_keys(bind);

    int port = 2222;
    if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT,
                             &port) != SSH_OK) {
        fprintf(stderr, "Error: %s\n", ssh_get_error(bind));
    }

    int log_verbosity = SSH_LOG_NOLOG;
    if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY,
                             &log_verbosity) != SSH_OK) {
        fprintf(stderr, "Error: %s\n", ssh_get_error(bind));
    }

    if (ssh_bind_listen(bind) < 0) {
        fprintf(stderr, "Error: %s\n", ssh_get_error(bind));
        return EXIT_FAILURE;
    }

    while (1) {
        ssh_session session = ssh_new();
        if (!session) {
            fprintf(stderr, "Failed to allocate session.\n");
            continue;
        }

        if (ssh_bind_accept(bind, session) == SSH_OK) {
            pid_t pid = fork();
            if (pid == 0) {
                fprintf(stderr, "DEBUG: fork-1, pid: %d\n", getpid());
                ssh_bind_free(bind);

                ssh_event event = ssh_event_new();
                if (event) {
                    handle_session(event, session);
                    ssh_event_free(event);
                } else {
                    fprintf(stderr, "Cannot create polling context.\n");
                }
                ssh_disconnect(session);
                ssh_free(session);
                exit(0);
            } else if (pid == -1) {
                fprintf(stderr, "Failed to fork.\n");
            }
        }

        ssh_disconnect(session);
        ssh_free(session);
    }

    ssh_bind_free(bind);
    ssh_finalize();
    return EXIT_SUCCESS;
}
