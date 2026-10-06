#include "shell_exec.h"
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

char *shell_exec(const char *command, int *exit_code) {
    if (!command) return NULL;

    // Redirect stderr to stdout
    size_t cmdLen = strlen(command) + 16;
    char *fullCmd = (char *)malloc(cmdLen);
    if (!fullCmd) return NULL;
    snprintf(fullCmd, cmdLen, "%s 2>&1", command);

    FILE *fp = popen(fullCmd, "r");
    free(fullCmd);
    if (!fp) {
        if (exit_code) *exit_code = -1;
        return NULL;
    }

    size_t capacity = 8192;
    size_t length = 0;
    char *buffer = (char *)malloc(capacity);
    if (!buffer) { pclose(fp); return NULL; }

    char chunk[4096];
    while (fgets(chunk, sizeof(chunk), fp)) {
        size_t chunkLen = strlen(chunk);
        if (length + chunkLen + 1 > capacity) {
            capacity *= 2;
            if (capacity > 512000) { // safety cap ~500KB
                break;
            }
            char *newBuf = (char *)realloc(buffer, capacity);
            if (!newBuf) break;
            buffer = newBuf;
        }
        memcpy(buffer + length, chunk, chunkLen);
        length += chunkLen;
    }
    buffer[length] = '\0';

    int status = pclose(fp);
    if (exit_code) {
        *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    return buffer;
}
