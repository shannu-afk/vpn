#include <stdio.h>
#include <string.h>

int check_user_credentials(const char *username, const char *password) {
    FILE *file = fopen("users.txt", "r");
    if (!file) {
        perror("users.txt not found");
        return 0;
    }

    char line[256], user[128], pass[128];
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%127[^:]:%127s", user, pass) == 2) {
            if (strcmp(user, username) == 0 && strcmp(pass, password) == 0) {
                fclose(file);
                return 1;
            }
        }
    }

    fclose(file);
    return 0;
}
