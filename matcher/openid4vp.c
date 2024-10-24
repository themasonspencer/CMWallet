#include <stdio.h>

#include "cJSON.h"
#include "credentialmanager.h"

int main() {
    
    AddStringIdEntry("ID1", NULL, 0, "My Test DL", "Test DMV", NULL, NULL);
    AddFieldForStringIdEntry("ID1", "Name", NULL);


    return 0;
}