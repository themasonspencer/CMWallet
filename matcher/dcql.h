#ifndef DCQL_H
#define DCQL_H

#include "cJSON/cJSON.h"

cJSON* dcql_query(cJSON* query, cJSON* credential_store);

#endif