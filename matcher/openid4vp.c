#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON/cJSON.h"
#include "credentialmanager.h"

#include "dcql.h"

#define PROTOCOL_OPENID4VP_1_0 "openid4vp1.0"

cJSON* GetDCRequestJson() {
    uint32_t request_size;
    GetRequestSize(&request_size);
    char* request_json = malloc(request_size);
    GetRequestBuffer(request_json);
    return cJSON_Parse(request_json);
}

cJSON* GetCredsJson() {
    uint32_t credentials_size;
    GetCredentialsSize(&credentials_size);
    char* creds_json = malloc(credentials_size);
    ReadCredentialsBuffer(creds_json, 0, credentials_size);
    return cJSON_Parse(creds_json);
}

int main() {
    cJSON* creds = GetCredsJson();
    cJSON* credential_store = cJSON_GetObjectItem(creds, "credentials");
    //printf("Creds JSON %s\n", cJSON_Print(credential_store));

    cJSON* dc_request = GetDCRequestJson();
    //printf("Request JSON %s\n", cJSON_Print(dc_request));

    // Parse each top level request looking for OpenID4VP requests
    cJSON* requests = cJSON_GetObjectItem(dc_request, "providers"); // TODO: This has changed in the latest spec
    int requests_size = cJSON_GetArraySize(requests);

    for(int i=0; i<requests_size; i++) {
        cJSON* request = cJSON_GetArrayItem(requests, i);
        //printf("Request %s\n", cJSON_Print(request));

        char* protocol = cJSON_GetStringValue(cJSON_GetObjectItem(request, "protocol"));
        if (strcmp(protocol, PROTOCOL_OPENID4VP_1_0) == 0) {
            // We have an OpenID4VP request
            cJSON* data = cJSON_GetObjectItem(request, "request"); // TODO: This has changed in the latest spec

            // TODO: Won't need to do this conversion in the latest spec.
            char* data_json_string = cJSON_GetStringValue(data);
            cJSON* data_json = cJSON_Parse(data_json_string);
            cJSON* query = cJSON_GetObjectItem(data_json, "dcql_query");

            cJSON* matched_creds = dcql_query(query, credential_store);
            //printf("matched_creds %d\n", cJSON_GetArraySize(matched_creds));
            //printf("matched_creds %s\n", cJSON_Print(cJSON_GetArrayItem(matched_creds,0)));

            // Only support one doc
            cJSON* matched_cred = cJSON_GetArrayItem(matched_creds,0);
            cJSON* c;
            cJSON_ArrayForEach(c, matched_cred) {
                //printf("cred %s\n", cJSON_Print(c));
                cJSON* id_obj = cJSON_CreateObject();
                cJSON* matched_id = cJSON_GetObjectItem(c, "id");
                cJSON_AddItemReferenceToObject(id_obj, "id", matched_id);
                cJSON_AddItemReferenceToObject(id_obj, "provider_idx", cJSON_CreateNumber(i));

                char* id = cJSON_PrintUnformatted(id_obj);
                char* title = cJSON_GetStringValue(cJSON_GetObjectItem(c, "title"));
                char* subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(c, "subtitle"));
                AddStringIdEntry(id, NULL, 0, title, subtitle, NULL, NULL);
                cJSON* matched_claim_names = cJSON_GetObjectItem(c, "matched_claim_names");
                cJSON* claim;
                cJSON_ArrayForEach(claim, matched_claim_names) {
                    AddFieldForStringIdEntry(id, cJSON_GetStringValue(claim), NULL);
                }
            }


        }
    }

    return 0;
}