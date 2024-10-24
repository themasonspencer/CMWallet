#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON/cJSON.h"
#include "credentialmanager.h"

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

void ProcessOpenID4VP(cJSON* request, cJSON* store) {
    //printf("OpenID4VP JSON %s\n", cJSON_Print(request));
    cJSON* store_creds = cJSON_GetObjectItem(store, "credentials");
    
    cJSON* vp_query = cJSON_GetObjectItem(request, "vp_query");
    
    // Get the Credential Query and loop through each one.
    cJSON* credentials = cJSON_GetObjectItem(vp_query, "credentials");
    int credentials_size = cJSON_GetArraySize(credentials);
    for(int i=0; i<credentials_size; i++) {
        cJSON* credential = cJSON_GetArrayItem(credentials, i);
        
        // Required
        cJSON* id = cJSON_GetObjectItem(credential, "id");
        cJSON* format = cJSON_GetObjectItem(credential, "format");
        char* format_string = cJSON_GetStringValue(format);
        
        // Optional
        cJSON* meta = cJSON_GetObjectItem(credential, "meta");
        cJSON* claims = cJSON_GetObjectItem(credential, "claims");
        
        //printf("ID %s\n", cJSON_Print(id));

        // Check if we have any creds matching this format in the store
        cJSON* matching_creds_for_format = cJSON_GetObjectItem(store_creds, format_string);
        if (matching_creds_for_format != NULL) {
            // We have credentials matching this format.
            
            // Perform format specific parsing - this is icky
            if (strcmp(format_string, "mso_mdoc") == 0) {
                // For mdocs meta can contain the doctype. Note its required for this matcher.
                if (meta != NULL) {
                    cJSON* doctype_value = cJSON_GetObjectItem(meta, "doctype_value");
                    if (doctype_value != NULL) {
                        char* doctype_value_string = cJSON_GetStringValue(doctype_value);
                        //printf("doctype %s\n", doctype_value_string);
                        cJSON* matching_creds_for_doctype = cJSON_GetObjectItem(matching_creds_for_format, doctype_value_string);
                        //printf("Matched %s\n", cJSON_Print(matching_creds_for_doctype));
                        int candiate_size = cJSON_GetArraySize(matching_creds_for_doctype);
                        for(int candiate_idx=0; candiate_idx<candiate_size; candiate_idx++) {
                            cJSON* candiate = cJSON_GetArrayItem(matching_creds_for_doctype, candiate_idx);
                            cJSON* candiate_namespaces = cJSON_GetObjectItem(candiate, "namespaces");

                            if (claims != NULL) {
                                int claims_size = cJSON_GetArraySize(claims);
                                cJSON** matching_claims = calloc(claims_size, sizeof(cJSON*));
                                int match = 1;
                                for(int claim_idx=0; claim_idx<claims_size; claim_idx++) {
                                    cJSON* claim = cJSON_GetArrayItem(claims, claim_idx);
                                    char* claim_namespace = cJSON_GetStringValue(cJSON_GetObjectItem(claim, "namespace"));
                                    char* claim_name = cJSON_GetStringValue(cJSON_GetObjectItem(claim, "claim_name"));
                                    
                                    cJSON* matched_namespace = cJSON_GetObjectItem(candiate_namespaces, claim_namespace);
                                    if (matched_namespace != NULL) {
                                        // We matched the namespace, so check for the claim
                                        cJSON* matched_claim = cJSON_GetObjectItem(matched_namespace, claim_name);
                                        if (matched_claim != NULL) {
                                            //printf("claim: %s %s \n", claim_namespace, claim_name);
                                            matching_claims[claim_idx] = matched_claim;
                                        } else {
                                            match = 0;
                                        }
                                    } else {
                                        match = 0;
                                    }
                                }
                                if (match) {
                                    //printf("MATCH: %s\n", cJSON_Print(candiate_id));
                                    cJSON* candiate_id = cJSON_GetObjectItem(candiate, "id");
                                    cJSON* candiate_title = cJSON_GetObjectItem(candiate, "title");
                                    cJSON* candiate_subtitle = cJSON_GetObjectItem(candiate, "subtitle");
                                    char* candiate_id_string = cJSON_GetStringValue(candiate_id);
                                    char* candiate_title_string = cJSON_GetStringValue(candiate_title);
                                    char* candiate_subtitle_string = cJSON_GetStringValue(candiate_subtitle);
                                    AddStringIdEntry(candiate_id_string, NULL, 0, candiate_title_string, candiate_subtitle_string, NULL, NULL);
                                    for(int claim_idx=0; claim_idx<claims_size; claim_idx++) {
                                        if (matching_claims[claim_idx]) {
                                            cJSON* display = cJSON_GetObjectItem(matching_claims[claim_idx], "display");
                                            AddFieldForStringIdEntry(candiate_id_string, cJSON_GetStringValue(display), NULL);
                                        }
                                    }
                                }
                            } else {
                                // match all claims

                            }
                        }

                    }
                }

            }
        }
    }
}

int main() {

    cJSON* creds = GetCredsJson();
    //printf("Creds JSON %s\n", cJSON_Print(creds));

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
            ProcessOpenID4VP(data_json, creds);
        }
    }

    return 0;
}