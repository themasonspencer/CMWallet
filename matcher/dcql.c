#include <stdio.h>
#include <string.h>

#include "dcql.h"

#include "cJSON/cJSON.h"

cJSON* MatchCredential(cJSON* credential, cJSON* credential_store) {
    cJSON* matched_credentials = cJSON_CreateArray();
    char* format = cJSON_GetStringValue(cJSON_GetObjectItem(credential, "format"));

    // check for optional params
    cJSON* meta = cJSON_GetObjectItem(credential, "meta");
    cJSON* claims = cJSON_GetObjectItem(credential, "claims");
    cJSON* claim_sets = cJSON_GetObjectItem(credential, "claim_sets");

    cJSON* candidates = cJSON_GetObjectItem(credential_store, format);

    if (candidates == NULL) {
        return matched_credentials;
    }

    // Filter by meta
    if (meta != NULL) {
        if (strcmp(format, "mso_mdoc") == 0) {
            cJSON* doctype_value_obj = cJSON_GetObjectItem(meta, "doctype_value");
            if (doctype_value_obj != NULL) {
                char* doctype_value = cJSON_GetStringValue(doctype_value_obj);
                candidates = cJSON_GetObjectItem(candidates, doctype_value);
                //printf("candidates %s\n", cJSON_Print(candidates));
            }
        } else {
            return matched_credentials;
        }
    }

    if (candidates == NULL) {
        return matched_credentials;
    }

    // Match on the claims
    if (claims == NULL) {
        // Match every candidate
        cJSON* candidate;
        cJSON_ArrayForEach(candidate, candidates) {
            cJSON* matched_credential = cJSON_CreateObject();
            cJSON_AddItemReferenceToObject(matched_credential, "id", cJSON_GetObjectItem(candidate, "id"));
            cJSON_AddItemReferenceToObject(matched_credential, "title", cJSON_GetObjectItem(candidate, "title"));
            cJSON_AddItemReferenceToObject(matched_credential, "subtitle", cJSON_GetObjectItem(candidate, "subtitle"));
            cJSON_AddItemReferenceToObject(matched_credential, "icon", cJSON_GetObjectItem(candidate, "icon"));
            cJSON* matched_claim_names = cJSON_CreateArray();
            //printf("candidate %s\n", cJSON_Print(candidate));
            if (strcmp(format, "mso_mdoc") == 0) {
                cJSON* namespace;
                cJSON_ArrayForEach(namespace, cJSON_GetObjectItem(candidate, "namespaces")) {
                    //printf("namespace %s\n", cJSON_Print(namespace));
                    cJSON* attr;
                    cJSON_ArrayForEach(attr, namespace) {
                        //printf("attr %s\n", cJSON_Print(attr));
                        cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItem(attr, "display"));
                    }
                }
                cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_names", matched_claim_names);
                cJSON_AddItemReferenceToArray(matched_credentials, matched_credential);
            }
        }
    } else {
        if (claim_sets == NULL) {
            cJSON* candidate;
            cJSON_ArrayForEach(candidate, candidates) {
                cJSON* matched_credential = cJSON_CreateObject();
                cJSON_AddItemReferenceToObject(matched_credential, "id", cJSON_GetObjectItem(candidate, "id"));
                cJSON_AddItemReferenceToObject(matched_credential, "title", cJSON_GetObjectItem(candidate, "title"));
                cJSON_AddItemReferenceToObject(matched_credential, "subtitle", cJSON_GetObjectItem(candidate, "subtitle"));
                cJSON_AddItemReferenceToObject(matched_credential, "icon", cJSON_GetObjectItem(candidate, "icon"));
                cJSON* matched_claim_names = cJSON_CreateArray();

                cJSON* claim;
                cJSON_ArrayForEach(claim, claims) {
                    cJSON* claim_values = cJSON_GetObjectItem(claim, "values");
                    if (strcmp(format, "mso_mdoc") == 0) {
                        char* namespace = cJSON_GetStringValue(cJSON_GetObjectItem(claim, "namespace"));
                        char* claim_name = cJSON_GetStringValue(cJSON_GetObjectItem(claim, "claim_name"));
                        if (cJSON_HasObjectItem(cJSON_GetObjectItem(candidate, "namespaces"), namespace)) {
                            if (cJSON_HasObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(candidate, "namespaces"),namespace), claim_name)) {
                                if (claim_values != NULL) {
                                    cJSON* v;
                                    cJSON_ArrayForEach(v, claim_values) {
                                        if (cJSON_Compare(v, cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(candidate, "namespaces"),namespace), claim_name), "value"), cJSON_True)) {
                                            cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(candidate, "namespaces"),namespace), claim_name), "display"));
                                            break;
                                        }
                                    }
                                } else {
                                    cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(candidate, "namespaces"),namespace), claim_name), "display"));
                                }
                            }
                        }
                    }
                }
                cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_names", matched_claim_names);
                if (cJSON_GetArraySize(matched_claim_names) == cJSON_GetArraySize(claims)) {
                    cJSON_AddItemReferenceToArray(matched_credentials, matched_credential);
                }
            }
        } else {
            cJSON* candidate;
            cJSON_ArrayForEach(candidate, candidates) {
                cJSON* matched_credential = cJSON_CreateObject();
                cJSON_AddItemReferenceToObject(matched_credential, "id", cJSON_GetObjectItem(candidate, "id"));
                cJSON_AddItemReferenceToObject(matched_credential, "title", cJSON_GetObjectItem(candidate, "title"));
                cJSON_AddItemReferenceToObject(matched_credential, "subtitle", cJSON_GetObjectItem(candidate, "subtitle"));
                cJSON_AddItemReferenceToObject(matched_credential, "icon", cJSON_GetObjectItem(candidate, "icon"));
                cJSON* matched_claim_ids = cJSON_CreateObject();

                cJSON* claim;
                cJSON_ArrayForEach(claim, claims) {
                    cJSON* claim_values = cJSON_GetObjectItem(claim, "values");
                    char* claim_id = cJSON_GetStringValue(cJSON_GetObjectItem(claim, "id"));
                    if (strcmp(format, "mso_mdoc") == 0) {
                        char* namespace = cJSON_GetStringValue(cJSON_GetObjectItem(claim, "namespace"));
                        char* claim_name = cJSON_GetStringValue(cJSON_GetObjectItem(claim, "claim_name"));
                        if (cJSON_HasObjectItem(cJSON_GetObjectItem(candidate, "namespaces"), namespace)) {
                            if (cJSON_HasObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(candidate, "namespaces"),namespace), claim_name)) {
                                if (claim_values != NULL) {
                                    cJSON* v;
                                    cJSON_ArrayForEach(v, claim_values) {
                                        if (cJSON_Compare(v, cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(candidate, "namespaces"),namespace), claim_name), "value"), cJSON_True)) {
                                            cJSON_AddItemReferenceToObject(matched_claim_ids, claim_id, cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(candidate, "namespaces"),namespace), claim_name), "display"));
                                            break;
                                        }
                                    }
                                } else {
                                    cJSON_AddItemReferenceToObject(matched_claim_ids, claim_id, cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(candidate, "namespaces"),namespace), claim_name), "display"));
                                }
                            }
                        }
                    }
                }
                cJSON* claim_set;
                cJSON_ArrayForEach(claim_set, claim_sets) {
                    cJSON* matched_claim_names = cJSON_CreateArray();
                    cJSON* c;
                    cJSON_ArrayForEach(c, claim_set) {
                        if (cJSON_HasObjectItem(matched_claim_ids, cJSON_GetStringValue(c))) {
                            cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItem(matched_claim_ids, cJSON_GetStringValue(c)));
                        }
                    }
                    if (cJSON_GetArraySize(matched_claim_names) == cJSON_GetArraySize(claim_set)) {
                        cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_names", matched_claim_names);
                        cJSON_AddItemReferenceToArray(matched_credentials, matched_credential);
                        break;
                    }
                }
            }
        }
    }

    return matched_credentials;
}

cJSON* dcql_query(cJSON* query, cJSON* credential_store) {
    cJSON* matched_credentials = cJSON_CreateObject();
    cJSON* candidate_matched_credentials = cJSON_CreateObject();
    cJSON* credentials = cJSON_GetObjectItem(query, "credentials");

    cJSON* credential;
    cJSON_ArrayForEach(credential, credentials) {
        char* id = cJSON_GetStringValue(cJSON_GetObjectItem(credential, "id"));
        cJSON* matched = MatchCredential(credential, credential_store);
        if (cJSON_GetArraySize(matched) > 0) {
            cJSON* m = cJSON_CreateObject();
            cJSON_AddItemReferenceToObject(m, "id", cJSON_GetObjectItem(credential, "id"));
            cJSON_AddItemReferenceToObject(m, "matched", matched);
            cJSON_AddItemReferenceToObject(candidate_matched_credentials, id, m);
        }

        if (cJSON_GetArraySize(credentials) == cJSON_GetArraySize(candidate_matched_credentials)) {
            matched_credentials = candidate_matched_credentials;
        }
    }
    return matched_credentials;
}