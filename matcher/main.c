#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include "cJSON.h"
#include "credentialmanager.h"

#define Matcher_NONE (0)
#define Matcher_EQUAL (1 << 0)

typedef struct Matcher {
    char *name;
    int type;
    struct cJSON *matcher_value;
    struct Matcher *next;
} Matcher;

static void init_matcher(Matcher *curr, char *name, int type, cJSON *matcher_value, Matcher *next) {
    curr->name = name;
    curr->type = type;
    // TODO: store the value immediately for better efficiency.
    curr->matcher_value = matcher_value;
    curr->next = next;
}

typedef struct MatchersPerDoc {
    char *doc_type;
    struct Matcher *head_matcher;
    int matcher_size;
    struct MatchersPerDoc *next;
} MatchersPerDoc;

static void init_per_doc_matchers(MatchersPerDoc *it) {
    it->doc_type = NULL;
    it->head_matcher = malloc(sizeof(Matcher));
    it->matcher_size = 0;
    it->next = NULL;
}

// TODO: add full validation and refactoring for repeating logic.
int main() {
	printf("Identity Credentials Matcher\n");
	void* request = GetRequest();
	void* credentials = GetCredentials();

    CallingAppInfo *appInfo = malloc(sizeof(CallingAppInfo));
    GetCallingAppInfo(appInfo);
    printf("App package name: %s, origin: %s\n", appInfo->package_name, appInfo->origin);

    int* header_size = (int*) credentials;
    int* creds_size = (int*) (credentials + sizeof(int));
    int* icon_size_array_size = (int*) (credentials + sizeof(int) * 2);
    char* icon_ptr_array[(*icon_size_array_size) + 1];  // [icon1_start_ptr, icon2_start_ptr, ..., iconN_start_ptr, iconN_end_ptr]
    icon_ptr_array[0] = credentials + *header_size + *creds_size; // start of icon
    int icon_size_index = 0;
    while (icon_size_index < *icon_size_array_size) {
        int* curr_icon_size = (int*) (credentials + sizeof(int) * (3 + icon_size_index));
	    // printf("curr_icon_size: %d\n", *curr_icon_size);
        icon_ptr_array[icon_size_index+1] = icon_ptr_array[icon_size_index] + (*curr_icon_size); 
        ++icon_size_index;
    }
	cJSON *request_json = cJSON_Parse(request);
	cJSON *credentials_json = cJSON_Parse(credentials + *header_size);
	
	char *request_json_str = cJSON_Print(request_json);
	printf("Request: %s\n", request_json_str);
	char *creds_json_str = cJSON_Print(credentials_json);
	printf("Creds: %s\n", creds_json_str);

    char *preview_protocol_name = "preview";
    char *openid_protocol_name = "openid4vp";
    char *dot = ".";
    // Parse request
    MatchersPerDoc *doc_matcher_list = malloc(sizeof(MatchersPerDoc));
    init_per_doc_matchers(doc_matcher_list);
    MatchersPerDoc *curr_doc = doc_matcher_list;
    int doc_size = 0;
    cJSON *providers = cJSON_GetObjectItemCaseSensitive(request_json, "providers");
    if (cJSON_IsArray(providers)) {
        int providerSize = cJSON_GetArraySize(providers);
        int i = 0;
        while (i < providerSize) {
            cJSON *provider = cJSON_GetArrayItem(providers, i);
            if (cJSON_IsObject(provider)) {
            
                cJSON *protocol = cJSON_GetObjectItem(provider, "protocol");
                char* protocol_value = cJSON_GetStringValue(protocol);
	            printf("protocol in request: %s\n", protocol_value);
                cJSON *protocol_request = cJSON_GetObjectItem(provider, "request");
                char* protocol_request_value = cJSON_GetStringValue(protocol_request);
	            printf("protocol request: %s\n", protocol_request_value);
                cJSON *protocol_request_json = cJSON_Parse(protocol_request_value);
                
                // 1. PROTOCOL PREVIE
                if (strcmp(protocol_value, preview_protocol_name) == 0) {

                    cJSON *selector = cJSON_GetObjectItem(protocol_request_json, "selector");
                    if (cJSON_IsObject(selector)) {
                        Matcher *curr_matcher = curr_doc->head_matcher;
                        ++doc_size;
                        cJSON *doc_type = cJSON_GetObjectItem(selector, "doctype");
                        char *doc_type_value = cJSON_GetStringValue(doc_type);
                        curr_doc->doc_type = doc_type_value;

                        cJSON *fields = cJSON_GetObjectItem(selector, "fields");
                        if (cJSON_IsArray(fields)) {
                            int fieldSize = cJSON_GetArraySize(fields);
                            int j = 0;
                            while (j < fieldSize) {
                                cJSON *field = cJSON_GetArrayItem(fields, j);
                                if (cJSON_IsObject(field)) {
                                    // Required fields.
                                    cJSON *nameSpaceField =  cJSON_GetObjectItem(field, "namespace");
                                    char* nameSpaceFieldValue = cJSON_GetStringValue(nameSpaceField);
                                    cJSON *nameField =  cJSON_GetObjectItem(field, "name");
                                    char* nameFieldValue = cJSON_GetStringValue(nameField);

                                    // Optional matcher fields. For now only equal.
                                    // TODO: update
                                    // if (cJSON_HasObjectItem(field, "equal")) {
                                    //     cJSON *equalField = cJSON_GetObjectItem(field, "equal");
                                    //     Matcher *prev_matcher = head_matcher;
                                    //     head_matcher = malloc(sizeof(Matcher));
                                    //     init_matcher(head_matcher, nameFieldValue, Matcher_EQUAL, equalField, prev_matcher);
                                    //     ++matcher_size;
                                    // } else {
                                    Matcher *prev_matcher = curr_matcher;
                                    curr_matcher = malloc(sizeof(Matcher));
                                    prev_matcher->next = curr_matcher;
                                    prev_matcher->name = malloc(strlen(nameSpaceFieldValue) + strlen(nameFieldValue) + 2);
                                    strcpy(prev_matcher->name, nameSpaceFieldValue); 
                                    strcat(prev_matcher->name, dot);
                                    strcat(prev_matcher->name, nameFieldValue);
                                    prev_matcher->type = Matcher_NONE;
                                    prev_matcher->matcher_value = NULL;
                                    curr_doc->matcher_size = curr_doc->matcher_size + 1;
                                    // }
                                } else {
                                    printf("Not a valid field object\n");
                                }
                                ++j;
                            }
                        } else {
                            printf("Failed to find a valid `fields` field\n");
                        }
                    } else {
                        printf("Failed to find a valid `selector` field\n");
                    }
                }  else if (strcmp(protocol_value, openid_protocol_name) == 0) { 
                    // 2. PROTOCOL OPENID4VP

                    cJSON *presentation_definition = cJSON_GetObjectItem(protocol_request_json, "presentation_definition");
                    cJSON *input_descriptors = cJSON_GetObjectItem(presentation_definition, "input_descriptors"); 
                    int input_descriptor_size = cJSON_GetArraySize(input_descriptors);
                    int j = 0;
                    while (j < input_descriptor_size) {
                        ++doc_size;

                        cJSON *input_descriptor = cJSON_GetArrayItem(input_descriptors, j);

                        cJSON *doc_type =  cJSON_GetObjectItem(input_descriptor, "id");
                        char *doc_type_value = cJSON_GetStringValue(doc_type);
                        curr_doc->doc_type = doc_type_value;

                        cJSON *constraints =  cJSON_GetObjectItem(input_descriptor, "constraints");
                        cJSON *fields =  cJSON_GetObjectItem(constraints, "fields");
                        int fieldSize = cJSON_GetArraySize(fields);
                        int k = 0;
                        Matcher *curr_matcher = curr_doc->head_matcher;
                        while (k < fieldSize) {
                            cJSON *field = cJSON_GetArrayItem(fields, k);
                            if (cJSON_IsObject(field)) {
                                Matcher *prev_matcher = curr_matcher;
                                curr_matcher = malloc(sizeof(Matcher));
                                prev_matcher->next = curr_matcher;
                                prev_matcher->type = Matcher_NONE;
                                prev_matcher->matcher_value = NULL;
                                curr_doc->matcher_size = curr_doc->matcher_size + 1;

                                cJSON *path =  cJSON_GetObjectItem(field, "path");
                                cJSON *path_name =  cJSON_GetArrayItem(path, 0);
                                // E.g. "$['org.iso.18013.5.1']['family_name']"
                                char *path_name_value = cJSON_GetStringValue(path_name);
                                prev_matcher->name = malloc(strlen(path_name_value) - 7);
                                char name_space_end_char = '\'';
                                char *name_space_end = strchr(path_name_value + 3, name_space_end_char);
                                char *name_value_end = strchr(name_space_end + 4, name_space_end_char);
                                char name_space_len = name_space_end - path_name_value - 3;
                                strncpy(prev_matcher->name, path_name_value + 3, name_space_len);
                                (prev_matcher->name)[name_space_len] = '.';
                                strncpy(prev_matcher->name + name_space_len + 1, name_space_end + 4, name_value_end - name_space_end - 4);
                                (prev_matcher->name)[strlen(path_name_value) - 8] = '\0'; // Null terminate
                                printf("Matcher: %s\n", prev_matcher->name);
                            } else {
                                printf("Not a valid field object\n");
                            }
                            ++k;
                        }

                        ++j;
                        MatchersPerDoc *prev_doc = curr_doc;
                        curr_doc = malloc(sizeof(MatchersPerDoc));
                        init_per_doc_matchers(curr_doc);
                        prev_doc->next = curr_doc;
                    }


                }  else {
                    printf("Unsupported protocol: %s\n", protocol_value);
                    return 0;
                }
            
            } else {
                printf("Not a valid provider object\n");
            }
            ++i;
        }
    } else {
        printf("Failed to find a valid `providers` field\n");
    }

    if (doc_size == 0 || doc_matcher_list->matcher_size == 0) {
        printf("Abort: can't find any valid matcher in request. \n");
        return 0;
    }

    // Match data
    cJSON *creds = cJSON_GetObjectItemCaseSensitive(credentials_json, "credentials");
    printf("Matching\n");
    if (cJSON_IsArray(creds)) {
        int credential_size = cJSON_GetArraySize(creds);
        int i = 0;
        while (i < credential_size) {
            cJSON *cred = cJSON_GetArrayItem(creds, i);
            if (cJSON_IsObject(cred)) {
                cJSON *credential = cJSON_GetObjectItem(cred, "credential");
                cJSON *cred_fields = cJSON_GetObjectItem(credential, "fields");
                int field_size = cJSON_GetArraySize(cred_fields);

                int doc_idx = 0;
                MatchersPerDoc *curr_doc = doc_matcher_list;
                while (doc_idx < doc_size) {
                    // Pre-allocate spaces to record field names and values that are matched.
                    int matcher_size = curr_doc->matcher_size; // TODO next/[0]
                    char **field_display_names = malloc(sizeof(char*) * matcher_size);
                    char **field_display_values = malloc(sizeof(char*) * matcher_size);
                    int field_display_names_idx = 0;
                    int matcher_idx = 0;
                    Matcher *matcher_itr = curr_doc->head_matcher; // TODO next/[0]
                    while (matcher_idx < matcher_size) {
                        int matched = 0;
                        int j = 0;
                        while (j < field_size) {
                            cJSON *field = cJSON_GetArrayItem(cred_fields, j);
                            cJSON *field_name = cJSON_GetObjectItem(field, "name");
                            char* field_name_value = cJSON_GetStringValue(field_name);
                            if (strcmp(matcher_itr->name, field_name_value) == 0) {
                                printf("matched matchername: %s\n", matcher_itr->name);
                                printf("matched fieldname: %s\n", field_name_value);
                                if ((matcher_itr->type & 0xFF) == Matcher_NONE) {
                                    // TODO: abstract into method
                                    // if-change-#1
                                    if (cJSON_HasObjectItem(field, "display_name")){
                                        cJSON *field_display_name = cJSON_GetObjectItem(field, "display_name");
                                        field_display_names[field_display_names_idx] = cJSON_GetStringValue(field_display_name);
                                        if (cJSON_HasObjectItem(field, "display_value")){
                                            cJSON *field_display_value = cJSON_GetObjectItem(field, "display_value");
                                            field_display_values[field_display_names_idx] = cJSON_GetStringValue(field_display_value);
                                        } else {
                                                field_display_values[field_display_names_idx] = NULL;
                                        }
                                        ++field_display_names_idx;
                                    }
                                    // End if-change-#1
                                    matched = 1;
                                } else if ((matcher_itr->type & 0xFF) == Matcher_EQUAL) {
                                    cJSON *field_value = cJSON_GetObjectItem(field, "value");
                                    char* field_value_str = cJSON_GetStringValue(field_value);
                                    char* matcher_value_str = cJSON_GetStringValue(matcher_itr->matcher_value);
                                    if (strcmp(matcher_value_str, field_value_str) == 0) {
                                        // then-change-#1
                                        if (cJSON_HasObjectItem(field, "display_name")){
                                            cJSON *field_display_name = cJSON_GetObjectItem(field, "display_name");
                                            field_display_names[field_display_names_idx] = cJSON_GetStringValue(field_display_name);
                                            if (cJSON_HasObjectItem(field, "display_value")){
                                                cJSON *field_display_value = cJSON_GetObjectItem(field, "display_value");
                                                field_display_values[field_display_names_idx] = cJSON_GetStringValue(field_display_value);
                                            } else {
                                                field_display_values[field_display_names_idx] = NULL;
                                            }
                                            ++field_display_names_idx;
                                        }
                                        // End then-change-#1
                                        matched = 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                            ++j;
                        }
                        if (matched == 0) {
                            printf("matched == 0");
                            break;
                        }
                        ++matcher_idx;
                        matcher_itr = matcher_itr->next;
                    }
                    if (matcher_idx == matcher_size && matcher_size != 0) { // All matcher succeeds through. The cred is a match.
                        printf("Found a match!\n");
                        cJSON *id = cJSON_GetObjectItem(cred, "id");
                        char *id_value = cJSON_GetStringValue(id);
                        cJSON *cred_display_info = cJSON_GetObjectItem(credential, "display_info");
                        cJSON *title_json = cJSON_GetObjectItem(cred_display_info, "title");
                        char *title = cJSON_GetStringValue(title_json);
                        char *icon_start = NULL;
                        size_t icon_len = 0;
                        char *subtitle = NULL;
                        char *disclaimer = NULL;
                        char *warning = NULL;
                        if (cJSON_HasObjectItem(cred_display_info, "icon_id")){
                            cJSON *icon_id_json = cJSON_GetObjectItem(cred_display_info, "icon_id");
                            int icon_id = cJSON_GetNumberValue(icon_id_json);
                            if (icon_id >= 0 && icon_id < *icon_size_array_size) {
                                icon_start = icon_ptr_array[icon_id];
                                icon_len = icon_ptr_array[icon_id+1] - icon_start;
                            }
                        }
                        if (cJSON_HasObjectItem(cred_display_info, "subtitle")){
                            cJSON *subtitle_json = cJSON_GetObjectItem(cred_display_info, "subtitle");
                            subtitle = cJSON_GetStringValue(subtitle_json);
                        }
                        if (cJSON_HasObjectItem(cred_display_info, "disclaimer")){
                            cJSON *disclaimer_json = cJSON_GetObjectItem(cred_display_info, "disclaimer");
                            disclaimer = cJSON_GetStringValue(disclaimer_json);
                        }
                        if (cJSON_HasObjectItem(cred_display_info, "warning")){
                            cJSON *warning_json = cJSON_GetObjectItem(cred_display_info, "warning");
                            warning = cJSON_GetStringValue(warning_json);
                        }
                        printf("Adding entry with title %s, icon_len!\n", title);
                        AddStringIdEntry(id_value, icon_start, icon_len, title, subtitle, disclaimer, warning);

                        int k = 0;
                        while (k < field_display_names_idx) {
                            printf("Adding field with display name %s!\n", field_display_names[k]);
                            AddFieldForStringIdEntry(id_value, field_display_names[k], field_display_values[k]);
                            ++k;
                        }
                        break;
                    }
                    ++doc_idx;
                    curr_doc = curr_doc->next;
                }
                
            } else {
                printf("Not a valid credential object\n");
            }
            ++i;
        }
    } else {
        printf("Failed to find a valid `credentials` field\n");
    }

	//cJSON_Delete(request_json);
	//cJSON_Delete(credentials_json);
	return 0;
}