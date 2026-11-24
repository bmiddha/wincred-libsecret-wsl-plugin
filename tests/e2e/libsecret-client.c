#include <libsecret/secret.h>
#include <stdio.h>
#include <string.h>

static const SecretSchema schema = {
    "wincred-e2e",
    SECRET_SCHEMA_NONE,
    {
        { "e2e-run", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "e2e-kind", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL, 0 }
    }
};

static int fail(GError *error) {
    if (error != NULL) {
        fprintf(stderr, "libsecret E2E operation failed: %s\n", error->message);
        g_error_free(error);
    }
    return 1;
}

static const char *kind_for(const char *mode) {
    if (strcmp(mode, "replace") == 0 || strcmp(mode, "read-replacement") == 0) {
        return "libsecret-replacement";
    }
    return "libsecret";
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: libsecret-client MODE RUN-ID WORK-ROOT\n");
        return 2;
    }
    const char *mode = argv[1];
    const char *run_id = argv[2];
    const char *kind = kind_for(mode);
    const char *value = strcmp(kind, "libsecret-replacement") == 0
        ? "libsecret replacement unicode ✓" : "libsecret unicode ✓";
    GError *error = NULL;

    if (strcmp(mode, "write") == 0 || strcmp(mode, "replace") == 0) {
        if (!secret_password_store_sync(&schema, SECRET_COLLECTION_DEFAULT,
                                        "WinCred E2E libsecret client", value, NULL, &error,
                                        "e2e-run", run_id, "e2e-kind", kind, NULL)) {
            return fail(error);
        }
        return 0;
    }
    if (strcmp(mode, "read") == 0 || strcmp(mode, "read-replacement") == 0) {
        gchar *read = secret_password_lookup_sync(&schema, NULL, &error,
                                                  "e2e-run", run_id, "e2e-kind", kind, NULL);
        if (read == NULL) {
            return fail(error);
        }
        int result = g_strcmp0(read, value) == 0 ? 0 : 1;
        secret_password_free(read);
        if (result != 0) {
            fprintf(stderr, "libsecret E2E retrieval hash comparison failed\n");
        }
        return result;
    }
    if (strcmp(mode, "item-read") == 0) {
        /* The convenience API above reads through Service.GetSecrets, which
           answers with a map of secrets. This path asks for one item and so
           goes through Item.GetSecret, whose single out-argument has to be the
           (oayays) struct rather than that struct's four members loose:
           libsecret rejects the loose form, and this is the call that notices. */
        SecretService *service = secret_service_get_sync(SECRET_SERVICE_NONE, NULL, &error);
        if (service == NULL) {
            return fail(error);
        }
        GHashTable *attributes = g_hash_table_new(g_str_hash, g_str_equal);
        g_hash_table_insert(attributes, (gpointer)"e2e-run", (gpointer)run_id);
        g_hash_table_insert(attributes, (gpointer)"e2e-kind", (gpointer)kind);
        GList *items = secret_service_search_sync(service, NULL, attributes,
                                                  SECRET_SEARCH_NONE, NULL, &error);
        g_hash_table_unref(attributes);
        if (items == NULL) {
            g_object_unref(service);
            return fail(error);
        }
        int result = 1;
        for (GList *node = items; node != NULL; node = node->next) {
            SecretItem *item = SECRET_ITEM(node->data);
            if (!secret_item_load_secret_sync(item, NULL, &error)) {
                g_list_free_full(items, g_object_unref);
                g_object_unref(service);
                return fail(error);
            }
            SecretValue *secret = secret_item_get_secret(item);
            if (secret != NULL) {
                if (g_strcmp0(secret_value_get_text(secret), value) == 0) {
                    result = 0;
                }
                secret_value_unref(secret);
            }
        }
        g_list_free_full(items, g_object_unref);
        g_object_unref(service);
        if (result != 0) {
            fprintf(stderr, "libsecret E2E item read did not return the stored value\n");
        }
        return result;
    }
    if (strcmp(mode, "clear") == 0) {
        if (!secret_password_clear_sync(&schema, NULL, &error,
                                        "e2e-run", run_id, NULL)) {
            return fail(error);
        }
        return 0;
    }
    fprintf(stderr, "unknown libsecret E2E mode\n");
    return 2;
}
