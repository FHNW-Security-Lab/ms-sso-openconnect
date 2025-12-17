/*
 * NetworkManager VPN Plugin Editor for MS SSO OpenConnect
 *
 * Provides the GTK4 editor interface for configuring MS SSO VPN
 * connections in GNOME Settings (gnome-control-center).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <gtk/gtk.h>
#include <NetworkManager.h>
#include <libsecret/secret.h>
#include <string.h>

#include "nm-ms-sso-editor.h"

/* Keyring schema for MS SSO VPN secrets */
static const SecretSchema ms_sso_schema = {
    "org.freedesktop.NetworkManager.ms-sso",
    SECRET_SCHEMA_DONT_MATCH_NAME,
    {
        { "connection-id", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "secret-type", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL, 0 }
    }
};

/* VPN data keys */
#define KEY_GATEWAY        "gateway"
#define KEY_PROTOCOL       "protocol"
#define KEY_USERNAME       "username"

/* Secret keys */
#define KEY_PASSWORD       "password"
#define KEY_TOTP_SECRET    "totp-secret"

/* Protocol values */
#define PROTO_ANYCONNECT   "anyconnect"
#define PROTO_GP           "gp"

/*
 * Editor Private Data
 */
struct _MsSsoEditorPrivate {
    GtkWidget *widget;

    /* UI widgets */
    GtkEntry *gateway;
    GtkDropDown *protocol;
    GtkEntry *username;
    GtkPasswordEntry *password;
    GtkPasswordEntry *totp_secret;

    /* Protocol model */
    GtkStringList *protocol_model;

    NMConnection *connection;
    gboolean changed;
};

static void ms_sso_editor_interface_init(NMVpnEditorInterface *iface);

G_DEFINE_TYPE_WITH_CODE(MsSsoEditor, ms_sso_editor, G_TYPE_OBJECT,
                        G_ADD_PRIVATE(MsSsoEditor)
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR,
                                              ms_sso_editor_interface_init))

enum {
    PROP_0,
    PROP_CONNECTION,
    LAST_PROP
};

/*
 * Helper: Get secret from keyring
 */
static char *
keyring_get_secret(const char *connection_uuid, const char *secret_type)
{
    GError *error = NULL;
    char *secret;

    if (!connection_uuid || !*connection_uuid) {
        g_message("ms-sso-editor: keyring_get_secret: no connection UUID");
        return NULL;
    }

    g_message("ms-sso-editor: keyring_get_secret: looking up %s for %s", secret_type, connection_uuid);

    secret = secret_password_lookup_sync(&ms_sso_schema, NULL, &error,
                                         "connection-id", connection_uuid,
                                         "secret-type", secret_type,
                                         NULL);
    if (error) {
        g_warning("ms-sso-editor: Failed to lookup secret: %s", error->message);
        g_error_free(error);
        return NULL;
    }

    if (secret) {
        g_message("ms-sso-editor: keyring_get_secret: found %s", secret_type);
    } else {
        g_message("ms-sso-editor: keyring_get_secret: %s not found", secret_type);
    }

    return secret;
}

/*
 * Helper: Store secret in keyring
 */
static gboolean
keyring_store_secret(const char *connection_uuid, const char *secret_type, const char *secret)
{
    GError *error = NULL;
    gboolean success;
    char *label;

    if (!connection_uuid || !*connection_uuid) {
        g_message("ms-sso-editor: keyring_store_secret: no connection UUID");
        return FALSE;
    }

    g_message("ms-sso-editor: keyring_store_secret: storing %s for %s", secret_type, connection_uuid);

    /* If secret is empty, remove it */
    if (!secret || !*secret) {
        g_message("ms-sso-editor: keyring_store_secret: clearing empty secret");
        secret_password_clear_sync(&ms_sso_schema, NULL, &error,
                                   "connection-id", connection_uuid,
                                   "secret-type", secret_type,
                                   NULL);
        if (error) {
            g_warning("ms-sso-editor: Failed to clear secret: %s", error->message);
            g_error_free(error);
        }
        return TRUE;
    }

    label = g_strdup_printf("MS SSO VPN %s for %s", secret_type, connection_uuid);
    success = secret_password_store_sync(&ms_sso_schema,
                                         SECRET_COLLECTION_DEFAULT,
                                         label, secret, NULL, &error,
                                         "connection-id", connection_uuid,
                                         "secret-type", secret_type,
                                         NULL);
    g_free(label);

    if (error) {
        g_warning("ms-sso-editor: Failed to store secret: %s", error->message);
        g_error_free(error);
        return FALSE;
    }

    g_message("ms-sso-editor: keyring_store_secret: %s stored successfully: %d", secret_type, success);

    return success;
}

/*
 * Signal emission on changes
 */
static void
stuff_changed_cb(GtkWidget *widget, gpointer user_data)
{
    MsSsoEditor *self = MS_SSO_EDITOR(user_data);
    self->priv->changed = TRUE;
    g_signal_emit_by_name(self, "changed");
}

/*
 * Get the editor widget
 */
static GObject *
get_widget(NMVpnEditor *editor)
{
    MsSsoEditor *self = MS_SSO_EDITOR(editor);
    return G_OBJECT(self->priv->widget);
}

/*
 * Update the NMConnection with current values
 */
static gboolean
update_connection(NMVpnEditor *editor, NMConnection *connection, GError **error)
{
    MsSsoEditor *self = MS_SSO_EDITOR(editor);
    MsSsoEditorPrivate *priv = self->priv;
    NMSettingVpn *s_vpn;
    NMSettingConnection *s_con;
    const char *gateway;
    const char *username;
    const char *password;
    const char *totp_secret;
    const char *connection_id;
    guint protocol_idx;
    const char *protocol;

    /* Get values from widgets */
    gateway = gtk_editable_get_text(GTK_EDITABLE(priv->gateway));
    username = gtk_editable_get_text(GTK_EDITABLE(priv->username));
    password = gtk_editable_get_text(GTK_EDITABLE(priv->password));
    totp_secret = gtk_editable_get_text(GTK_EDITABLE(priv->totp_secret));
    protocol_idx = gtk_drop_down_get_selected(priv->protocol);

    /* Validate gateway */
    if (!gateway || !*gateway) {
        g_set_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING,
                    "Gateway is required");
        return FALSE;
    }

    /* Validate username */
    if (!username || !*username) {
        g_set_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING,
                    "Username is required");
        return FALSE;
    }

    /* Get or create VPN setting */
    s_vpn = nm_connection_get_setting_vpn(connection);
    if (!s_vpn) {
        s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
        nm_connection_add_setting(connection, NM_SETTING(s_vpn));
    }

    /* Set service type */
    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.ms-sso", NULL);

    /* Set data items */
    nm_setting_vpn_add_data_item(s_vpn, KEY_GATEWAY, gateway);
    nm_setting_vpn_add_data_item(s_vpn, KEY_USERNAME, username);

    /* Set protocol */
    protocol = (protocol_idx == 0) ? PROTO_ANYCONNECT : PROTO_GP;
    nm_setting_vpn_add_data_item(s_vpn, KEY_PROTOCOL, protocol);

    /* Set secrets in NM connection (for NM's internal handling) */
    if (password && *password) {
        nm_setting_vpn_add_secret(s_vpn, KEY_PASSWORD, password);
    }
    if (totp_secret && *totp_secret) {
        nm_setting_vpn_add_secret(s_vpn, KEY_TOTP_SECRET, totp_secret);
    }

    /* Also store secrets in keyring for direct access using UUID (stable identifier) */
    s_con = nm_connection_get_setting_connection(connection);
    connection_id = s_con ? nm_setting_connection_get_uuid(s_con) : NULL;
    g_message("ms-sso-editor: update_connection: UUID=%s", connection_id ? connection_id : "(null)");
    if (connection_id) {
        keyring_store_secret(connection_id, KEY_PASSWORD, password);
        keyring_store_secret(connection_id, KEY_TOTP_SECRET, totp_secret);
    } else {
        g_warning("ms-sso-editor: update_connection: no UUID, cannot store secrets in keyring");
    }

    return TRUE;
}

/*
 * Create the editor widget
 */
static GtkWidget *
create_editor_widget(MsSsoEditor *self)
{
    MsSsoEditorPrivate *priv = self->priv;
    GtkWidget *grid;
    GtkWidget *label;
    int row = 0;

    /* Create main grid */
    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_widget_set_margin_top(grid, 12);
    gtk_widget_set_margin_bottom(grid, 12);
    gtk_widget_set_margin_start(grid, 12);
    gtk_widget_set_margin_end(grid, 12);

    /* Gateway */
    label = gtk_label_new("Gateway:");
    gtk_widget_set_halign(label, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);

    priv->gateway = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(priv->gateway, "vpn.example.com");
    gtk_widget_set_hexpand(GTK_WIDGET(priv->gateway), TRUE);
    g_signal_connect(priv->gateway, "changed", G_CALLBACK(stuff_changed_cb), self);
    gtk_grid_attach(GTK_GRID(grid), GTK_WIDGET(priv->gateway), 1, row, 1, 1);
    row++;

    /* Protocol */
    label = gtk_label_new("Protocol:");
    gtk_widget_set_halign(label, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);

    priv->protocol_model = gtk_string_list_new(NULL);
    gtk_string_list_append(priv->protocol_model, "Cisco AnyConnect");
    gtk_string_list_append(priv->protocol_model, "GlobalProtect");

    priv->protocol = GTK_DROP_DOWN(gtk_drop_down_new(G_LIST_MODEL(priv->protocol_model), NULL));
    gtk_widget_set_hexpand(GTK_WIDGET(priv->protocol), TRUE);
    g_signal_connect(priv->protocol, "notify::selected", G_CALLBACK(stuff_changed_cb), self);
    gtk_grid_attach(GTK_GRID(grid), GTK_WIDGET(priv->protocol), 1, row, 1, 1);
    row++;

    /* Username */
    label = gtk_label_new("Username:");
    gtk_widget_set_halign(label, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);

    priv->username = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(priv->username, "user@example.com");
    gtk_widget_set_hexpand(GTK_WIDGET(priv->username), TRUE);
    g_signal_connect(priv->username, "changed", G_CALLBACK(stuff_changed_cb), self);
    gtk_grid_attach(GTK_GRID(grid), GTK_WIDGET(priv->username), 1, row, 1, 1);
    row++;

    /* Password */
    label = gtk_label_new("Password:");
    gtk_widget_set_halign(label, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);

    priv->password = GTK_PASSWORD_ENTRY(gtk_password_entry_new());
    gtk_password_entry_set_show_peek_icon(priv->password, TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(priv->password), TRUE);
    g_signal_connect(priv->password, "changed", G_CALLBACK(stuff_changed_cb), self);
    gtk_grid_attach(GTK_GRID(grid), GTK_WIDGET(priv->password), 1, row, 1, 1);
    row++;

    /* TOTP Secret */
    label = gtk_label_new("TOTP Secret:");
    gtk_widget_set_halign(label, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);

    priv->totp_secret = GTK_PASSWORD_ENTRY(gtk_password_entry_new());
    gtk_password_entry_set_show_peek_icon(priv->totp_secret, TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(priv->totp_secret), TRUE);
    g_signal_connect(priv->totp_secret, "changed", G_CALLBACK(stuff_changed_cb), self);
    gtk_grid_attach(GTK_GRID(grid), GTK_WIDGET(priv->totp_secret), 1, row, 1, 1);
    row++;

    /* Info label */
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label),
        "<small>TOTP Secret is the Base32 secret key from your authenticator app setup.\n"
        "Leave empty if TOTP is not required.</small>");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(label, 12);
    gtk_grid_attach(GTK_GRID(grid), label, 0, row, 2, 1);

    return grid;
}

/*
 * Load connection settings into the editor
 */
static void
load_connection(MsSsoEditor *self, NMConnection *connection)
{
    MsSsoEditorPrivate *priv = self->priv;
    NMSettingVpn *s_vpn;
    NMSettingConnection *s_con;
    const char *gateway;
    const char *protocol;
    const char *username;
    const char *password;
    const char *totp_secret;
    const char *connection_uuid;
    char *keyring_password = NULL;
    char *keyring_totp = NULL;

    s_vpn = nm_connection_get_setting_vpn(connection);
    if (!s_vpn) {
        g_message("ms-sso-editor: load_connection: no VPN setting");
        return;
    }

    /* Get connection UUID for keyring lookup (UUID is stable, ID can change) */
    s_con = nm_connection_get_setting_connection(connection);
    connection_uuid = s_con ? nm_setting_connection_get_uuid(s_con) : NULL;
    g_message("ms-sso-editor: load_connection: UUID=%s", connection_uuid ? connection_uuid : "(null)");

    /* Load data items */
    gateway = nm_setting_vpn_get_data_item(s_vpn, KEY_GATEWAY);
    if (gateway)
        gtk_editable_set_text(GTK_EDITABLE(priv->gateway), gateway);

    protocol = nm_setting_vpn_get_data_item(s_vpn, KEY_PROTOCOL);
    if (protocol) {
        if (g_strcmp0(protocol, PROTO_GP) == 0)
            gtk_drop_down_set_selected(priv->protocol, 1);
        else
            gtk_drop_down_set_selected(priv->protocol, 0);
    }

    username = nm_setting_vpn_get_data_item(s_vpn, KEY_USERNAME);
    if (username)
        gtk_editable_set_text(GTK_EDITABLE(priv->username), username);

    /* Load secrets - try NM first, then keyring */
    password = nm_setting_vpn_get_secret(s_vpn, KEY_PASSWORD);
    g_message("ms-sso-editor: load_connection: NM password=%s", password ? "(set)" : "(null)");
    if (!password && connection_uuid) {
        keyring_password = keyring_get_secret(connection_uuid, KEY_PASSWORD);
        password = keyring_password;
    }
    if (password)
        gtk_editable_set_text(GTK_EDITABLE(priv->password), password);

    totp_secret = nm_setting_vpn_get_secret(s_vpn, KEY_TOTP_SECRET);
    g_message("ms-sso-editor: load_connection: NM totp=%s", totp_secret ? "(set)" : "(null)");
    if (!totp_secret && connection_uuid) {
        keyring_totp = keyring_get_secret(connection_uuid, KEY_TOTP_SECRET);
        totp_secret = keyring_totp;
    }
    if (totp_secret)
        gtk_editable_set_text(GTK_EDITABLE(priv->totp_secret), totp_secret);

    /* Free keyring-retrieved secrets */
    secret_password_free(keyring_password);
    secret_password_free(keyring_totp);

    priv->changed = FALSE;
}

/*
 * Editor interface implementation
 */
static void
ms_sso_editor_interface_init(NMVpnEditorInterface *iface)
{
    iface->get_widget = get_widget;
    iface->update_connection = update_connection;
}

/*
 * GObject methods
 */
static void
ms_sso_editor_init(MsSsoEditor *self)
{
    self->priv = ms_sso_editor_get_instance_private(self);
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    MsSsoEditor *self = MS_SSO_EDITOR(object);

    switch (prop_id) {
    case PROP_CONNECTION:
        self->priv->connection = g_value_dup_object(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    MsSsoEditor *self = MS_SSO_EDITOR(object);

    switch (prop_id) {
    case PROP_CONNECTION:
        g_value_set_object(value, self->priv->connection);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
constructed(GObject *object)
{
    MsSsoEditor *self = MS_SSO_EDITOR(object);

    G_OBJECT_CLASS(ms_sso_editor_parent_class)->constructed(object);

    /* Create the widget */
    self->priv->widget = create_editor_widget(self);
    g_object_ref_sink(self->priv->widget);

    /* Load connection if provided */
    if (self->priv->connection)
        load_connection(self, self->priv->connection);
}

static void
dispose(GObject *object)
{
    MsSsoEditor *self = MS_SSO_EDITOR(object);

    /* Note: protocol_model is owned by the GtkDropDown after gtk_drop_down_new(),
     * so we don't clear it here - it will be freed when the widget is disposed */
    g_clear_object(&self->priv->widget);
    g_clear_object(&self->priv->connection);

    G_OBJECT_CLASS(ms_sso_editor_parent_class)->dispose(object);
}

static void
ms_sso_editor_class_init(MsSsoEditorClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->constructed = constructed;
    object_class->dispose = dispose;
    object_class->set_property = set_property;
    object_class->get_property = get_property;

    g_object_class_install_property(object_class, PROP_CONNECTION,
        g_param_spec_object("connection", "Connection",
                            "NMConnection",
                            NM_TYPE_CONNECTION,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

/*
 * Editor factory function
 */
NMVpnEditor *
ms_sso_editor_new(NMConnection *connection, GError **error)
{
    return NM_VPN_EDITOR(g_object_new(MS_SSO_TYPE_EDITOR,
                                      "connection", connection,
                                      NULL));
}

/*
 * Editor Plugin Implementation
 */

/* Plugin property IDs */
enum {
    PLUGIN_PROP_0,
    PLUGIN_PROP_NAME,
    PLUGIN_PROP_DESC,
    PLUGIN_PROP_SERVICE,
    PLUGIN_LAST_PROP
};

static void ms_sso_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface);

G_DEFINE_TYPE_WITH_CODE(MsSsoEditorPlugin, ms_sso_editor_plugin, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN,
                                              ms_sso_editor_plugin_interface_init))

static NMVpnEditor *
plugin_get_editor(NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
    return ms_sso_editor_new(connection, error);
}

static guint32
plugin_get_capabilities(NMVpnEditorPlugin *plugin)
{
    return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static void
ms_sso_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface)
{
    iface->get_editor = plugin_get_editor;
    iface->get_capabilities = plugin_get_capabilities;
}

static void
ms_sso_editor_plugin_init(MsSsoEditorPlugin *plugin)
{
}

static void
plugin_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    switch (prop_id) {
    case PLUGIN_PROP_NAME:
        g_value_set_string(value, "MS SSO OpenConnect");
        break;
    case PLUGIN_PROP_DESC:
        g_value_set_string(value, "VPN connection using Microsoft SSO authentication");
        break;
    case PLUGIN_PROP_SERVICE:
        g_value_set_string(value, "org.freedesktop.NetworkManager.ms-sso");
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
ms_sso_editor_plugin_class_init(MsSsoEditorPluginClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->get_property = plugin_get_property;

    g_object_class_override_property(object_class, PLUGIN_PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);
    g_object_class_override_property(object_class, PLUGIN_PROP_DESC, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
    g_object_class_override_property(object_class, PLUGIN_PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

/*
 * Plugin factory - entry point
 */
G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory(GError **error)
{
    return NM_VPN_EDITOR_PLUGIN(g_object_new(MS_SSO_TYPE_EDITOR_PLUGIN, NULL));
}
