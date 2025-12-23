#include <NetworkManager.h>
#include <gtk/gtk.h>

#define VPN_SERVICE_TYPE "org.freedesktop.NetworkManager.ms-sso-openconnect"

#define DATA_KEY_GATEWAY   "gateway"
#define DATA_KEY_PROTOCOL  "protocol"
#define DATA_KEY_USERNAME  "username"
#define DATA_KEY_NO_DTLS   "no-dtls"

#define SECRET_KEY_PASSWORD    "password"
#define SECRET_KEY_TOTP_SECRET "totp-secret"

typedef struct {
    GtkWidget *root;
    GtkWidget *gateway_entry;
    GtkWidget *protocol_dropdown;
    GtkWidget *username_entry;
    GtkWidget *password_entry;
    GtkWidget *totp_entry;
    GtkWidget *no_dtls_check;
} MsSsoEditorWidgets;

typedef struct {
    GObject parent;
    MsSsoEditorWidgets ui;
} MsSsoVpnEditor;

typedef struct {
    GObjectClass parent;
} MsSsoVpnEditorClass;

static void ms_sso_vpn_editor_interface_init(NMVpnEditorInterface *iface);

G_DEFINE_TYPE_WITH_CODE(MsSsoVpnEditor,
                        ms_sso_vpn_editor,
                        G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR, ms_sso_vpn_editor_interface_init))

typedef struct {
    GObject parent;
} MsSsoVpnEditorPlugin;

typedef struct {
    GObjectClass parent;
} MsSsoVpnEditorPluginClass;

static void ms_sso_vpn_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface);

G_DEFINE_TYPE_WITH_CODE(MsSsoVpnEditorPlugin,
                        ms_sso_vpn_editor_plugin,
                        G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN,
                                              ms_sso_vpn_editor_plugin_interface_init))

enum {
    PROP_0,
    PROP_NAME,
    PROP_DESCRIPTION,
    PROP_SERVICE,
    PROP_LAST,
};

static GParamSpec *properties[PROP_LAST];

static const char *
_dropdown_get_protocol(GtkDropDown *dropdown)
{
    guint idx = gtk_drop_down_get_selected(dropdown);
    return (idx == 1) ? "gp" : "anyconnect";
}

static void
_dropdown_set_protocol(GtkDropDown *dropdown, const char *protocol)
{
    if (protocol && g_strcmp0(protocol, "gp") == 0)
        gtk_drop_down_set_selected(dropdown, 1);
    else
        gtk_drop_down_set_selected(dropdown, 0);
}

static void
_editor_emit_changed(MsSsoVpnEditor *editor)
{
    g_signal_emit_by_name(editor, "changed");
}

static void
_wire_changed_signals(MsSsoVpnEditor *editor)
{
    g_signal_connect_swapped(editor->ui.gateway_entry, "changed", G_CALLBACK(_editor_emit_changed), editor);
    g_signal_connect_swapped(editor->ui.username_entry, "changed", G_CALLBACK(_editor_emit_changed), editor);
    g_signal_connect_swapped(editor->ui.password_entry, "changed", G_CALLBACK(_editor_emit_changed), editor);
    g_signal_connect_swapped(editor->ui.totp_entry, "changed", G_CALLBACK(_editor_emit_changed), editor);
    g_signal_connect_swapped(editor->ui.no_dtls_check, "toggled", G_CALLBACK(_editor_emit_changed), editor);
    g_signal_connect_swapped(editor->ui.protocol_dropdown,
                             "notify::selected",
                             G_CALLBACK(_editor_emit_changed),
                             editor);
}

static GtkWidget *
_labeled_row(const char *label, GtkWidget *widget)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *lbl = gtk_label_new(label);
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_widget_set_hexpand(lbl, FALSE);
    gtk_box_append(GTK_BOX(box), lbl);
    gtk_widget_set_hexpand(widget, TRUE);
    gtk_box_append(GTK_BOX(box), widget);
    return box;
}

static void
ms_sso_vpn_editor_init(MsSsoVpnEditor *self)
{
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(root, 12);
    gtk_widget_set_margin_end(root, 12);
    gtk_widget_set_margin_top(root, 12);
    gtk_widget_set_margin_bottom(root, 12);

    self->ui.gateway_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(self->ui.gateway_entry), "vpn.example.com");

    GtkStringList *protocols = gtk_string_list_new(NULL);
    gtk_string_list_append(protocols, "Cisco AnyConnect");
    gtk_string_list_append(protocols, "GlobalProtect");
    self->ui.protocol_dropdown = gtk_drop_down_new(G_LIST_MODEL(protocols), NULL);

    self->ui.username_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(self->ui.username_entry), "user@example.com");

    self->ui.password_entry = gtk_password_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(self->ui.password_entry), "Password");

    self->ui.totp_entry = gtk_password_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(self->ui.totp_entry), "Base32 TOTP secret");

    self->ui.no_dtls_check = gtk_check_button_new_with_label("Disable DTLS (TCP only)");

    gtk_box_append(GTK_BOX(root), _labeled_row("Server", self->ui.gateway_entry));
    gtk_box_append(GTK_BOX(root), _labeled_row("Protocol", self->ui.protocol_dropdown));
    gtk_box_append(GTK_BOX(root), _labeled_row("Username", self->ui.username_entry));
    gtk_box_append(GTK_BOX(root), _labeled_row("Password", self->ui.password_entry));
    gtk_box_append(GTK_BOX(root), _labeled_row("TOTP Secret", self->ui.totp_entry));
    gtk_box_append(GTK_BOX(root), self->ui.no_dtls_check);

    self->ui.root = root;

    _wire_changed_signals(self);
}

static void
ms_sso_vpn_editor_class_init(MsSsoVpnEditorClass *klass)
{
    (void) klass;
}

static GObject *
ms_sso_vpn_editor_get_widget(NMVpnEditor *editor)
{
    MsSsoVpnEditor *self = (MsSsoVpnEditor *) editor;
    return G_OBJECT(self->ui.root);
}

static gboolean
ms_sso_vpn_editor_update_connection(NMVpnEditor *editor, NMConnection *connection, GError **error)
{
    MsSsoVpnEditor *self = (MsSsoVpnEditor *) editor;

    const char *gateway = gtk_editable_get_text(GTK_EDITABLE(self->ui.gateway_entry));
    const char *username = gtk_editable_get_text(GTK_EDITABLE(self->ui.username_entry));
    const char *password = gtk_editable_get_text(GTK_EDITABLE(self->ui.password_entry));
    const char *totp_secret = gtk_editable_get_text(GTK_EDITABLE(self->ui.totp_entry));
    const char *protocol = _dropdown_get_protocol(GTK_DROP_DOWN(self->ui.protocol_dropdown));
    gboolean no_dtls = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->ui.no_dtls_check));

    if (!gateway || !gateway[0]) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing server address");
        return FALSE;
    }
    if (!username || !username[0]) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing username");
        return FALSE;
    }
    if (!password || !password[0]) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing password");
        return FALSE;
    }
    if (!totp_secret || !totp_secret[0]) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing TOTP secret");
        return FALSE;
    }

    NMSettingVpn *s_vpn = nm_connection_get_setting_vpn(connection);
    if (!s_vpn) {
        s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
        nm_connection_add_setting(connection, NM_SETTING(s_vpn));
    }

    g_object_set(G_OBJECT(s_vpn), NM_SETTING_VPN_SERVICE_TYPE, VPN_SERVICE_TYPE, NULL);

    nm_setting_vpn_add_data_item(s_vpn, DATA_KEY_GATEWAY, gateway);
    nm_setting_vpn_add_data_item(s_vpn, DATA_KEY_PROTOCOL, protocol);
    nm_setting_vpn_add_data_item(s_vpn, DATA_KEY_USERNAME, username);
    nm_setting_vpn_add_data_item(s_vpn, DATA_KEY_NO_DTLS, no_dtls ? "yes" : "no");

    nm_setting_vpn_add_secret(s_vpn, SECRET_KEY_PASSWORD, password);
    nm_setting_vpn_add_secret(s_vpn, SECRET_KEY_TOTP_SECRET, totp_secret);

    nm_setting_set_secret_flags(NM_SETTING(s_vpn),
                                SECRET_KEY_PASSWORD,
                                NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                NULL);
    nm_setting_set_secret_flags(NM_SETTING(s_vpn),
                                SECRET_KEY_TOTP_SECRET,
                                NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                NULL);

    return TRUE;
}

static void
ms_sso_vpn_editor_interface_init(NMVpnEditorInterface *iface)
{
    iface->get_widget = ms_sso_vpn_editor_get_widget;
    iface->update_connection = ms_sso_vpn_editor_update_connection;
}

static NMVpnEditor *
ms_sso_vpn_editor_new_from_connection(NMConnection *connection)
{
    MsSsoVpnEditor *editor = g_object_new(ms_sso_vpn_editor_get_type(), NULL);

    if (connection) {
        NMSettingVpn *s_vpn = nm_connection_get_setting_vpn(connection);
        if (s_vpn) {
            const char *gateway = nm_setting_vpn_get_data_item(s_vpn, DATA_KEY_GATEWAY);
            const char *protocol = nm_setting_vpn_get_data_item(s_vpn, DATA_KEY_PROTOCOL);
            const char *username = nm_setting_vpn_get_data_item(s_vpn, DATA_KEY_USERNAME);
            const char *password = nm_setting_vpn_get_secret(s_vpn, SECRET_KEY_PASSWORD);
            const char *totp = nm_setting_vpn_get_secret(s_vpn, SECRET_KEY_TOTP_SECRET);
            const char *no_dtls = nm_setting_vpn_get_data_item(s_vpn, DATA_KEY_NO_DTLS);

            if (gateway)
                gtk_editable_set_text(GTK_EDITABLE(editor->ui.gateway_entry), gateway);
            if (username)
                gtk_editable_set_text(GTK_EDITABLE(editor->ui.username_entry), username);
            if (password)
                gtk_editable_set_text(GTK_EDITABLE(editor->ui.password_entry), password);
            if (totp)
                gtk_editable_set_text(GTK_EDITABLE(editor->ui.totp_entry), totp);
            _dropdown_set_protocol(GTK_DROP_DOWN(editor->ui.protocol_dropdown), protocol);
            gtk_check_button_set_active(GTK_CHECK_BUTTON(editor->ui.no_dtls_check),
                                        (no_dtls && g_strcmp0(no_dtls, "yes") == 0));
        }
    }

    return NM_VPN_EDITOR(editor);
}

static void
ms_sso_vpn_editor_plugin_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    switch (prop_id) {
    case PROP_NAME:
        g_value_set_string(value, "MS SSO OpenConnect");
        break;
    case PROP_DESCRIPTION:
        g_value_set_string(value, "OpenConnect VPN with Microsoft SSO (Playwright)");
        break;
    case PROP_SERVICE:
        g_value_set_string(value, VPN_SERVICE_TYPE);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
ms_sso_vpn_editor_plugin_class_init(MsSsoVpnEditorPluginClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    object_class->get_property = ms_sso_vpn_editor_plugin_get_property;

    properties[PROP_NAME] =
        g_param_spec_string(NM_VPN_EDITOR_PLUGIN_NAME, NM_VPN_EDITOR_PLUGIN_NAME, NULL, NULL, G_PARAM_READABLE);
    properties[PROP_DESCRIPTION] = g_param_spec_string(NM_VPN_EDITOR_PLUGIN_DESCRIPTION,
                                                       NM_VPN_EDITOR_PLUGIN_DESCRIPTION,
                                                       NULL,
                                                       NULL,
                                                       G_PARAM_READABLE);
    properties[PROP_SERVICE] = g_param_spec_string(NM_VPN_EDITOR_PLUGIN_SERVICE,
                                                   NM_VPN_EDITOR_PLUGIN_SERVICE,
                                                   NULL,
                                                   NULL,
                                                   G_PARAM_READABLE);

    g_object_class_install_properties(object_class, PROP_LAST, properties);
}

static void
ms_sso_vpn_editor_plugin_init(MsSsoVpnEditorPlugin *self)
{
    (void) self;
}

static NMVpnEditor *
ms_sso_vpn_editor_plugin_get_editor(NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
    (void) plugin;
    (void) error;
    return ms_sso_vpn_editor_new_from_connection(connection);
}

static NMVpnEditorPluginCapability
ms_sso_vpn_editor_plugin_get_capabilities(NMVpnEditorPlugin *plugin)
{
    (void) plugin;
    return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static void
ms_sso_vpn_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface)
{
    iface->get_editor = ms_sso_vpn_editor_plugin_get_editor;
    iface->get_capabilities = ms_sso_vpn_editor_plugin_get_capabilities;
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_factory_ms_sso_openconnect(GError **error)
{
    (void) error;
    return NM_VPN_EDITOR_PLUGIN(g_object_new(ms_sso_vpn_editor_plugin_get_type(), NULL));
}
