/*
 * NetworkManager VPN Plugin Editor for MS SSO OpenConnect
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NM_MS_SSO_EDITOR_H__
#define __NM_MS_SSO_EDITOR_H__

#include <gtk/gtk.h>
#include <NetworkManager.h>

#define MS_SSO_TYPE_EDITOR            (ms_sso_editor_get_type())
#define MS_SSO_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MS_SSO_TYPE_EDITOR, MsSsoEditor))
#define MS_SSO_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MS_SSO_TYPE_EDITOR))
#define MS_SSO_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), MS_SSO_TYPE_EDITOR, MsSsoEditorClass))
#define MS_SSO_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), MS_SSO_TYPE_EDITOR))

typedef struct _MsSsoEditor        MsSsoEditor;
typedef struct _MsSsoEditorClass   MsSsoEditorClass;
typedef struct _MsSsoEditorPrivate MsSsoEditorPrivate;

struct _MsSsoEditor {
    GObject parent;
    MsSsoEditorPrivate *priv;
};

struct _MsSsoEditorClass {
    GObjectClass parent_class;
};

GType ms_sso_editor_get_type(void);

NMVpnEditor *ms_sso_editor_new(NMConnection *connection, GError **error);

/* Plugin factory */
#define MS_SSO_TYPE_EDITOR_PLUGIN            (ms_sso_editor_plugin_get_type())
#define MS_SSO_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MS_SSO_TYPE_EDITOR_PLUGIN, MsSsoEditorPlugin))

typedef struct _MsSsoEditorPlugin        MsSsoEditorPlugin;
typedef struct _MsSsoEditorPluginClass   MsSsoEditorPluginClass;

struct _MsSsoEditorPlugin {
    GObject parent;
};

struct _MsSsoEditorPluginClass {
    GObjectClass parent_class;
};

GType ms_sso_editor_plugin_get_type(void);

/* Plugin entry point */
G_MODULE_EXPORT NMVpnEditorPlugin *nm_vpn_editor_plugin_factory(GError **error);

#endif /* __NM_MS_SSO_EDITOR_H__ */
