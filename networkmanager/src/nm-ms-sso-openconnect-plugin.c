#define _GNU_SOURCE 1

#include <NetworkManager.h>

#include <dlfcn.h>
#include <gmodule.h>

typedef NMVpnEditorPlugin *(*EditorFactoryFunc)(GError **error);

static char *
_self_dir(void)
{
    Dl_info info;
    if (!dladdr((void *) _self_dir, &info) || !info.dli_fname)
        return NULL;
    return g_path_get_dirname(info.dli_fname);
}

static NMVpnEditorPlugin *
_try_load(const char *module_path, const char *symbol, GError **error)
{
    g_clear_error(error);

    GModule *module = g_module_open(module_path, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
    if (!module)
        return NULL;

    EditorFactoryFunc factory = NULL;
    if (!g_module_symbol(module, symbol, (gpointer *) &factory) || !factory) {
        g_module_close(module);
        return NULL;
    }

    NMVpnEditorPlugin *plugin = factory(error);
    if (!plugin) {
        g_module_close(module);
        return NULL;
    }

    /* Keep the module resident for the lifetime of the editor plugin. */
    g_module_make_resident(module);
    return plugin;
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory(GError **error)
{
    const char *symbol = "nm_vpn_editor_factory_ms_sso_openconnect";

    g_autofree char *dir = _self_dir();
    if (dir) {
        g_autofree char *gtk4 =
            g_build_filename(dir, "libnm-gtk4-vpn-plugin-ms-sso-openconnect-editor.so", NULL);
        NMVpnEditorPlugin *plugin = _try_load(gtk4, symbol, error);
        if (plugin)
            return plugin;

        g_autofree char *gtk3 =
            g_build_filename(dir, "libnm-vpn-plugin-ms-sso-openconnect-editor.so", NULL);
        plugin = _try_load(gtk3, symbol, error);
        if (plugin)
            return plugin;
    }

    /* Fallback to dlopen search path. */
    NMVpnEditorPlugin *plugin =
        _try_load("libnm-gtk4-vpn-plugin-ms-sso-openconnect-editor.so", symbol, error);
    if (plugin)
        return plugin;
    return _try_load("libnm-vpn-plugin-ms-sso-openconnect-editor.so", symbol, error);
}
