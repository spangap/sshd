/**
 * sshd_lcd.cpp — on-device LCD Settings pane for the SSH server.
 *
 * A single enable/disable switch bound to s.sshd.enabled (the same key the CLI
 * `sshd enable`/`disable` and the web panel toggle, and which sshdTask
 * subscribes to — so flipping it here starts/stops the listener immediately).
 *
 * Gated on CONFIG_SPANGAP_LCD: when spangap-lcd is excluded from the build
 * (`--no-lcd` / not in the dep graph) this whole unit compiles to nothing and
 * sshdInit()'s call to sshdLcdRegister() is #if'd out too. Registration only
 * populates spangap-lcd's in-RAM settings tree (safe from any init task, before
 * lcdInit()), so sshdInit() calls it directly — no main.cpp wiring.
 */
#include "sdkconfig.h"

#if CONFIG_SPANGAP_LCD

#include "lcd.h"
#include "sshd.h"

namespace {

void sshdSettingsPane(void* arg) {
    lv_obj_t* p = static_cast<lv_obj_t*>(arg);
    lcdSettingSection(p, "SSH server");
    lcdSettingSwitch(p, "Enabled", "s.sshd.enabled");
}

}  // namespace

void sshdLcdRegister() {
    lcdRegisterSettings("Net/SSH", "SSH", sshdSettingsPane);
}

#endif /* CONFIG_SPANGAP_LCD */
