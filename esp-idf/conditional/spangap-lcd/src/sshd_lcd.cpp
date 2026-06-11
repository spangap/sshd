/**
 * sshd_lcd.cpp — on-device LCD Settings pane for the SSH server.
 *
 * A single enable/disable switch bound to s.sshd.enabled (the same key the CLI
 * `sshd enable`/`disable` and the web panel toggle, and which sshdTask
 * subscribes to — so flipping it here starts/stops the listener immediately).
 *
 * This whole file lives under conditional/spangap-lcd/, compiled only when the
 * spangap-lcd straddle is staged, so no #if is needed. It registers via the
 * when:-gated init: hook (spangap/spangap-lcd) — sshdLcdRegister, plain C++
 * linkage to match the generated dispatcher's forward decl. Registration only
 * populates spangap-lcd's in-RAM settings tree (safe from any init task, before
 * lcdInit()), so it runs in the straddle init band rather than from sshdInit().
 */
#include "lcd.h"
#include "sshd.h"

namespace {

void sshdSettingsPane(void* arg) {
    lv_obj_t* p = static_cast<lv_obj_t*>(arg);
    lcdSettingSection(p, "SSH server");
    lcdSettingSwitch(p, "Enabled", "s.sshd.enabled");
}

}  // namespace

/* Register the SSH server's on-device Settings pane — a when:-gated init: hook
 * (spangap/spangap-lcd). Plain C++ linkage to match the generated dispatcher's
 * forward decl. */
void sshdLcdRegister(void) {
    lcdRegisterSettings("Internet/SSH", "SSH", sshdSettingsPane);
}
