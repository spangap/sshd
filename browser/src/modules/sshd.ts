import { useMenuStore } from 'spangap-browser/stores/menu'
import SshdPanel from '../panels/SshdPanel.vue'

export function registerSshd() {
  useMenuStore().register('settings/network/ssh', 'SSH', { type: 'panel', component: SshdPanel })
}
