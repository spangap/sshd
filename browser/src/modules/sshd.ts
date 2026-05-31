import { useMenuStore } from 'spangap-browser/stores/menu'
import SshdPanel from '../panels/SshdPanel.vue'

export function registerSshd() {
  useMenuStore().register('settings', 'Settings', [
    { id: 'network', label: 'Network', type: 'submenu',
      children: [
        { id: 'network.ssh', label: 'SSH', type: 'panel',
          component: SshdPanel },
      ],
    },
  ])
}
