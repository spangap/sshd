<template>
  <div class="q-gutter-y-md">
    <SettingToggle label="Enable" k="s.sshd.enabled" />

    <q-separator dark />
    <PanelHeading>Authorized keys</PanelHeading>

    <div v-if="keys.length === 0" class="text-caption" style="opacity:0.5">
      No authorized keys — add an ssh-ed25519 public key to allow logins.
    </div>

    <div
      v-for="(k, idx) in keys"
      :key="idx"
      class="key-item"
      :class="{ selected: selectedIdx === idx }"
      @click="selectedIdx = idx"
    >
      <div class="key-label">{{ keyDisplay(k) }}</div>
    </div>

    <div class="row q-gutter-x-sm q-mt-xs">
      <q-btn dense no-caps label="+" class="key-btn" @click="openAdd" />
      <q-btn dense no-caps class="key-btn" :disable="selectedIdx < 0" @click="removeKey"><IconTrash /></q-btn>
    </div>

    <q-dialog v-model="showAdd" persistent>
      <q-card dark class="q-pa-md" style="min-width:420px">
        <q-card-section class="text-subtitle1 text-weight-medium">Add SSH key</q-card-section>
        <q-card-section class="q-gutter-y-sm">
          <q-input
            v-model="newKey"
            type="textarea"
            rows="3"
            autogrow
            label="ssh-ed25519 AAAA… optional-comment"
            dense
            outlined
            autofocus
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
          />
          <div v-if="newKey.trim() && !verdict.ok" class="text-caption text-negative">
            {{ verdict.why }}
          </div>
          <div v-else-if="verdict.ok" class="text-caption text-positive">
            Looks good{{ verdict.comment ? ` — comment: ${verdict.comment}` : '' }}
          </div>
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" @click="showAdd = false" />
          <q-btn flat label="Add" color="primary" :disable="!verdict.ok" @click="confirmAdd" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useDeviceStore } from 'spangap-browser/stores/device'
import SettingToggle from 'spangap-browser/components/SettingToggle.vue'
import PanelHeading from 'spangap-browser/components/PanelHeading.vue'
import IconTrash from 'spangap-browser/components/IconTrash.vue'

const device = useDeviceStore()

// Stored as an array of full openssh lines: "ssh-ed25519 <base64> [comment]".
// The trailing comment is preserved verbatim (the device keeps the whole line;
// auth only compares the base64 blob).
const keys = computed<string[]>(() => {
  const arr = device.get('s.sshd.authorized_keys')
  return Array.isArray(arr) ? arr.map((k: unknown) => String(k ?? '')) : []
})

const selectedIdx = ref(-1)
watch(
  keys,
  (n) => {
    if (selectedIdx.value >= n.length) selectedIdx.value = n.length - 1
  },
  { immediate: true },
)

function keyDisplay(line: string): string {
  const parts = line.trim().split(/\s+/)
  const type = parts[0] || '?'
  const blob = parts[1] || ''
  const comment = parts.slice(2).join(' ')
  const tail = blob.length > 12 ? '…' + blob.slice(-12) : blob
  return `${type} ${tail}${comment ? '  ' + comment : ''}`
}

// The firmware accepts ssh-ed25519 only (publickey auth is ed25519-only), so the
// panel "likes" exactly those — mirror that and explain why anything else is
// rejected before it can be saved.
interface Verdict {
  ok: boolean
  why?: string
  comment?: string
}
function validate(raw: string): Verdict {
  const line = raw.trim()
  if (!line) return { ok: false, why: 'Empty.' }
  const parts = line.split(/\s+/)
  if (parts.length < 2) return { ok: false, why: 'Expected: ssh-ed25519 <base64> [comment]' }
  const [type, blob, ...rest] = parts
  if (type !== 'ssh-ed25519') {
    return { ok: false, why: `Only ssh-ed25519 keys are accepted (got "${type}").` }
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) {
    return { ok: false, why: 'Key body is not valid base64.' }
  }
  // ed25519 blob = string("ssh-ed25519") || string(pub32) = 51 bytes ≈ 68 b64 chars.
  if (blob.length < 64) return { ok: false, why: 'Key body looks too short for ed25519.' }
  return { ok: true, comment: rest.join(' ') || undefined }
}
const verdict = computed(() => validate(newKey.value))

function writeKeys(arr: string[]) {
  // Plain array → full replacement on the device (shrinking deletes entries).
  device.sendJson({ s: { sshd: { authorized_keys: arr } } })
  device.save()
}

const showAdd = ref(false)
const newKey = ref('')
function openAdd() {
  newKey.value = ''
  showAdd.value = true
}
function confirmAdd() {
  if (!validate(newKey.value).ok) return
  const arr = [...keys.value, newKey.value.trim()]
  writeKeys(arr)
  selectedIdx.value = arr.length - 1
  showAdd.value = false
}
function removeKey() {
  if (selectedIdx.value < 0) return
  const arr = [...keys.value]
  arr.splice(selectedIdx.value, 1)
  writeKeys(arr)
  if (selectedIdx.value >= arr.length) selectedIdx.value = arr.length - 1
}
</script>

<style scoped>
.key-item {
  padding: 8px 10px;
  border-radius: 4px;
  cursor: pointer;
  color: rgba(255, 255, 255, 0.7);
  font-family: monospace;
  font-size: 12px;
  background: rgba(255, 255, 255, 0.03);
  word-break: break-all;
}
.key-item:hover {
  background: rgba(255, 255, 255, 0.06);
}
.key-item.selected {
  background: rgba(255, 255, 255, 0.1);
  outline: 1px solid rgba(255, 255, 255, 0.2);
}
.key-label {
  flex: 1;
}
.key-btn {
  font-size: 16px !important;
  min-width: 32px !important;
  padding: 2px 10px !important;
  background: rgba(255, 255, 255, 0.08) !important;
  color: rgba(255, 255, 255, 0.7) !important;
}
.key-btn:hover {
  background: rgba(255, 255, 255, 0.16) !important;
}
</style>
