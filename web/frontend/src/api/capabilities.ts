import { launcherFetch } from "@/api/http"

export interface CapabilityEntry {
  artifact_version_digest: string
  admission_revision: number
  revocation_generation: number
  projected_state: string
}

export interface CapabilityInventory {
  snapshot_revision: number
  source_generation: number
  policy_revision: number
  created_at_unix: number
  expires_at_unix: number
  entries: CapabilityEntry[]
}

export async function getCapabilities(): Promise<CapabilityInventory> {
  const response = await launcherFetch("/api/capabilities")
  if (!response.ok) throw new Error(await response.text())
  return response.json() as Promise<CapabilityInventory>
}
