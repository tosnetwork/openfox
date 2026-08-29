import { useQuery } from "@tanstack/react-query"

import { getCapabilities } from "@/api/capabilities"
import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export function CapabilitiesPage() {
  const inventory = useQuery({ queryKey: ["capabilities"], queryFn: getCapabilities })
  return <div className="space-y-6 p-6">
    <PageHeader title="Trusted capabilities" />
    <p className="text-sm text-muted-foreground">Evidence-backed local Inventory. Discovery and quarantine do not grant execution authority.</p>
    {inventory.error ? <Card><CardContent className="pt-6 text-sm text-destructive">{inventory.error.message}</CardContent></Card> : null}
    {(inventory.data?.entries ?? []).map((entry) => <Card key={entry.artifact_version_digest}>
      <CardHeader><CardTitle className="flex items-center justify-between text-base"><span className="break-all font-mono">{entry.artifact_version_digest}</span><Badge variant="outline">{entry.projected_state}</Badge></CardTitle></CardHeader>
      <CardContent className="text-sm text-muted-foreground">Admission revision {entry.admission_revision}; revocation generation {entry.revocation_generation}</CardContent>
    </Card>)}
    {inventory.data?.entries.length === 0 ? <Card><CardContent className="pt-6 text-sm text-muted-foreground">No evidence-backed capabilities. Existing Skills remain unverified legacy until imported and admitted.</CardContent></Card> : null}
  </div>
}
