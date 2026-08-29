import { createFileRoute } from "@tanstack/react-router"
import { CapabilitiesPage } from "@/components/agent/capabilities/capabilities-page"
export const Route = createFileRoute("/agent/capabilities")({ component: CapabilitiesPage })
