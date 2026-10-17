// Device sources: Fleet (fleetd/osquery, open-source core), Microsoft Intune and Jamf Pro.
// Listed in index.ts as one entry.
import type { Source } from "../types.ts";
import { fleet } from "./fleet.ts";
import { intune } from "./intune.ts";
import { jamf } from "./jamf.ts";

export const DEVICE_SOURCES: readonly Source[] = [fleet, intune, jamf];
