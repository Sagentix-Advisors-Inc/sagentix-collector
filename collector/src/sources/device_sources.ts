// Device sources: Fleet (fleetd/osquery, open-source core), Microsoft Intune, Jamf Pro, Iru Endpoint Management (formerly
// Kandji), Microsoft Defender for Endpoint, and the Mac or Windows PC the collector runs on. Listed in index.ts as one entry.
import type { Source } from "../types.ts";
import { defender_endpoint } from "./defender_endpoint.ts";
import { fleet } from "./fleet.ts";
import { intune } from "./intune.ts";
import { jamf } from "./jamf.ts";
import { kandji } from "./kandji.ts";
import { macos } from "./macos.ts";
import { windows } from "./windows.ts";

export const DEVICE_SOURCES: readonly Source[] = [fleet, intune, jamf, kandji, defender_endpoint, macos, windows];
