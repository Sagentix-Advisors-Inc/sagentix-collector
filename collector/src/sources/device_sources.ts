// Device sources: Fleet (fleetd/osquery, open-source core), Microsoft Intune, Jamf Pro, Iru Endpoint Management (formerly
// Kandji), Microsoft Defender for Endpoint, Omnissa Workspace ONE UEM, Microsoft Configuration Manager, Google endpoint
// management, Ivanti Neurons for MDM, NinjaOne, ManageEngine Endpoint Central (cloud), and the Mac or Windows PC the
// collector runs on. Listed in index.ts as one entry.
import type { Source } from "../types.ts";
import { configmgr } from "./configmgr.ts";
import { defender_endpoint } from "./defender_endpoint.ts";
import { endpoint_central } from "./endpoint_central.ts";
import { fleet } from "./fleet.ts";
import { googleEndpoints } from "./google_endpoints.ts";
import { intune } from "./intune.ts";
import { ivanti_mdm } from "./ivanti_mdm.ts";
import { jamf } from "./jamf.ts";
import { kandji } from "./kandji.ts";
import { macos } from "./macos.ts";
import { ninjaone } from "./ninjaone.ts";
import { windows } from "./windows.ts";
import { workspaceOne } from "./workspace_one.ts";

export const DEVICE_SOURCES: readonly Source[] = [
  fleet, intune, jamf, kandji, defender_endpoint,
  workspaceOne, configmgr, googleEndpoints, ivanti_mdm, ninjaone, endpoint_central,
  macos, windows,
];
