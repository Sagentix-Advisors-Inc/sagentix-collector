// Fixtures for the jamf source, shared by test/jamf.test.ts and the end-to-end run (test/e2e.test.ts).
import { PAGE, inventoryPath, jamf, jamfFromEnv } from "../../../src/sources/jamf.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const BASE = "https://acme.jamfcloud.com/api";
export const INV = "/v4/computers-inventory";
export const CMD = "/v2/mdm/commands";
export const ok = (b: unknown) => res(200, b);

export function computer(id: string, serial: string, over: { state?: string; version?: string; report?: string; managed?: boolean } = {}): Record<string, unknown> {
  return {
    id, udid: `UDID-${id}`,
    general: { name: "Anna's MacBook Air", managementId: `mgmt-${id}`, reportDate: over.report ?? daysAgo(1), lastContact: daysAgo(1), remoteManagement: { managed: over.managed ?? true },
      lastLoggedInUsernameBinary: "achao" },
    diskEncryption: { fileVault2Enabled: true, fileVault2EnabledUserNames: ["achao"],
      bootPartitionEncryptionDetails: { partitionName: "Macintosh HD (Boot Partition)", partitionFileVault2State: over.state ?? "ENCRYPTED", partitionFileVault2Percent: 100 } },
    operatingSystem: { name: "macOS", version: over.version ?? "15.1", build: "24B83" },
    hardware: { serialNumber: serial, model: "MacBook Air (M2, 2022)" },
  };
}
export const inv = (results: unknown[], total = results.length) => ok({ totalCount: total, results });
/** One erase per row; the username and device name are there to prove they never reach a result. */
export const erase = (mgmt: string, state: string, sent: string) => ({ uuid: `u-${mgmt}`, dateSent: sent, dateCompleted: state === "ACKNOWLEDGED" ? sent : null,
  client: { managementId: mgmt, clientType: "COMPUTER" }, commandState: state, commandType: "ERASE_DEVICE", username: "it.admin", deviceName: "Anna's MacBook Air" });
export const cmds = (rows: unknown[]) => ok({ totalCount: rows.length, results: rows });
export const strong = (): Routes => ({ [INV]: inv([computer("1", "C02TEST0001"), computer("2", "C02TEST0002")]),
  [CMD]: cmds([erase("mgmt-2", "ACKNOWLEDGED", daysAgo(10)), erase("mgmt-gone", "ACKNOWLEDGED", daysAgo(60))]) });
export const withComputer = (over: Parameters<typeof computer>[2]): Routes => ({ [INV]: inv([computer("1", "C02TEST0001"), computer("2", "C02TEST0002", over)]) });

export const C: Contract = {
  source: jamf, clientKey: "jamf", base: BASE, prefix: "jamf", strong,
  opts: { "jamf-min-os": "14.0" },
  env: { JAMF_URL: "https://acme.jamfcloud.com", JAMF_CLIENT_ID: "client-1", JAMF_CLIENT_SECRET: "x" },
  rateLimited: { path: INV, check: "filevault" },
  fails: {
    filevault: withComputer({ state: "UNENCRYPTED" }),
    os_minimum: withComputer({ version: "13.6.9" }),
    last_inventory: withComputer({ report: daysAgo(30) }),
    managed: withComputer({ managed: false }),
    device_wipe_recorded: { [CMD]: cmds([erase("mgmt-3", "ERROR", daysAgo(2))]) },
  },
};
