// Fixtures for the azure source, shared by test/azure.test.ts and the end-to-end run (test/e2e.test.ts).
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { azure } from "../../../src/sources/azure.ts";
import { API, ARM, fetchAzure, tokenFromEnv, type AzureTransport } from "../../../src/sources/azure/api.ts";
import { adminPortsIn, openAdminRules } from "../../../src/sources/azure/checks.ts";
import type { HttpReply } from "../../../src/sources/shared-cloud.ts";
import type { OptionValue, Result } from "../../../src/types.ts";

export const NOW = new Date("2026-10-15T12:00:00Z");
export const SUB = "11111111-2222-3333-4444-555555555555";
export const S = `/subscriptions/${SUB}`;
export const RG = `${S}/resourceGroups/prod`;

export type Route = unknown | ((url: string) => HttpReply);
export const json = (status: number, body: unknown, headers: Record<string, string> = {}): HttpReply => ({ status, headers, body: JSON.stringify(body) });
export const list = (value: unknown[], nextLink?: string) => ({ value, ...(nextLink ? { nextLink } : {}) });
export const armErr = (status: number, message: string) => json(status, { error: { code: status === 403 ? "AuthorizationFailed" : "Error", message } });

export const rule = (name: string, props: Record<string, unknown>) => ({ name, properties: { direction: "Inbound", access: "Allow", protocol: "Tcp", sourceAddressPrefix: "10.0.0.0/8", destinationPortRange: "443", priority: 100, ...props } });

/** Resources - List answering `$filter=resourceType eq '<type>'` from a list of the types the subscription holds. */
export const resources = (types: string[]) => (url: string): HttpReply => {
  const f = decodeURIComponent(/[?&]\$filter=([^&]*)/.exec(url)?.[1] ?? "");
  const want = /resourceType eq '([^']+)'/.exec(f)?.[1];
  return json(200, list(types.filter((t) => t === want).map((t, i) => ({ id: `${RG}/providers/${t}/r${i}`, type: t }))));
};
export const VM = `${RG}/providers/Microsoft.Compute/virtualMachines/vm1`;
export const patchView = (summary: Record<string, unknown> | undefined, power = "PowerState/running") => ({
  statuses: [{ code: "ProvisioningState/succeeded" }, { code: power }],
  ...(summary ? { patchStatus: { availablePatchSummary: summary } } : {}),
});
export const goodPatch = { status: "Succeeded", criticalAndSecurityPatchCount: 0, otherPatchCount: 2, lastModifiedTime: "2026-10-14T03:00:00Z" };

/** A well-configured subscription: every check passes. Keyed by path without the query. */
export function strong(): Record<string, Route> {
  return {
    "/subscriptions": list([{ subscriptionId: SUB, state: "Enabled" }]),
    [`${S}/providers/Microsoft.Security/pricings`]: list([
      { name: "VirtualMachines", properties: { pricingTier: "Standard" } },
      { name: "KubernetesService", properties: { pricingTier: "Free", deprecated: true } },
    ]),
    [`${S}/providers/Microsoft.Security/secureScores`]: list([{ name: "ascScore", properties: { score: { current: 30, max: 40, percentage: 0.75 } } }]),
    [`${S}/providers/Microsoft.Insights/diagnosticSettings`]: list([{ name: "to-law", properties: { workspaceId: `${RG}/providers/Microsoft.OperationalInsights/workspaces/law`, logs: [{ category: "Administrative", enabled: true }, { category: "Security", enabled: true }] } }]),
    [`${S}/providers/Microsoft.KeyVault/vaults`]: list([{ id: `${RG}/providers/Microsoft.KeyVault/vaults/kv1`, name: "kv1", properties: { enableSoftDelete: true, enablePurgeProtection: true } }]),
    [`${S}/providers/Microsoft.Storage/storageAccounts`]: list([{ id: `${RG}/providers/Microsoft.Storage/storageAccounts/st1`, name: "st1", properties: { supportsHttpsTrafficOnly: true, allowBlobPublicAccess: false, minimumTlsVersion: "TLS1_2" } }]),
    [`${S}/providers/Microsoft.Sql/servers`]: list([{ id: `${RG}/providers/Microsoft.Sql/servers/sql1`, name: "sql1" }]),
    [`${RG}/providers/Microsoft.Sql/servers/sql1/databases`]: list([
      { id: `${RG}/providers/Microsoft.Sql/servers/sql1/databases/master`, name: "master" },
      { id: `${RG}/providers/Microsoft.Sql/servers/sql1/databases/app`, name: "app" },
    ]),
    [`${RG}/providers/Microsoft.Sql/servers/sql1/databases/app/transparentDataEncryption/current`]: { name: "current", properties: { state: "Enabled" } },
    [`${S}/providers/Microsoft.Network/networkSecurityGroups`]: list([{ id: `${RG}/providers/Microsoft.Network/networkSecurityGroups/web`, name: "web", properties: { securityRules: [rule("https", { sourceAddressPrefix: "Internet" }), rule("ssh-vpn", { destinationPortRange: "22" })] } }]),
    [`${S}/providers/Microsoft.Authorization/policyAssignments`]: list([{ name: "asb", properties: { enforcementMode: "Default" } }]),
    [`${S}/providers/Microsoft.Compute/disks`]: list([{ id: `${RG}/providers/Microsoft.Compute/disks/os1`, name: "os1", properties: { encryption: { type: "EncryptionAtRestWithPlatformKey" } } }]),
    [`${S}/providers/Microsoft.RecoveryServices/vaults`]: list([{ id: `${RG}/providers/Microsoft.RecoveryServices/vaults/rsv`, name: "rsv" }]),
    [`${RG}/providers/Microsoft.RecoveryServices/vaults/rsv/backupProtectedItems`]: list([{ name: "VM;iaasvmcontainerv2;prod;vm1" }]),
    [`${RG}/providers/Microsoft.RecoveryServices/vaults/rsv/backupJobs`]: list([
      { name: "j1", properties: { operation: "Backup", status: "Failed", entityFriendlyName: "vm1", startTime: "2026-10-13T01:00:00Z" } },
      { name: "j2", properties: { operation: "Backup", status: "Completed", entityFriendlyName: "vm1", startTime: "2026-10-14T01:00:00Z" } },
      { name: "j3", properties: { operation: "Restore", status: "Completed", entityFriendlyName: "vm1", startTime: "2026-06-01T01:00:00Z" } }]),
    [`${S}/providers/Microsoft.OperationalInsights/workspaces`]: list([{ id: `${RG}/providers/Microsoft.OperationalInsights/workspaces/law`, name: "law", properties: { retentionInDays: 730 } }]),
    [`${S}/resources`]: resources(["Microsoft.Compute/virtualMachines"]),
    [`${RG}/providers/Microsoft.Sql/servers/sql1/firewallRules`]: list([
      { name: "AllowAllWindowsAzureIps", properties: { startIpAddress: "0.0.0.0", endIpAddress: "0.0.0.0" } },
      { name: "office", properties: { startIpAddress: "203.0.113.0", endIpAddress: "203.0.113.255" } },
    ]),
    [`${S}/providers/Microsoft.Compute/virtualMachines`]: list([{ id: VM, name: "vm1", properties: { osProfile: { linuxConfiguration: { patchSettings: { patchMode: "AutomaticByPlatform", assessmentMode: "AutomaticByPlatform" } } } } }]),
    [`${VM}/instanceView`]: patchView(goodPatch),
  };
}

export function fake(over: Record<string, Route> = {}, calls: string[] = [], sleeps: number[] = []): AzureTransport {
  const routes = { ...strong(), ...over };
  return {
    async get(url: string) {
      calls.push(url);
      assert.ok(url.startsWith(`${ARM}/`), url);
      const path = url.slice(ARM.length).split("?")[0];
      const r = routes[path];
      if (r === undefined) return armErr(404, `no fake for ${path}`);
      if (typeof r === "function") return (r as (u: string) => HttpReply)(url);
      if (typeof r === "object" && r !== null && "status" in r && "body" in r) return r as HttpReply;
      return json(200, r);
    },
    sleep: async (ms) => { sleeps.push(ms); },
  };
}
