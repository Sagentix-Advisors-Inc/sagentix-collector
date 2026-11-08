// Fixtures for the kandji source, shared by test/kandji.test.ts and the end-to-end run (test/e2e.test.ts).
import { PAGE, kandji, kandjiFromEnv } from "../../../src/sources/kandji.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Route, type Routes } from "../../rest_fakes.ts";

export const BASE = "https://acme.api.kandji.io/api";
export const DEV = "/v1/devices";
export const ok = (b: unknown) => res(200, b);
export const q = (url: string) => new URL(`https://x${url}`).searchParams;

export interface Over { version?: string; checkin?: string; mdm?: boolean; filevault?: boolean; firewall?: boolean; gatekeeper?: boolean; sip?: boolean;
  item?: string; param?: string; erase?: number }

export function mac(id: string, serial: string, o: Over = {}): Record<string, unknown> {
  return {
    device_id: id, device_name: "Anna's MacBook Air", model: "MacBook Air (M2, 2022)", serial_number: serial, platform: "Mac",
    os_version: o.version ?? "15.1", last_check_in: o.checkin ?? daysAgo(1),
    user: { email: "anna@acme.example", name: "Anna Chao", id: "u-1", is_archived: false },
    blueprint_id: "bp-1", blueprint_name: "All Staff", mdm_enabled: o.mdm ?? true, agent_installed: true, is_missing: false, is_removed: false,
  };
}
export const prismRow = (id: string, serial: string, fields: Record<string, unknown>) => ({
  device_id: id, device__name: "Anna's MacBook Air", device__family: "Mac", device__user_name: "Anna Chao", device__user_email: "anna@acme.example",
  serial_number: serial, ...fields,
});
export const status = (o: Over = {}) => ok({
  device_id: "x",
  library_items: [
    { id: 1, item_id: "li-1", name: "FileVault", status: o.item ?? "PASS", type: "filevault", last_audit_log: "user achao", log: "user achao" },
    { id: 2, item_id: "li-2", name: "Zoom", status: "PENDING", type: "custom-app", last_audit_log: null, log: "" },
  ],
  parameters: [{ status: o.param ?? "PASS", item_id: "p-1", name: "Disable the \"root\" user", category: "User Accounts & Authentication", subcategory: "User Accounts" }],
});

/** Get Device Commands: one routine command, and an EraseDevice with the given MDM status code when asked. */
export const commands = (o: Over = {}) => ok({ device_id: "x", commands: { count: 2, next: null, previous: null, results: [
  { uuid: "c-1", error_chain: [], command_type: "DeviceInformation", request_type: "DeviceInformation", status: 3, date_requested: daysAgo(1), date_completed: daysAgo(1), user: null },
  ...(o.erase !== undefined ? [{ uuid: "c-2", error_chain: [], command_type: "EraseDevice", request_type: "EraseDevice", status: o.erase, attempts: 1,
    date_requested: daysAgo(15), date_completed: o.erase === 3 ? daysAgo(15) : null, user: { email: "it@acme.example", name: "IT Admin" } }] : []),
] } });

/** Routes for a fleet of Macs: the device list (filtered by filevault_enabled when asked), Prism categories, statuses. */
export function fleet(macs: { id: string; serial: string; o?: Over }[]): Routes {
  const list: Route = (url) => {
    const fv = q(url).get("filevault_enabled"), off = Number(q(url).get("offset"));
    const rows = macs.filter((m) => fv === null || String(m.o?.filevault ?? true) === fv).map((m) => mac(m.id, m.serial, m.o));
    return ok(rows.slice(off, off + PAGE));
  };
  const prism = (field: keyof Over, key: string): Route => () => ok({ offset: null, limit: PAGE, total: macs.length, cursor: null,
    data: macs.map((m) => prismRow(m.id, m.serial, { [key]: m.o?.[field] ?? true })) });
  const r: Routes = {
    [DEV]: list,
    "/v1/prism/application_firewall": prism("firewall", "status"),
    "/v1/prism/gatekeeper_and_xprotect": prism("gatekeeper", "gatekeeper_status"),
    "/v1/prism/startup_settings": prism("sip", "sip"),
  };
  for (const m of macs) { r[`${DEV}/${m.id}/status`] = status(m.o); r[`${DEV}/${m.id}/commands`] = commands(m.o); }
  return r;
}
export const strong = () => fleet([{ id: "d-1", serial: "C02TEST0001" }, { id: "d-2", serial: "C02TEST0002", o: { erase: 3 } }]);
export const weak = (o: Over) => fleet([{ id: "d-1", serial: "C02TEST0001" }, { id: "d-2", serial: "C02TEST0002", o }]);

export const C: Contract = {
  source: kandji, clientKey: "kandji", base: BASE, prefix: "kandji", strong,
  opts: { "kandji-min-os": "14.0" },
  env: { KANDJI_API_URL: "https://acme.api.kandji.io", KANDJI_API_TOKEN: "x" },
  rateLimited: { path: DEV, check: "managed" },
  fails: {
    filevault: weak({ filevault: false }),
    os_minimum: weak({ version: "13.6.9" }),
    last_checkin: weak({ checkin: daysAgo(30) }),
    managed: weak({ mdm: false }),
    library_items: weak({ item: "ERROR" }),
    parameters: weak({ param: "WARNING" }),
    firewall: weak({ firewall: false }),
    gatekeeper: weak({ gatekeeper: false }),
    sip: weak({ sip: false }),
    device_wipe_recorded: weak({ erase: 4 }),
  },
};
