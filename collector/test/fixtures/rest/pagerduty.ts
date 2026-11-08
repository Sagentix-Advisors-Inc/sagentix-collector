// Fixtures for the pagerduty source, shared by test/pagerduty.test.ts and the end-to-end run (test/e2e.test.ts).
import { PAGERDUTY_BASE, pagerduty, pagerdutyFromEnv } from "../../../src/sources/pagerduty.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const ok = (b: unknown) => res(200, b);
export const page = (key: string, items: unknown[], more = false, offset = 0) => ok({ [key]: items, limit: 100, offset, more, total: null });

export const policy = (id: string, levels: { id: string; type: string }[][]) => ({ id, type: "escalation_policy", num_loops: 0,
  escalation_rules: levels.map((targets, i) => ({ id: `R${id}${i}`, escalation_delay_in_minutes: 30, targets })) });

export function strong(): Routes {
  return {
    "/incidents": page("incidents", [
      { id: "PINC1", incident_number: 101, status: "resolved", urgency: "high", created_at: "2026-09-01T00:00:00Z", resolved_at: "2026-09-01T03:00:00Z" },
      { id: "PINC2", incident_number: 102, status: "resolved", urgency: "high", created_at: "2026-09-20T00:00:00Z", resolved_at: "2026-09-20T01:00:00Z" },
    ]),
    "/incidents/PINC1/notes": ok({ notes: [{ id: "n1", content: "Postmortem: https://wiki.example/pm-101 (by Alice Smith)", created_at: "2026-09-02T00:00:00Z" }] }),
    "/incidents/PINC2/notes": ok({ notes: [{ id: "n2", content: "Retrospective scheduled", created_at: "2026-09-21T00:00:00Z" }] }),
    "/services": page("services", [
      { id: "PSVC1", name: "api", status: "active", escalation_policy: { id: "PEP1", type: "escalation_policy_reference" } },
      { id: "PSVC2", name: "web", status: "warning", escalation_policy: { id: "PEP2", type: "escalation_policy_reference" } },
      { id: "PSVC3", name: "old", status: "disabled", escalation_policy: { id: "PEP3", type: "escalation_policy_reference" } },
    ]),
    "/escalation_policies": page("escalation_policies", [
      policy("PEP1", [[{ id: "PSCH1", type: "schedule_reference" }], [{ id: "PUSR1", type: "user_reference" }]]),
      policy("PEP2", [[{ id: "PUSR2", type: "user_reference" }], [{ id: "PSCH1", type: "schedule_reference" }]]),
      policy("PEP3", [[{ id: "PUSR3", type: "user_reference" }]]),
    ]),
    "/schedules/PSCH1": ok({ schedule: { id: "PSCH1", time_zone: "UTC", final_schedule: { name: "Final Schedule", rendered_coverage_percentage: 100, rendered_schedule_entries: [] } } }),
    "/incident_workflows": page("incident_workflows", [{ id: "PWF1", name: "Major incident", is_enabled: true }]),
    "/automation_actions/actions": ok({ actions: [], limit: 100, next_cursor: null }),
  };
}

export const C: Contract = {
  source: pagerduty, clientKey: "pagerduty", base: PAGERDUTY_BASE, prefix: "pagerduty", strong,
  env: { PAGERDUTY_TOKEN: "x" },
  rateLimited: { path: "/services", check: "escalation_multi_level" },
  fails: {
    incident_reviews_linked: { "/incidents/PINC2/notes": ok({ notes: [{ id: "n2", content: "restarted the pod" }] }) },
    escalation_multi_level: { "/escalation_policies": page("escalation_policies", [policy("PEP1", [[{ id: "PUSR1", type: "user_reference" }]]), policy("PEP2", [[{ id: "PUSR2", type: "user_reference" }], [{ id: "PUSR1", type: "user_reference" }]])]) },
    oncall_24x7: { "/schedules/PSCH1": ok({ schedule: { id: "PSCH1", final_schedule: { name: "Final Schedule", rendered_coverage_percentage: 71.4 } } }) },
    response_automation: { "/incident_workflows": page("incident_workflows", [{ id: "PWF1", is_enabled: false }]) },
  },
};
