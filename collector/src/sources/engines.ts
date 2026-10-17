// Sources that read what another engine already produced (CISA SCuBA, Trivy, Grype, Syft, Gitleaks,
// OpenSSF Scorecard, Kubescape, Checkov), Cinc Auditor's STIG scans and the PagerDuty incident-management API. Listed in index.ts as one entry.
import type { Source } from "../types.ts";
import { scubagear, scubagoggles } from "./scuba.ts";
import { trivy } from "./trivy.ts";
import { grype } from "./grype.ts";
import { syft } from "./syft.ts";
import { gitleaks } from "./gitleaks.ts";
import { scorecard } from "./scorecard.ts";
import { pagerduty } from "./pagerduty.ts";
import { stig } from "./stig.ts";
import { kubescape } from "./kubescape.ts";
import { checkov } from "./checkov.ts";

export const ENGINE_SOURCES: readonly Source[] = [scubagoggles, scubagear, trivy, grype, syft, gitleaks, scorecard, pagerduty, stig, kubescape, checkov];
