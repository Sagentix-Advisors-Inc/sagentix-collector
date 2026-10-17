// Every source the collector can run. A new source is one file in this folder and one line below.
import type { Source } from "../types.ts";
import { cloudflare } from "./cloudflare.ts";
import { entra } from "./entra.ts";
import { okta } from "./okta.ts";
import { googleWorkspace } from "./google_workspace.ts";
import { github } from "./github.ts";
import { aws } from "./aws.ts";
import { azure } from "./azure.ts";
import { gcp } from "./gcp.ts";
import { jira } from "./jira.ts";
import { lms } from "./lms.ts";
import { prowler } from "./prowler.ts";
import { ENGINE_SOURCES } from "./engines.ts";
import { DEVICE_SOURCES } from "./device_sources.ts";

export const SOURCES: readonly Source[] = [
  cloudflare,
  entra, okta, googleWorkspace, github,
  aws, azure, gcp, jira, lms,
  prowler,
  ...ENGINE_SOURCES,
  ...DEVICE_SOURCES,
];
