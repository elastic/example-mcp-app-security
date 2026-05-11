/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  AlertsClient,
  AttackDiscoveryClient,
  CasesClient,
  EntityDetailClient,
  EsqlClient,
  IndicesClient,
  InvestigateClient,
  RulesClient,
  SampleDataClient,
} from "./elastic/client/index.js";
import {
  createCredentialClient,
  type CredentialClient,
} from "./elastic/credential-client/index.js";
import { createEsClient } from "./elastic/es-client/index.js";
import { createKibanaClient } from "./elastic/kibana-client/index.js";
import {
  AlertsService,
  AttackDiscoveryService,
  CasesService,
  EntityDetailService,
  EsqlService,
  IndicesService,
  InvestigateService,
  RulesService,
  SampleDataService,
} from "./elastic/service/index.js";
import { registerAlertTriageTools } from "./tools/alert-triage.js";
import { registerAttackDiscoveryTools } from "./tools/attack-discovery.js";
import { registerCaseManagementTools } from "./tools/case-management.js";
import { registerDetectionRuleTools } from "./tools/detection-rules.js";
import { registerSampleDataTools } from "./tools/sample-data.js";
import { registerThreatHuntTools } from "./tools/threat-hunt.js";

export interface CreateServerDeps {
  /**
   * Pre-built credential client. In HTTP mode, callers should construct
   * this once at startup and reuse it across requests so we don't re-read
   * `CLUSTERS_FILE` and re-run Zod validation on every `POST /mcp`.
   * Defaults to a freshly-built one for tests and stdio callers that only
   * call `createServer()` once.
   */
  readonly credentialClient?: CredentialClient;
}

/**
 * Build a fresh `McpServer` wired up against the **default** configured
 * cluster.
 *
 * Cluster selection is intentionally pinned to the default cluster for the
 * moment. Once tools accept a cluster parameter, this will be replaced with
 * a per-request factory call.
 */
export function createServer(deps: CreateServerDeps = {}): McpServer {
  const credentialClient = deps.credentialClient ?? createCredentialClient();
  const credentials = credentialClient.get();

  const esClient = createEsClient(credentials);
  const kibanaClient = createKibanaClient(credentials);

  const alertsService = new AlertsService({
    alertsClient: new AlertsClient({ esClient }),
  });
  const attackDiscoveryService = new AttackDiscoveryService({
    attackDiscoveryClient: new AttackDiscoveryClient({ esClient, kibanaClient }),
  });
  const casesService = new CasesService({
    casesClient: new CasesClient({ esClient, kibanaClient }),
  });
  const entityDetailService = new EntityDetailService({
    entityDetailClient: new EntityDetailClient({ esClient }),
  });
  const esqlService = new EsqlService({
    esqlClient: new EsqlClient({ esClient }),
  });
  const indicesService = new IndicesService({
    indicesClient: new IndicesClient({ esClient }),
  });
  const investigateService = new InvestigateService({
    investigateClient: new InvestigateClient({ esClient }),
  });
  const rulesService = new RulesService({
    rulesClient: new RulesClient({ esClient, kibanaClient }),
  });
  const sampleDataService = new SampleDataService({
    sampleDataClient: new SampleDataClient({ esClient }),
    rulesService,
  });

  const server = new McpServer({
    name: "elastic-security",
    version: "1.0.0",
  });

  registerAlertTriageTools(server, { alertsService });
  registerCaseManagementTools(server, { casesService });
  registerDetectionRuleTools(server, { rulesService });
  registerThreatHuntTools(server, {
    esqlService,
    indicesService,
    investigateService,
    entityDetailService,
  });
  registerSampleDataTools(server, { sampleDataService });
  registerAttackDiscoveryTools(server, {
    attackDiscoveryService,
    casesService,
  });

  return server;
}
