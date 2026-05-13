/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  AlertsClient,
  AttackDiscoveryClient,
  CasesClient,
  EsqlClient,
  IndicesClient,
  RulesClient,
  SampleDataClient,
} from "../../src/elastic/client/index.js";
import type { ClusterCredentials } from "../../src/elastic/credential-client/index.js";
import {
  createEsClient,
  type EsClient,
} from "../../src/elastic/es-client/index.js";
import {
  createKibanaClient,
  type KibanaClient,
} from "../../src/elastic/kibana-client/index.js";
import {
  AlertsService,
  AttackDiscoveryService,
  CasesService,
  EsqlService,
  IndicesService,
  RulesService,
  SampleDataService,
} from "../../src/elastic/service/index.js";

/**
 * Bundle of services + low-level clients wired against a single set of
 * cluster credentials. The runner rebuilds this on each role swap rather
 * than mutating any singleton.
 *
 * Mirrors the wiring in `src/server.ts` — keep this in sync when new
 * services are added there.
 */
export interface Services {
  readonly esClient: EsClient;
  readonly kibanaClient: KibanaClient;
  readonly alertsService: AlertsService;
  readonly casesService: CasesService;
  readonly rulesService: RulesService;
  readonly attackDiscoveryService: AttackDiscoveryService;
  readonly esqlService: EsqlService;
  readonly indicesService: IndicesService;
  readonly sampleDataService: SampleDataService;
}

export function buildServices(creds: ClusterCredentials): Services {
  const esClient = createEsClient(creds);
  const kibanaClient = createKibanaClient(creds);

  const alertsService = new AlertsService({
    alertsClient: new AlertsClient({ esClient }),
  });
  const attackDiscoveryService = new AttackDiscoveryService({
    attackDiscoveryClient: new AttackDiscoveryClient({ esClient, kibanaClient }),
  });
  const casesService = new CasesService({
    casesClient: new CasesClient({ esClient, kibanaClient }),
  });
  const esqlService = new EsqlService({
    esqlClient: new EsqlClient({ esClient }),
  });
  const indicesService = new IndicesService({
    indicesClient: new IndicesClient({ esClient }),
  });
  const rulesService = new RulesService({
    rulesClient: new RulesClient({ esClient, kibanaClient }),
  });
  const sampleDataService = new SampleDataService({
    sampleDataClient: new SampleDataClient({ esClient }),
    rulesService,
  });

  return {
    esClient,
    kibanaClient,
    alertsService,
    casesService,
    rulesService,
    attackDiscoveryService,
    esqlService,
    indicesService,
    sampleDataService,
  };
}
