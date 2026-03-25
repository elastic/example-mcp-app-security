import { esRequest } from "./client.js";
import type { EsqlResult } from "../shared/types.js";

export async function executeEsql(query: string): Promise<EsqlResult> {
  const result = await esRequest<EsqlResult>("/_query", {
    body: { query },
    params: { format: "json" },
  });
  return result;
}
