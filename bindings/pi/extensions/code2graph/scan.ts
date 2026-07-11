// SPDX-License-Identifier: Apache-2.0

import { scan as scanAsync, summarize as summarizeAsync, type ScanParams } from "./scan-service.ts";
export { type ScanParams } from "./scan-service.ts";
export const scan = scanAsync;
export const summarize = summarizeAsync;
