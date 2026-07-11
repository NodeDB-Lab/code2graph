// SPDX-License-Identifier: Apache-2.0

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerCommands } from "./commands.ts";
import { impactTool, relationTool, scanTool, symbolSearchTool } from "./tools.ts";

export default function code2graphExtension(pi: ExtensionAPI) {
	pi.registerTool(scanTool);
	pi.registerTool(symbolSearchTool);
	pi.registerTool(relationTool("code2graph_callers", "code2graph callers", "callers"));
	pi.registerTool(relationTool("code2graph_callees", "code2graph callees", "callees"));
	pi.registerTool(impactTool);
	registerCommands(pi);
}
