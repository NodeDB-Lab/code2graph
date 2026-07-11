// SPDX-License-Identifier: Apache-2.0

import { Type } from "@earendil-works/pi-ai";
export const DEFAULT_LIMIT=50, MAX_LIMIT=200;
export function numberParam(description:string,defaultValue:number,minimum=1,maximum=MAX_LIMIT){return Type.Optional(Type.Number({description,default:defaultValue,minimum,maximum}));}
export const tierParam=Type.Optional(Type.Union([Type.Literal("name"),Type.Literal("scope")],{description:"Resolution tier: name is recall-first; scope is scope-aware where available.",default:"scope"}));
export function rootParam(){return Type.Optional(Type.String({description:"Directory to scan. Relative paths resolve from Pi's current working directory."}));}
export function refreshParam(){return Type.Optional(Type.Boolean({description:"Rescan instead of reusing the bounded in-process snapshot cache.",default:false}));}
export function textResult(payload:unknown){return{content:[{type:"text" as const,text:JSON.stringify(payload,null,2)}],details:payload};}
