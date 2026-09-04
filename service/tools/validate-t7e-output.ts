import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { fixedResources, validateOperatorReceipt, validateT7eEvidence } from "../t7e-semantic-validator.ts";
import { validateDraft202012 } from "../draft202012-validator.ts";
export const DISCOVERY_SCHEMA_HASH="sha256:6844bd75f71472cf00523facf392f551a5daf068d2d1fdec39db678fa2ef55c5";
export const RECEIPT_SCHEMA_HASH="sha256:782ea8a63b67f05e1309abd2e22848cb8357e2a5008f0c97d9ce014fde8ed405";
const sha=(bytes:Buffer)=>`sha256:${createHash("sha256").update(bytes).digest("hex")}`;
export function validateOutputFiles(planPath:string,evidenceBytes:Buffer,receiptBytes:Buffer,discoverySchemaPath:string,receiptSchemaPath:string):void{const discoverySchemaBytes=readFileSync(discoverySchemaPath),receiptSchemaBytes=readFileSync(receiptSchemaPath);if(sha(discoverySchemaBytes)!==DISCOVERY_SCHEMA_HASH||sha(receiptSchemaBytes)!==RECEIPT_SCHEMA_HASH)throw new Error("schema authority hash mismatch");const evidence=JSON.parse(evidenceBytes.toString("utf8")),receipt=JSON.parse(receiptBytes.toString("utf8"));validateDraft202012(JSON.parse(discoverySchemaBytes.toString("utf8")),evidence);validateDraft202012(JSON.parse(receiptSchemaBytes.toString("utf8")),receipt);validateT7eEvidence(evidence,fixedResources(planPath));validateOperatorReceipt(receipt,evidenceBytes);}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){const [planArg,evidenceArg,receiptArg]=process.argv.slice(2);if(!planArg||!evidenceArg||!receiptArg)throw new Error("usage: validate-t7e-output <accepted-plan> <evidence> <operator-receipt>");const evidenceBytes=readFileSync(resolve(evidenceArg));validateOutputFiles(resolve(planArg),evidenceBytes,readFileSync(resolve(receiptArg)),resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-v0.2.schema.json"),resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-receipt-v0.1.schema.json"));}
