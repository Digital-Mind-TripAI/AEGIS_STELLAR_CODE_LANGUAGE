import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
const [outArg]=process.argv.slice(2);if(!outArg)throw new Error("usage: generate-t7e-receipt-schema <new-output>");
const schema={$schema:"https://json-schema.org/draft/2020-12/schema",$id:"stellar-target-host-discovery-receipt-v0.1.schema.json",type:"object",additionalProperties:false,required:["bytes","exitCode","fileId","flushSucceeded","path","rootPolicyVerified","schema","sha256","volumeSerial"],properties:{bytes:{type:"integer",minimum:1,maximum:67108864},exitCode:{const:0},fileId:{type:"string",pattern:"^[a-f0-9]{32}$"},flushSucceeded:{const:true},path:{const:"C:\\ProgramData\\AEGIS\\Stellar\\v0.1\\evidence\\target-host-discovery.canonical.json"},rootPolicyVerified:{const:true},schema:{const:"stellar.t7e-operator-receipt/v0.1"},sha256:{type:"string",pattern:"^sha256:[a-f0-9]{64}$"},volumeSerial:{type:"string",pattern:"^[0-9]+$"}}};
writeFileSync(resolve(outArg),JSON.stringify(schema));
