import { createHash, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  CapabilityContractVerifier,
  CapabilityContractValidationError,
  canonicalContractJson,
  type CapabilityAudience,
  type CapabilityContractEnvelope,
} from '../../../../server/stellar-capability-contract.ts';
import {
  CapabilityReplayConflictError,
  type CapabilityReceipt,
  type CapabilityReplayStore,
} from '../../../../server/stellar-capability-store.ts';

export const FIXED_T7C_ACTION='stellar.t7b.fixed-security-probe-suite/v0.1' as const;
const HASH=/^(?:sha256:)?[a-f0-9]{64}$/;

export function canonicalSha256(value:string):string {
  if (!HASH.test(value)) throw new CapabilityContractValidationError('SHA-256 value must be one lowercase digest with an optional lowercase sha256 prefix.');
  return value.startsWith('sha256:') ? value : `sha256:${value}`;
}

function digestText(value:string):string {
  return `sha256:${createHash('sha256').update(value.trim()).digest('hex')}`;
}

export interface FixedBrokerInvocation {
  action:typeof FIXED_T7C_ACTION;
  contractId:string;
  requestHash:string;
  executorSubject:string;
}
export interface FixedBrokerResult {
  status:'completed'|'refused';
  aggregateEvidenceHash:string;
  cleanupEvidenceHash:string;
  reason?:string;
}
export interface FixedBrokerInvoker { invoke(request:FixedBrokerInvocation):Promise<FixedBrokerResult> }
export interface BrokerAttestationSigner { readonly keyId:string; sign(bytes:Buffer):string }
export interface SignedBrokerReceipt {
  schema:'stellar-broker-receipt-envelope-v0.1';
  protected:string;
  payload:string;
  signature:string;
}
export type AdapterResult={status:'completed'|'refused';receipt:SignedBrokerReceipt}|{status:'prior_receipt';receipt:CapabilityReceipt}|{status:'already_reserved'};

interface Options {
  resolveKey:(keyId:string)=>KeyObject|undefined;
  expectedAudience:CapabilityAudience;
  store:CapabilityReplayStore;
  invoker:FixedBrokerInvoker;
  signer:BrokerAttestationSigner;
  artifactRoot:string;
  now?:()=>number;
  environment?:'test'|'development'|'production'|'lab';
  fixedAction?:typeof FIXED_T7C_ACTION;
}

export class StellarServiceContractAdapter {
  private readonly verifier:CapabilityContractVerifier;
  private readonly now:()=>number;
  private readonly action:typeof FIXED_T7C_ACTION;
  constructor(private readonly options:Options) {
    this.action=options.fixedAction??FIXED_T7C_ACTION;
    if (this.action!==FIXED_T7C_ACTION) throw new CapabilityContractValidationError('only the fixed T7b security probe action is accepted.');
    const environment=options.environment??'production';
    if ((environment==='production'||environment==='lab')&&!options.store.durable) throw new CapabilityReplayConflictError('durable Redis replay storage is required for the service boundary.');
    this.now=options.now??Date.now;
    this.verifier=new CapabilityContractVerifier(options.resolveKey,{now:this.now,expectedAudience:options.expectedAudience});
  }

  async execute(request:{contract:CapabilityContractEnvelope;contractId:string;requestHash:string;executorSubject:string;action:typeof FIXED_T7C_ACTION}):Promise<AdapterResult> {
    if (request.action!==this.action) throw new CapabilityContractValidationError('broker action is not the fixed T7b security probe action.');
    const payload=this.verifier.verify(request.contract);
    if (payload.contractId!==request.contractId||payload.bindings.request.requestHash!==request.requestHash) throw new CapabilityContractValidationError('contract path and request hash do not match the signed payload.');
    this.verifyFixedBindings(payload.bindings);
    const reserved=await this.options.store.reserve({contractId:request.contractId,executionNonce:payload.executionNonce,requestHash:request.requestHash,executorSubject:request.executorSubject});
    if (reserved.status==='prior_receipt') return {status:'prior_receipt',receipt:reserved.receipt};
    if (reserved.status==='already_reserved') return {status:'already_reserved'};
    if (this.now()>=Date.parse(payload.expiresAt)) return this.finalize(request,payload,'refused',{status:'refused',reason:'contract_expired_after_reservation',aggregateEvidenceHash:this.artifact('t7b-target-host-acceptance.json'),cleanupEvidenceHash:this.artifact('t7b-fixed-probe-resource.canonical.json')});
    let result:FixedBrokerResult;
    try { result=await this.options.invoker.invoke({action:this.action,contractId:request.contractId,requestHash:request.requestHash,executorSubject:request.executorSubject}); }
    catch (error) { result={status:'refused',reason:`fixed_broker_failure:${error instanceof Error?error.name:'unknown'}`,aggregateEvidenceHash:this.artifact('t7b-target-host-acceptance.json'),cleanupEvidenceHash:this.artifact('t7b-fixed-probe-resource.canonical.json')}; }
    return this.finalize(request,payload,result.status,result);
  }

  private artifact(name:string):string { return digestText(readFileSync(resolve(this.options.artifactRoot,name),'utf8')); }
  private verifyFixedBindings(bindings:ReturnType<CapabilityContractVerifier['verify']>['bindings']):void {
    const report=JSON.parse(readFileSync(resolve(this.options.artifactRoot,'t7b-target-host-acceptance.json'),'utf8')) as {bindings:Record<string,string>;securityGate:{s7001StellarExecutionClosed:boolean;serverIntegrated:boolean;arbitraryCodeLoaded:boolean}};
    const expected={
      requestHash:this.artifact('t7b-fixed-probe-input.canonical.json'),sourceHash:this.artifact('t7b-fixed-probe-input.canonical.json'),packageHash:this.artifact('t7b-fixed-probe-effects.canonical.json'),buildLockHash:this.artifact('t7b-fixed-probe-policy.canonical.json'),toolchainHash:this.artifact('t7b-fixed-probe-resource.canonical.json'),runnerHash:canonicalSha256(report.bindings.runnerSha256),imageHash:canonicalSha256(report.bindings.brokerSha256),inputHash:this.artifact('t7b-fixed-probe-input.canonical.json'),manifestHash:this.artifact('t7b-fixed-probe-effects.canonical.json'),runnerImportsHash:this.artifact('t7b-fixed-probe-imports.canonical.json'),
    };
    const actual={...bindings.request,manifestHash:bindings.effects.manifestHash,runnerImportsHash:bindings.effects.runnerImportsHash};
    if (canonicalContractJson(actual)!==canonicalContractJson(expected)) throw new CapabilityContractValidationError('signed bindings do not exactly match the locally rederived fixed runner evidence.');
    if (bindings.target.entrySymbol!=='stellar_t7b_fixed_probe'||bindings.effects.capabilities.length!==0||bindings.effects.imports.length!==0) throw new CapabilityContractValidationError('fixed runner target/effect binding is not exact.');
    if (!report.securityGate.s7001StellarExecutionClosed||report.securityGate.serverIntegrated||report.securityGate.arbitraryCodeLoaded) throw new CapabilityContractValidationError('retained fixed-probe acceptance evidence does not preserve the closed gate.');
  }

  private async finalize(request:{contract:CapabilityContractEnvelope;contractId:string;requestHash:string;executorSubject:string},payload:ReturnType<CapabilityContractVerifier['verify']>,status:'completed'|'refused',result:FixedBrokerResult):Promise<AdapterResult> {
    const issuedAt=this.now(),expiresAt=Math.min(Date.parse(payload.expiresAt),issuedAt+5000);
    const body={action:this.action,brokerImageHash:payload.bindings.request.imageHash,brokerService:'AegisStellarExecutionBroker',cleanupEvidenceHash:canonicalSha256(result.cleanupEvidenceHash),contractHash:`sha256:${createHash('sha256').update(canonicalContractJson(request.contract)).digest('hex')}`,contractId:request.contractId,evidenceHash:canonicalSha256(result.aggregateEvidenceHash),expiresAt,hostId:payload.bindings.audience.machineId,issuedAt,nonce:payload.executionNonce,operationId:`operation:${request.contractId}`,releaseHash:payload.bindings.request.buildLockHash,requestHash:request.requestHash,requestId:request.contractId,runnerHash:payload.bindings.request.runnerHash,schema:'stellar-broker-receipt-v0.1',status,targetService:payload.bindings.audience.service};
    const header={alg:'ES256',kid:canonicalSha256(this.options.signer.keyId),schema:'stellar-broker-receipt-protected-v0.1'};
    const protectedValue=Buffer.from(canonicalContractJson(header)).toString('base64url'),payloadValue=Buffer.from(canonicalContractJson(body)).toString('base64url');
    const signature=this.options.signer.sign(Buffer.from(`${protectedValue}.${payloadValue}`));
    const receipt:SignedBrokerReceipt={payload:payloadValue,protected:protectedValue,schema:'stellar-broker-receipt-envelope-v0.1',signature};
    const canonicalReceipt=canonicalContractJson(receipt),receiptHash=`sha256:${createHash('sha256').update(canonicalReceipt).digest('hex')}`;
    const ledgerReceipt:CapabilityReceipt=result.reason?{receiptHash,status,reason:result.reason}:{receiptHash,status};
    if (status==='completed') await this.options.store.consume(request.contractId,request.requestHash,ledgerReceipt); else await this.options.store.refuse(request.contractId,request.requestHash,ledgerReceipt);
    return {status,receipt};
  }
}
