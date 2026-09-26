/* tslint:disable */
/* eslint-disable */
interface CreateServerRegistrationResponseParams {
    serverSetup: string;
    userIdentifier: string;
    registrationRequest: string;
}

interface CreateServerRegistrationResponseResult {
    registrationResponse: string;
}

interface CustomIdentifiers {
    client?: string;
    server?: string;
}

interface FinishClientLoginParams {
    clientLoginState: string;
    loginResponse: string;
    password: string;
    identifiers?: CustomIdentifiers;
    keyStretching?: KeyStretchingFunctionConfig;
}

interface FinishClientLoginResult {
    finishLoginRequest: string;
    sessionKey: string;
    exportKey: string;
    serverStaticPublicKey: string;
}

interface FinishClientRegistrationParams {
    password: string;
    registrationResponse: string;
    clientRegistrationState: string;
    identifiers?: CustomIdentifiers;
    keyStretching?: KeyStretchingFunctionConfig;
}

interface FinishClientRegistrationResult {
    registrationRecord: string;
    exportKey: string;
    serverStaticPublicKey: string;
}

interface FinishServerLoginParams {
    serverLoginState: string;
    finishLoginRequest: string;
    identifiers?: CustomIdentifiers;
}

interface FinishServerLoginResult {
    sessionKey: string;
}

interface StartClientLoginParams {
    password: string;
}

interface StartClientLoginResult {
    clientLoginState: string;
    startLoginRequest: string;
}

interface StartClientRegistrationParams {
    password: string;
}

interface StartClientRegistrationResult {
    clientRegistrationState: string;
    registrationRequest: string;
}

interface StartServerLoginParams {
    serverSetup: string;
    registrationRecord: string | null | undefined;
    startLoginRequest: string;
    userIdentifier: string;
    identifiers?: CustomIdentifiers;
}

interface StartServerLoginResult {
    serverLoginState: string;
    loginResponse: string;
}

type KeyStretchingFunctionConfig = "rfc-recommended" | "rfc-draft-recommended" | "memory-constrained" | { "argon2id-custom": { iterations: number; memory: number; parallelism: number } };


declare function createServerRegistrationResponse(params: CreateServerRegistrationResponseParams): CreateServerRegistrationResponseResult;

declare function createServerSetup(): string;

declare function finishClientLogin(params: FinishClientLoginParams): FinishClientLoginResult | undefined;

declare function finishClientRegistration(params: FinishClientRegistrationParams): FinishClientRegistrationResult;

declare function finishServerLogin(params: FinishServerLoginParams): FinishServerLoginResult;

declare function getServerPublicKey(data: string): string;

declare function startClientLogin(params: StartClientLoginParams): StartClientLoginResult;

declare function startClientRegistration(params: StartClientRegistrationParams): StartClientRegistrationResult;

declare function startServerLogin(params: StartServerLoginParams): StartServerLoginResult;

// This file serves only as a template and will be copied
// by the build script into the build directory.
// The imports in this file are relative to the target build
// directory so will show up as errors here.

declare namespace client {
  export { finishClientLogin as finishLogin, finishClientRegistration as finishRegistration, startClientLogin as startLogin, startClientRegistration as startRegistration };
  export type { FinishClientLoginParams as FinishLoginParams, FinishClientLoginResult as FinishLoginResult, FinishClientRegistrationParams as FinishRegistrationParams, FinishClientRegistrationResult as FinishRegistrationResult, StartClientLoginParams as StartLoginParams, StartClientLoginResult as StartLoginResult, StartClientRegistrationParams as StartRegistrationParams, StartClientRegistrationResult as StartRegistrationResult };
}

// This file serves only as a template and will be copied
// by the build script into the build directory.
// The imports in this file are relative to the target build
// directory so will show up as errors here.

declare namespace server {
  export { createServerRegistrationResponse as createRegistrationResponse, createServerSetup as createSetup, finishServerLogin as finishLogin, getServerPublicKey as getPublicKey, startServerLogin as startLogin };
  export type { CreateServerRegistrationResponseParams as CreateRegistrationResponseParams, CreateServerRegistrationResponseResult as CreateRegistrationResponseResult, FinishServerLoginParams as LoginFinishParams, FinishServerLoginResult as LoginFinishResult, StartServerLoginParams as LoginStartParams, StartServerLoginResult as LoginStartResult };
}

declare const ready: Promise<void>;

export { client, ready, server };
