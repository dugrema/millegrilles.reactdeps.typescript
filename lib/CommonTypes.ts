export type AuthenticationChallengePublicKeyType = {
    allowCredentials?: Array<{id: string, type: string}>,
    challenge: string,
    rpId?: string,
    timeout?: number,
    userVerification?: 'string',
};

export type AuthenticationChallengeType = {
    publicKey: AuthenticationChallengePublicKeyType,
};

export type PerformLoginResult = {
    register?: boolean,
    mustReconnectWorker?: boolean,
    mustManuallyAuthenticate?: boolean,
    authenticated?: boolean,
    userId?: string,
    webauthnChallenge?: AuthenticationChallengeType,
};
