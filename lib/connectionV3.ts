import { io, Socket } from 'socket.io-client';
import { certificates, ed25519, messageStruct } from 'millegrilles.cryptography';

const CONST_TRANSPORTS = ['websocket', 'polling'];

export type ConnectionSocketioProps = {
    reconnectionDelay?: number;
};

export type ConnectionCallbackParameters = {
    connected: boolean, 
    authenticated?: boolean,
    username?: string, 
    userId?: string,
    idmg?: string,
};

export type EmitWithAckProps = VerifyResponseOpts & {
    timeout?: number,
    overrideConnected?: boolean,
}

export type SendProps = VerifyResponseOpts & {
    eventName?: string,
    timeout?: number,
    overrideConnected?: boolean,
    partition?: string,
    attachments?: Object
    encrypt?: boolean,
    nowait?: boolean,
    exchange?: string,
}

export type EmitProps = {
    overrideConnected?: boolean,
}

export type VerifyResponseOpts = {
    noverif?: boolean,
    domain?: string,
    role?: string,
};

export type RoutedMessageProps = VerifyResponseOpts & {
    partition?: string,
    nowait?: boolean,
}

export type MessageResponse = {
    ok?: boolean,
    code?: number,
    err?: string,
    __original?: messageStruct.MilleGrillesMessage,
    __certificate?: certificates.CertificateWrapper,
};

export type SubscriptionMessage = {
    exchange: string,
    routingKey: string,
    message: MessageResponse | messageStruct.MilleGrillesMessage,
}

export interface SubscriptionCallback {
    (event: SubscriptionMessage): void;
}

export type SubscriptionParameters = Object;

export default class ConnectionSocketio {
    url: string;
    serverUrl?: string;
    params?: {path: string, reconnection: boolean, transports: Array<string>, reconnectionDelay?: number};
    connectionParams?: {};
    messageFactory?: MessageFactory;
    socket?: Socket;
    certificateStore?: certificates.CertificateStore;
    callback?: (params: ConnectionCallbackParameters) => void;
    opts?: ConnectionSocketioProps;
    unsubscribeHandlers: { [key: string]: () => void };
    encryptionCertificates: Array<certificates.CertificateWrapper>;
    authenticated: boolean;

    /**
     * 
     * @param url 
     * @param ca 
     * @param callback Function to callback when a change occurs (e.g. connect, disconnect, authenticated).
     * @param opts 
     */
    constructor(url: string, ca: string, callback: (params: ConnectionCallbackParameters) => void, opts?: ConnectionSocketioProps) {
        opts = opts || {};
        this.url = url;
        this.opts = opts;
        this.unsubscribeHandlers = {};
        this.encryptionCertificates = [];
        this.authenticated = false;

        // Wrap the callback to avoid a comlink error.
        this.callback = (params) => { callback(params); }

        // Initialize certificate/message validation store and cache
        this.certificateStore = new certificates.CertificateStore(ca);
        this.certificateStore.cache = new certificates.CertificateCache(20);

        this.configureConnection();
    }

    configureConnection() {
        let urlInfo = new URL(this.url);
        let pathSocketio = urlInfo.pathname;
        this.serverUrl = `https://${urlInfo.hostname}`;

        let transports = CONST_TRANSPORTS;

        this.params = {
            path: pathSocketio,
            reconnection: false,
            transports,
        };

        if(this.opts?.reconnectionDelay) {
            this.params.reconnection = true;
            this.params.reconnectionDelay = this.opts.reconnectionDelay;
        }

        // console.info("ConnexionSocketio Server : %s, Params %O", this.serverUrl, this.params);
        this.socket = io(this.serverUrl, this.params);

        this.bindSocketioEventHandlers()
    }

    bindSocketioEventHandlers() {
        if(!this.socket) throw new Error('Socket not initialized');

        this.socket.on('connect', () => this.onConnect())
        this.socket.io.on('reconnect_attempt', () => this.onReconnectAttempt())
        this.socket.io.on('reconnect', () => this.onReconnect())
        this.socket.on('disconnect', reason => this.onDisconnect(reason))
        this.socket.on('connect_error', err => this.onConnectError(err))
    }

    onConnect() {
        if(this.callback) this.callback({connected: true});
        this.onConnectHandler()
            .catch((err: Error)=>console.error("Connection error ", err));
    }

    onDisconnect(reason: string) {
        this.authenticated = false;
        if(this.callback) this.callback({connected: false, authenticated: false});
        console.warn("Disconnected, reason : ", reason);
    }

    onReconnect() {
        this.authenticated = false;
        if(this.callback) this.callback({connected: true, authenticated: false});
        this.onConnectHandler()
            .catch((err: Error)=>console.error("Reconnection error ", err));
    }

    onReconnectAttempt() {
    }

    onConnectError(err: Error) {
        this.authenticated = false;
        if(this.callback) this.callback({connected: false, authenticated: false});
        console.error("Connection error : ", err);
    }

    async onConnectHandler() {
        // Pour la premiere connexion, infoPromise est le resultat d'une requete getEtatAuth.
        const info = await this.emitWithAck('getEtatAuth', {}, {noverif: true, overrideConnected: true}) as any;

        // Ensure encryption certificates are loaded.
        if(this.encryptionCertificates.length === 0) {
            let response = await this.emitWithAck('getCertificatsMaitredescles', null, {noverif: true}) as Array<Array<string>>;

            if(response && response.length > 0) {
                let wrappers = response.map(item=>{
                    let wrapper = new certificates.CertificateWrapper(item);
                    wrapper.populateExtensions();
                    return wrapper;
                })
                .filter(item=>
                    item.extensions?.domains?.includes('MaitreDesCles') &&
                    item.extensions?.exchanges?.includes('4.secure')
                );
                this.encryptionCertificates = wrappers
            } 
            
            if(this.encryptionCertificates.length === 0) {
                console.info("No encryption certificates are available for this system");
            }
        }

        if(this.callback) {
            let params: ConnectionCallbackParameters = {connected: true, authenticated: this.authenticated};
            // @ts-ignore
            let username = params.username || params.nomUsager;
            if(username) params.username = username;
            if(info.userId) params.userId = info.userId;
            if(info.idmg) params.idmg = info.idmg;
            this.callback(params);
        }
    }

    /**
     * Connects the socket to the server.
     */
    async connect() {
        if(!this.socket) throw new Error('Socketio is not configured');
        if(this.socket.connected) return true

        return new Promise((resolve, reject)=>{
            // Workaround si aucun callback
            const timeoutConnexion = setTimeout(()=>{
                if(this.socket?.connected) return resolve(true);
                else reject('Connection timeout');
            }, 5_000);

            const callbackHandler = (err?: Error) => {
                clearTimeout(timeoutConnexion)
                if(err) return reject(err)
                resolve(true)
            }

            this.socket?.on('connect', () => {
                callbackHandler();
            })

            this.socket?.on('connect_error', (err: Error) => {
                callbackHandler(err);
            })

            this.socket?.connect();
        })
    
    }

    /**
     * Disconnect then reconnect. Used to load a new user session (new auth cookie).
     */
    async reconnect() {
        throw new Error('todo');
    }

    async maintenance() {
        this.certificateStore?.cache.maintain()
            .catch(err=>{
                console.warn("Erreur during certificate cache maintenance: ", err);
            });
    }

    /**
     * Prepares a message factory for a user (key/certificate).
     * @param signingKey A user's private key
     * @param certificate A user's certificate
     */
    prepareMessageFactory(signingKey: ed25519.MessageSigningKey) {
        signingKey.certificate.populateExtensions();
        this.messageFactory = new MessageFactory(signingKey);
    }

    getMessageFactoryCertificate(): certificates.CertificateWrapper | undefined {
        return this.messageFactory?.signingKey.certificate;
    }

    /**
     * Creates and signs a new routed message.
     * @param kind Request (1) or command (2).
     * @param content 
     * @param routing 
     * @param timestamp 
     * @returns 
     */
    async createRoutedMessage(kind: messageStruct.MessageKind, content: Object, routing: messageStruct.Routage, 
        timestamp?: Date): Promise<messageStruct.MilleGrillesMessage> 
    {
        if(!this.messageFactory) throw new Error('Signing key is not loaded');
        return await this.messageFactory.createRoutedMessage(kind, content, routing, timestamp);
    }

    /**
     * Creates and signs a new routed message.
     * @param kind Request (1) or command (2).
     * @param content 
     * @param routing 
     * @param timestamp 
     * @returns 
     */
    async createEncryptedCommand(content: Object, routing: messageStruct.Routage, timestamp?: Date): Promise<messageStruct.MilleGrillesMessage> {
        if(!this.messageFactory) throw new Error('Signing key is not loaded');
        if(this.encryptionCertificates.length === 0) throw new Error('No encryption certificates are available');
        return await this.messageFactory.createEncryptedCommand(this.encryptionCertificates, content, routing, timestamp);
    }

    /**
     * Creates and signs a response.
     * @param content 
     * @param timestamp 
     * @returns 
     */
    async createResponse(content: Object, timestamp?: Date): Promise<messageStruct.MilleGrillesMessage> {
        if(!this.messageFactory) throw new Error('Signing key is not loaded');
        return await this.messageFactory.createResponse(content, timestamp);
    }

    /**
     * Methode principale pour emettre un message vers le serveur. Attend une confirmation/reponse.
     * Le message tranmis est signe localement (sauf si inhibe) et la signature de la reponse est verifiee.
     * @param {*} eventName 
     * @param {*} args 
     * @param {*} opts 
     * @returns 
     */
    async emitWithAck(eventName: string, message: Object | null, opts?: EmitWithAckProps) {
        opts = opts || {}
        if(!this.socket) throw new Error('The connection is not configured');
        if(!eventName) throw new TypeError('Event name is null');

        let timeoutDelay = opts.timeout || 9000;
        let overrideConnected = opts.overrideConnected || false;

        if(!overrideConnected && !this.socket.connected) throw new DisconnectedError("connexionClient.emitWithAck Deconnecte");

        let request = this.socket.timeout(timeoutDelay) as any;
        if(message) {
            request = request.emitWithAck(eventName, message);
        } else {
            request = request.emitWithAck(eventName);
        }

        const response = await request as any;
        if(response.sig) {
            return this.verifyResponse(response, opts);
        } else {
            // @ts-ignore
            if(response.err) throw new Error(response.err);  // Server error
            if(opts.noverif) return response as MessageResponse;
            else throw new Error("Invalid response");
        }
    }

    /**
     * Methode principale pour emettre un message vers le serveur. Attend une confirmation/reponse.
     * Le message tranmis est signe localement (sauf si inhibe) et la signature de la reponse est verifiee.
     * @param {*} eventName 
     * @param {*} message 
     * @param {*} opts 
     * @returns 
     */
    async emit(eventName: string, message: Object, opts?: EmitProps): Promise<boolean> {
        opts = opts || {}
        if(!this.socket) throw new Error('pas configure');
        if(!eventName) throw new TypeError('Event name is null');

        let overrideConnected = opts.overrideConnected || false;

        if(!overrideConnected && !this.socket.connected) throw new DisconnectedError();

        if(message) {
            this.socket.volatile.emit(eventName, message)
        } else {
            this.socket.volatile.emit(eventName)
        }

        return true
    }

    /**
     * Methode principale pour emettre un message vers le serveur. Attend une confirmation/reponse.
     * Le message tranmis est signe localement (sauf si inhibe) et la signature de la reponse est verifiee.
     * @param {*} message 
     * @param {*} callback 
     * @param {*} opts 
     * @returns 
     */
    async emitCallbackResponses(message: messageStruct.MilleGrillesMessage, callback: (m: MessageResponse) => void, 
        opts?: EmitWithAckProps): Promise<boolean> 
    {
        opts = opts || {}
        if(!this.socket) throw new Error('socket non configure');

        let overrideConnected = opts.overrideConnected || false;

        if(!overrideConnected && !this.socket.connected) throw new DisconnectedError();
        if(!message || !message.id || !message.sig) throw new Error('Message must be signed');

        let socketEvent = 'stream_' + message.id;
        let timeoutDelay = opts.timeout || 30_000;

        // Listen on socket
        let done: any = new Promise((resolve, reject) => {
            let timeout = null;
            this.socket.on(socketEvent, async (response: messageStruct.MilleGrillesMessage)=>{
                clearTimeout(timeout);
                if(response) {
                    if(response.sig) {
                        try {
                            let result = await this.verifyResponse(response, opts);
                            callback(result);
                        } catch(err) {
                            reject(err);
                        }
                    } else {
                        // @ts-ignore
                        if(response.err) throw new Error(response.err);  // Server error
                        if(opts.noverif) return response as MessageResponse;
                        return(new Error("Invalid response"));
                    }
                }
                // Check if we're done
                // @ts-ignore
                if(response.attachements?.streaming !== true) {
                    return resolve(true);  // Done
                } else {
                    // Not done
                    timeout = setTimeout(()=>{reject('Timeout')}, timeoutDelay);
                }
            })
            timeout = setTimeout(()=>{reject('Timeout')}, timeoutDelay);
        });

        this.socket.volatile.emit('route_message_stream_response', message);
        try {
            await done;
        } finally {
            this.socket.off(socketEvent);
        }

        return done;
    }
    

    async verifyResponse(response: any, opts?: VerifyResponseOpts): Promise<MessageResponse> {
        opts = opts || {}
    
        if(opts.noverif) {
            // No verification or parsing of the response.
            let content = {...response, '__original': response} as MessageResponse;
            return content
        }

        // if(response['__original']) return response;  // Already processed
        // if(!(response instanceof messageStruct.MilleGrillesMessage)) {
        //     throw new Error('Wrong response type');
        // }

        if(response.sig && response.certificat) {
            // Convert response to MilleGrillesMessage
            Object.setPrototypeOf(response, messageStruct.MilleGrillesMessage.prototype);
            let original = response;

            const certificateWrapper = await this.certificateStore?.verifyMessage(original);

            if(opts.role) {
                let roles = certificateWrapper?.extensions?.roles;
                if(!roles || !roles.includes(opts.role)) throw new Error(`Invalid response role: ${roles} - role mismatch or missing`);
            } else if(opts.domain) {
                let domains = certificateWrapper?.extensions?.domains;
                if(!domains || !domains.includes(opts.domain)) throw new Error(`Invalid response domain: ${domains} - domain mismatch or missing`);
            }

            // Parse content, keep original
            let content = {'__original': original, '__certificate': certificateWrapper} as MessageResponse;
            // let responseObject = new messageStruct.MilleGrillesMessage(response.estampille, response.kind, response.contenu);
            if(response.kind === 6) {
                // console.info("Encrypted response %O", original)
                const contenuParsed = await this.messageFactory.decryptMessage(original);
                content = {...content, ...contenuParsed};
            } else if(original.contenu) {
                content = {...JSON.parse(original.contenu), content};
            }
            return content;
        } else {
            console.warn("Reponse recue sans signature/cert : ", response)
            // return reponse
            throw new Error("Invalid response: the signature is missing");
        }    
    }

    /**
     * Sign and send a request. 
     * Verifies that the response signature is valid and comes from the proper back-end component.
     * 
     * @param message Message to sign
     * @param domain Domain of the back-end application to reach on the mq bus.
     * @param action Action to run in the domain.
     * @param props 
     * @returns Response from the back-end component
     */
    async sendRequest(message: Object, domain: string, action: string, props?: SendProps): Promise<MessageResponse> {
        if(props?.encrypt) throw new Error('Encrypting a request is not unsupported');
        if(!this.messageFactory) throw new Error("User is not initialized");

        let routing: {domaine: string, action: string, partition?: string} = {domaine: domain, action};
        if(props?.partition) routing.partition = props.partition;
        let request = await this.messageFactory.createRoutedMessage(messageStruct.MessageKind.Request, message, routing, new Date());
        if(!request) throw new Error("Error generating request: null");
        if(props?.attachments) request.attachements = props.attachments;
        let eventName = props?.eventName || 'route_message';

        if(props?.exchange) {
            // Override the default exchange for this request. Will be rejected if more secure than allowed.
            let attachements = request.attachements || {} as any;
            attachements.destination_exchange = props.exchange;
            request.attachements = attachements;
        }

        // Ensure the domain is added to emit props for verification. It is overriddeen when already present in props.
        let emitWithAckProps = props?{domain, ...props}:{domain};
        return await this.emitWithAck(eventName, request, emitWithAckProps);
    }

    /**
     * Sign and send a command.
     * Verifies that the response signature is valid and comes from the proper back-end component.
     * 
     * @param message Message to sign
     * @param domain Domain of the back-end application to reach on the mq bus.
     * @param action Action to run in the domain.
     * @param props 
     * @returns Response from the back-end component
     */
    async sendCommand(message: Object, domain: string, action: string, props?: SendProps): Promise<MessageResponse> {
        if(!this.messageFactory) throw new Error("User is not initialized");
        let routing: {domaine: string, action: string, partition?: string} = {domaine: domain, action};
        if(props?.partition) routing.partition = props.partition;

        if(props?.encrypt) {
            throw new Error('todo');
        }

        let command = await this.messageFactory.createRoutedMessage(messageStruct.MessageKind.Command, message, routing, new Date());
        if(!command) throw new Error("Error generating command: null");
        if(props?.attachments) command.attachements = props.attachments;
        let eventName = props?.eventName || 'route_message';

        if(props?.exchange) {
            // Override the default exchange for this request. Will be rejected if more secure than allowed.
            let attachements = command.attachements || {} as any;
            attachements.destination_exchange = props.exchange;
            command.attachements = attachements;
        }

        // Ensure the domain is added to emit props for verification. It is overriddeen when already present in props.
        let emitWithAckProps = props?{domain, ...props}:{domain};
        if(props?.nowait) {
            let ok = await this.emit(eventName, command, emitWithAckProps);
            return {ok};
        } else {
            return await this.emitWithAck(eventName, command, emitWithAckProps);
        }
    }

    async authenticate(apiMapping?: Object, reconnect?: boolean) {
        if(reconnect) {
            // Reconnect to get the latest request headers (HTTP session).
            this.socket?.disconnect();
            await this.connect();
        }

        // Faire une requete pour upgrader avec le certificat
        let challengeResponse = await this.emitWithAck('genererChallengeCertificat', null, {noverif: true}) as any;
        let data = {...challengeResponse.challengeCertificat};

        let authenticationResponse = await this.sendCommand(
            data, 'authentication', 'authenticate', 
            {attachments: { apiMapping }, eventName: 'authentication_authenticate', role: 'private_webapi'}
        );

        let authOk = authenticationResponse.ok === true;
        this.authenticated = authOk;

        let params: ConnectionCallbackParameters = {connected: true, authenticated: authOk};
        this.callback(params);

        return authOk;
    }

    async subscribeActivationCode(callback: SubscriptionCallback, publicKey: string): Promise<void> {
        if(!this.socket) throw new Error('Socket not initialized');
        let response = await this.emitWithAck('authentication_subscribe_activation', {publicKey});
        if(!response.ok) throw new Error('Error subscribing for certificate activation');

        let routingKey = `evenement.CoreMaitreDesComptes.activationFingerprintPk`;
        this.socket.on(routingKey, async (event: any) => {
            try {
                let responseMessage = await this.verifyResponse(event.message, {domain: 'CoreMaitreDesComptes'});
                callback({...event, message: responseMessage});
            } catch(err) {
                console.error("Error during event verification: ", err);
            }
        });
    }

    async unsubscribeActivationCode(callback: SubscriptionCallback, publicKey: string): Promise<void> {
        if(!this.socket) throw new Error('Socket not initialized');
        let routingKey = `evenement.CoreMaitreDesComptes.activationFingerprintPk`;
        this.socket.off(routingKey, callback);

        let response = await this.emitWithAck('authentication_unsubscribe_activation', {publicKey});
        if(!response.ok) console.warn("Error unsubscribing to listen for a certificate activation");
    }

    async subscribe(subscribeEventName: string, callback: SubscriptionCallback, parameters?: SubscriptionParameters): Promise<void> {
        if(!this.socket) throw new Error('Socket not initialized');
        if(!this.messageFactory) throw new Error("User is not initialized");

        let routing = {domaine: 'subscribe', action: subscribeEventName};
        let message = parameters || {};
        let command = await this.messageFactory.createRoutedMessage(messageStruct.MessageKind.Command, message, routing, new Date());
        if(!command) throw new Error("Error generating command: null");

        let subscriptionResponse = await this.emitWithAck('subscribe', command, {role: 'private_webapi'}) as any;
        if(!subscriptionResponse.ok) {
            throw new Error('Error subscribing to ' + subscribeEventName + ': ' + subscriptionResponse.err);
        }

        let routingKeys = subscriptionResponse.routingKeys;

        // Create a wrapper for the callback. Allows for verification of the event.
        let wrappedCallback = async (event: SubscriptionMessage) => {
            try {
                let responseMessage = await this.verifyResponse(event.message);
                callback({...event, message: responseMessage});
            } catch(err) {
                console.error("Error during event verification: ", err);
            }
        };

        // Register an unsubscribe handler.
        let unsubscribeHandler = () => {
            for(let rk of routingKeys) {
                this.socket?.off(rk, wrappedCallback);
            }
        }
        let handler = this.unsubscribeHandlers[subscribeEventName];
        if(handler) {
            console.warn("Cleaning up previous event unsubscribe handler");
            try { handler(); }
            catch(err) { console.warn("Error running unsubscribe handler ", err); }
        }
        this.unsubscribeHandlers[subscribeEventName] = unsubscribeHandler;

        // Register event listeners for each routingKey
        for(let rk of routingKeys) {
            this.socket.on(rk, wrappedCallback);
        }
    }
    
    async unsubscribe(subscribeEventName: string, callback: SubscriptionCallback, parameters?: SubscriptionParameters): Promise<void> {
        if(!this.socket) throw new Error('Socket not initialized');

        let handler = this.unsubscribeHandlers[subscribeEventName];
        delete this.unsubscribeHandlers[subscribeEventName];  // Cleanup
        if(handler) {
            try { handler(); }
            catch(err) { console.warn("Error running unsubscribe handler ", err); }
        } else {
            // console.info("Previous event unsubscribe handler is missing");            
            // Nothing to do.
            return
        }

        if(!this.messageFactory) throw new Error("User is not initialized");
        let routing = {domaine: 'unsubscribe', action: subscribeEventName};
        let message = parameters || {};
        let command = await this.messageFactory.createRoutedMessage(messageStruct.MessageKind.Command, message, routing, new Date());
        if(!command) throw new Error("Error generating command: null");

        let subscriptionResponse = await this.emitWithAck('unsubscribe', command, {role: 'private_webapi'});
        if(!subscriptionResponse.ok) {
            throw new Error('Error unsubscribing to ' + subscribeEventName + ': ' + subscriptionResponse.err);
        }
    }
    
}

export class ConnectionWorker {
    connection?: ConnectionSocketio;

    async connect() {
        if(!this.connection) throw new Error("Connection is not initialized");
        return this.connection.connect();
    }

    async reconnect() {
        if(!this.connection) throw new Error("Connection is not initialized");
        return this.connection.reconnect();
    }

    async initialize(serverUrl: string, ca: string, callback: (params: ConnectionCallbackParameters) => void, opts?: ConnectionSocketioProps): Promise<boolean> {
        this.connection = new ConnectionSocketio(serverUrl, ca, callback, opts);
        return true;
    }

    /** Maintenance on the connection. Must be called regularly. */
    async maintain() {
        if(!this.connection) throw new Error("Connection is not initialized");
        await this.connection.certificateStore?.cache.maintain();
    }
    
    async ping(): Promise<boolean> {
        if(!this.connection) return false;
        return true;
    }

    async prepareMessageFactory(privateKey: Uint8Array, certificate: Array<string>) {
        if(!this.connection) throw new Error("Connection is not initialized");
        let caPem = this.connection.certificateStore.caPem;
        let signingKey = await ed25519.messageSigningKeyFromBytes(privateKey, certificate, caPem);
        return this.connection.prepareMessageFactory(signingKey);
    }

    async signAuthentication(data: {certificate_challenge: string, activation?: boolean, dureeSession?: number}): Promise<string> {
        if(!this.connection) throw new Error("Connection is not initialized");

        // Sign an auth command.
        let command = await this.connection.createRoutedMessage(
            messageStruct.MessageKind.Command, 
            data, 
            {domaine: 'auth', action: 'authentifier_usager'}
        );
        // Serialize to string
        return JSON.stringify(command);
    }

    /**
     * @returns Current user certificate used for signing messsages.
     */
    async getMessageFactoryCertificate() {
        if(!this.connection) throw new Error("Connection is not initialized");
        return this.connection.getMessageFactoryCertificate();
    }
    
    async subscribe(subscribeEventName: string, callback: SubscriptionCallback, params?: SubscriptionParameters) {
        if(!this.connection) throw new Error("Connection is not initialized");
        if(!this.connection.messageFactory) throw new Error("User is not initialized");
        return await this.connection.subscribe(subscribeEventName, callback, params);
    }

    async unsubscribe(subscribeEventName: string, callback: SubscriptionCallback, params?: SubscriptionParameters) {
        if(!this.connection) throw new Error("Connection is not initialized");
        if(!this.connection.messageFactory) throw new Error("User is not initialized");
        return await this.connection.unsubscribe(subscribeEventName, callback, params);
    }

    async verifyMessage(message: messageStruct.MilleGrillesMessage): Promise<MessageResponse | messageStruct.MilleGrillesMessage> {
        if(!this.connection) throw new Error("Connection is not initialized");
        if(!this.connection.messageFactory) throw new Error("User is not initialized");
        return await this.connection.verifyResponse(message);
    }

    async createRoutedMessage(kind: messageStruct.MessageKind, content: Object, routing: messageStruct.Routage, 
        timestamp?: Date): Promise<messageStruct.MilleGrillesMessage> 
    {
        if(!this.connection) throw new Error("Connection is not initialized");
        return await this.connection.createRoutedMessage(kind, content, routing, timestamp);
    }    
}

/** Facade for the messageStruct create methods. */
class MessageFactory {
    signingKey: ed25519.MessageSigningKey;
    certificate: Array<string> | null;

    constructor(signingKey: ed25519.MessageSigningKey) {
        this.signingKey = signingKey;
        this.certificate = signingKey.getChain();
    }

    async createRoutedMessage(kind: messageStruct.MessageKind, content: Object, routing: messageStruct.Routage, 
        timestamp?: Date): Promise<messageStruct.MilleGrillesMessage> 
    {
        return await messageStruct.createRoutedMessage(this.signingKey, kind, content, routing, timestamp);
    }

    async createEncryptedCommand(encryptionKeys: Array<certificates.CertificateWrapper>, 
        content: Object, routing: messageStruct.Routage, timestamp?: Date): Promise<messageStruct.MilleGrillesMessage> 
    {
        return await messageStruct.createEncryptedCommand(this.signingKey, encryptionKeys, content, routing, timestamp);
    }

    async createResponse(content: Object, timestamp?: Date): Promise<messageStruct.MilleGrillesMessage> {
        return await messageStruct.createResponse(this.signingKey, content, timestamp);
    }

    async decryptMessage(message: messageStruct.MilleGrillesMessage): Promise<Object> {
        if(!message.dechiffrage) throw new Error("Wrong message type");
        return await message.getContent(this.signingKey);
    }
}

export class DisconnectedError extends Error {}
