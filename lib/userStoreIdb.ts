import { IDBPDatabase, openDB as openDbIdb } from 'idb';

const DB_NAME = 'millegrilles';
const STORE_USERS = 'usagers';
const STORE_KEYS = 'clesDechiffrees';
const DB_VERSION_CURRENT = 1;
const MAX_AGE_DEFAULT = 6 * 60 * 60 * 1_000;  // 6h in ms

// const STORE_KEYS_FIELDS = ['iv', 'nonce', 'tag', 'header', 'format', 'verification'];

export type UserCertificate = {
    certificate: Array<string>,
    publicKey: Uint8Array,
    privateKey: Uint8Array,
    publicKeyString: string,
};

export type UserCertificateRequest = {
    pem: string,
    publicKey: Uint8Array,
    privateKey: Uint8Array,
    publicKeyString: string,
    privateKeyPem: string,
};

export type UserStoreType = {
    username: string,
    nomUsager?: string,
    // userId?: string,
    certificate?: UserCertificate,
    request?: UserCertificateRequest,
    delegations_version?: number,
    delegations_date?: number,
    // Legacy
    ca?: string;
    certificat?: Array<string>,
    clePriveePem?: string,
};

export async function openDB(upgrade?: boolean): Promise<IDBPDatabase> {
    if(upgrade) {
        return openDbIdb(DB_NAME, DB_VERSION_CURRENT, {
            upgrade(db, oldVersion) {
                createObjectStores(db, oldVersion)
            },
            blocked() {
                console.error("OpenDB %s blocked", DB_NAME)
            },
            blocking() {
                console.warn("OpenDB, blocking")
            }
        });
    } else {
        return openDbIdb(DB_NAME)
    }
}

function createObjectStores(db: IDBPDatabase, oldVersion?: number) {
    switch(oldVersion) {
        // @ts-ignore Fallthrough
        case 0:
            db.createObjectStore(STORE_USERS, {keyPath: 'nomUsager'});
            db.createObjectStore(STORE_KEYS, {keyPath: 'hachage_bytes'});
        // @ts-ignore Fallthrough
        case 1:
        case 2: // Plus recent, rien a faire
            break
        default:
            console.warn("createObjectStores Default..., version %O", oldVersion)
    }
}

export type KeyInfoType = {
    format?: string,
    nonce?: string,
    verification?: string,
    iv?: string,
    tag?: string,
    header?: string,
};

export async function saveDecryptedKey(cleId: string, cleSecrete: Uint8Array, cleInfo: KeyInfoType) {
    let db = await openDbIdb(DB_NAME);

    let data = {
        cleId,
        cleSecrete,
        ...cleInfo,
        date: new Date(),
    };

    await db.transaction(STORE_KEYS, 'readwrite')
        .objectStore(STORE_KEYS)
        .put(data);
}

export type KeyType = {
    keyId: string,
    format?: string,
    nonce?: string,
    verification?: string,
    iv?: string,
    tag?: string,
    header?: string,
};

export async function getKey(keyId: string): Promise<KeyType> {
    const db = await openDB();
    const store = db.transaction(STORE_KEYS, 'readonly').objectStore(STORE_KEYS);
    return await store.get(keyId);
}

export async function getUser(username: string): Promise<UserStoreType | null> {
    let db = await openDB();
    let store = db.transaction(STORE_USERS, 'readonly').objectStore(STORE_USERS);
    return await store.get(username);
}

export async function updateUser(user: UserStoreType) {
    let entry = await getUser(user.username) as UserStoreType;

    let db = await openDB();
    let nomUsager = user.username;  // Ensure there is a field nomUsager (legacy)
    if(!entry) entry = {...user, nomUsager};
    else entry = {...entry, ...user, nomUsager};

    let store = db.transaction(STORE_USERS, 'readwrite').objectStore(STORE_USERS);
    await store.put(entry);
}

// async function lireUsager(db, nomUsager) {
//   const tx = await db.transaction(STORE_USERS, 'readonly')
//   const store = tx.objectStore(STORE_USERS)
//   const resultats = await Promise.all([store.get(nomUsager), tx.done])
//   return resultats[0]
// }

export async function getUsersList(): Promise<Array<string>> {
    let db = await openDB(true);
    let store = db.transaction(STORE_USERS, 'readonly').objectStore(STORE_USERS);
    let users = await store.getAllKeys() as Array<string>;
    users.sort();
    return users;
}

export async function deleteUser(username: string) {
    let db = await openDB(true);
    let store = db.transaction(STORE_USERS, 'readwrite').objectStore(STORE_USERS);
    await store.delete(username);
}

export async function maintenance(username: string, maxAge?: number) {
    if(!username) return;

    maxAge = maxAge || MAX_AGE_DEFAULT;  
    // const expirationDate = new Date(new Date().getTime() - maxAge);

    throw new Error('todo - fix me');

    // await Promise.all([
    //     // entretienCacheClesSecretes(nomUsager, tempsExpiration, opts),
    //     // entretienCacheFichiersDechiffres(tempsExpiration, opts),
    // ])
}

export async function receiveCertificate(username: string, certificate: Array<string>) {
    let ca = certificate.pop();

    let userIdb = await getUser(username);
    let certificateRequest = userIdb?.request;
    if(!certificateRequest) {
        throw new Error("Error during certificate renewal, no active certificate available");
    }

    let certificateEntry = {
        certificate,
        // Transfer request private key and values to the new certificate
        publicKey: certificateRequest.publicKey,
        privateKey: certificateRequest.privateKey,
        publicKeyString: certificateRequest.publicKeyString,
    };
    await updateUser({
        username, certificate: certificateEntry,
        request: undefined, // Remove previous request
        // legacy web apps
        ca, certificat: certificate, clePriveePem: certificateRequest.privateKeyPem,
    });
}

export async function clearCertificate(username: string) {
    await updateUser({
        username, certificate: undefined,
        // legacy web apps
        ca: undefined, certificat: undefined, clePriveePem: undefined,
    });
}

// async function entretienCacheClesSecretes(expirationTime: Date) {
//   const db = await openDB()

//   // console.debug("Entretien table de caches IndexedDB usager (%s), purger elements < %O", nomUsager, tempsExpiration)

//   let cursor = await db.transaction(STORE_KEYS, 'readonly').store.openCursor()
//   const clesExpirees = []
//   while(cursor) {
//     // console.debug("Cle %s = %O", cursor.key, cursor.value)
//     const dateCle = cursor.value.date
//     if(dateCle.getTime() < tempsExpiration) {
//       clesExpirees.push(cursor.key)
//     }
//     cursor = await cursor.continue()  // next
//   }

//   if(clesExpirees.length > 0) {
//     // console.debug("Nettoyage de %d cles expirees", clesExpirees.length)
//     const txUpdate = await db.transaction(STORE_KEYS, 'readwrite')
//     const storeUpdate = txUpdate.objectStore(STORE_KEYS)
//     const promises = clesExpirees.map(cle=>{
//       return storeUpdate.delete(cle)
//     })
//     promises.push(txUpdate.done)  // Marqueur de fin de transaction
//     await Promise.all(promises)
//     // console.debug("Nettoyage cles complete")
//   }
// }

// async function entretienCacheFichiersDechiffres(tempsExpiration, opts) {
//   const cache = await caches.open('fichiersDechiffres')
//   const keys = await cache.keys()
//   for await (let key of keys) {
//     const cacheObj = await cache.match(key)
//     const headers = {}
//     for await(let h of cacheObj.headers.entries()) {
//       headers[h[0]] = h[1]
//     }

//     // Utiliser header special 'date' injecte par consignationfichiers
//     let tempsCache = 0
//     try { tempsCache = new Date(headers.date).getTime() } catch(err) {/*OK*/}

//     // console.debug("Cache %s = %O date %s (Headers: %O)", key, cacheObj, tempsCache, headers)
//     if(tempsCache < tempsExpiration) {
//       // console.debug("Nettoyer fichier dechiffre expire : %s", key)
//       await cache.delete(key)
//     }
//   }
// }

export async function clearKeys() {
    const db = await openDB();
    const store = db.transaction(STORE_KEYS, 'readwrite').store;
    await store.clear();
}

export async function clearUserCertificate(username: string) {
    let entry = await getUser(username);
    if(!entry) return; // Unknown user, nothing to do
    if(!entry.certificate) return;  // No certificate, nothing to do

    const updatedEntry = {
        ...entry, 
        certificate: null, request: null,
        // Legacy
        clePriveePem: null, ca: null, certificat: null,
    };
  
    const db = await openDB();
    const store = db.transaction(STORE_USERS, 'readwrite').objectStore(STORE_USERS);
    await store.put(updatedEntry);
}
