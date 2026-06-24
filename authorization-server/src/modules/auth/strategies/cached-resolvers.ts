import {
  IIssuerDefinition,
  IRevokerDefinition,
  RoleCredentialSubject,
} from '@energyweb/credential-governance';
import {
  IssuerResolver,
  RevokerResolver,
  CredentialResolver,
  RoleEIP191JWT,
  VerifiableCredential,
  IRoleCredentialCache,
  IDIDDocumentCache,
  IRoleDefinitionCache,
  isCID,
  isEIP191Jwt,
  isVerifiableCredential,
  transformClaim,
  filterOutMaliciousClaims,
} from '@energyweb/vc-verification';
import { IDIDDocument } from '@ew-did-registry/did-resolver-interface';
import { IDidStore } from '@ew-did-registry/did-store-interface';
import { CacheServerClient } from 'passport-did-auth/dist/lib/cacheServerClient';
import { Logger } from 'passport-did-auth/dist/lib/Logger';
import { decode } from 'jsonwebtoken';
import { utils } from 'ethers';

export class CachedIssuerResolver implements IssuerResolver {
  constructor(private readonly cacheServerClient: CacheServerClient) {}

  async getIssuerDefinition(
    namespace: string,
    roleDefCache?: IRoleDefinitionCache,
  ): Promise<IIssuerDefinition | undefined> {
    const cachedRoleDefinition = roleDefCache?.getRoleDefinition(namespace);
    if (cachedRoleDefinition) return cachedRoleDefinition.issuer;

    if (!this.cacheServerClient.isAvailable) {
      throw new Error(
        `[Cache Only] SSI-Hub Cache Server unavailable. Cannot resolve issuer for ${namespace}.`,
      );
    }

    const roleDef = await this.cacheServerClient.getRoleDefinition({
      namespace,
    });
    if (!roleDef) {
      throw new Error(
        `Role Definition for ${namespace} not found in Identity Cache.`,
      );
    }

    Logger.info(
      `IIssuerDefinition for namespace: ${namespace} fetched strictly from SSI-Hub`,
    );
    roleDefCache?.setRoleDefinition(namespace, roleDef);
    return roleDef.issuer;
  }
}

export class CachedRevokerResolver implements RevokerResolver {
  constructor(private readonly cacheServerClient: CacheServerClient) {}

  async getRevokerDefinition(
    namespace: string,
    roleDefCache?: IRoleDefinitionCache,
  ): Promise<IRevokerDefinition | undefined> {
    const cachedRoleDefinition = roleDefCache?.getRoleDefinition(namespace);
    if (cachedRoleDefinition) return cachedRoleDefinition.revoker;

    if (!this.cacheServerClient.isAvailable) {
      throw new Error(
        `[Cache Only] SSI-Hub Cache Server unavailable. Cannot resolve revoker for ${namespace}.`,
      );
    }

    const roleDef = await this.cacheServerClient.getRoleDefinition({
      namespace,
    });
    if (!roleDef) {
      throw new Error(
        `Role Definition for ${namespace} not found in Identity Cache.`,
      );
    }

    roleDefCache?.setRoleDefinition(namespace, roleDef);
    return roleDef.revoker;
  }
}

export class CachedCredentialResolver implements CredentialResolver {
  constructor(
    private readonly cacheServerClient: CacheServerClient,
    private readonly didStore: IDidStore,
  ) {}

  async getDIDDocument(
    did: string,
    didDocumentCache?: IDIDDocumentCache,
  ): Promise<IDIDDocument> {
    let resolvedDIDDocument = didDocumentCache?.getDIDDocument(did);
    if (resolvedDIDDocument) return resolvedDIDDocument;

    if (!this.cacheServerClient.isAvailable) {
      throw new Error(
        `[Cache Only] Cache Server unavailable. Cannot resolve DID Document for ${did}.`,
      );
    }

    resolvedDIDDocument = await this.cacheServerClient.getDidDocument(did);
    didDocumentCache?.setDIDDocument(did, resolvedDIDDocument);
    return resolvedDIDDocument;
  }

  async eip191JwtsOf(
    did: string,
    didDocumentCache?: IDIDDocumentCache,
  ): Promise<RoleEIP191JWT[]> {
    if (!this.cacheServerClient.isAvailable) {
      throw new Error(
        `[Cache Only] Cache Server unavailable. Cannot resolve credentials for ${did}.`,
      );
    }

    const didDocument = await this.getDIDDocument(did, didDocumentCache);
    const services = didDocument.service?.map((s) => s.serviceEndpoint) || [];

    const resolved = await this.resolveFromDidStoreBatch(services);

    return resolved
      .filter((claimToken) => claimToken.split('.').length === 3)
      .map((claimToken) => ({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        payload: decode(claimToken) as any,
        eip191Jwt: claimToken,
      }))
      .filter(isEIP191Jwt)
      .map(transformClaim)
      .filter(filterOutMaliciousClaims);
  }

  async credentialsOf(
    did: string,
    didDocumentCache?: IDIDDocumentCache,
  ): Promise<VerifiableCredential<RoleCredentialSubject>[]> {
    if (!this.cacheServerClient.isAvailable) {
      throw new Error(
        `[Cache Only] Cache Server unavailable. Cannot resolve credentials for ${did}.`,
      );
    }

    const didDocument = await this.getDIDDocument(did, didDocumentCache);
    const services = didDocument.service?.map((s) => s.serviceEndpoint) || [];

    const resolved = await this.resolveFromDidStoreBatch(services);

    return resolved
      .filter((cred) => cred.split('.').length !== 3)
      .map((cred) => {
        try {
          return JSON.parse(cred);
        } catch (e) {
          Logger.error(
            `Error parsing VC credential from didStore: ${e.message}`,
          );
          return null;
        }
      })
      .filter(isVerifiableCredential);
  }

  async getCredential(
    did: string,
    namespace: string,
    roleCredentialCache?: IRoleCredentialCache,
    didDocumentCache?: IDIDDocumentCache,
  ): Promise<
    VerifiableCredential<RoleCredentialSubject> | RoleEIP191JWT | undefined
  > {
    const cachedRoleCredential = roleCredentialCache?.getRoleCredential(
      did,
      namespace,
    );
    if (cachedRoleCredential) {
      return cachedRoleCredential;
    }

    let credential:
      | VerifiableCredential<RoleCredentialSubject>
      | RoleEIP191JWT
      | undefined = await this.getVerifiableCredential(
      did,
      namespace,
      roleCredentialCache,
      didDocumentCache,
    );
    if (!credential) {
      credential = await this.getEIP191JWT(
        did,
        namespace,
        roleCredentialCache,
        didDocumentCache,
      );
    }
    return credential;
  }

  async getVerifiableCredential(
    did: string,
    namespace: string,
    roleCredentialCache?: IRoleCredentialCache,
    didDocumentCache?: IDIDDocumentCache,
  ): Promise<VerifiableCredential<RoleCredentialSubject> | undefined> {
    const cachedRoleCredential = roleCredentialCache?.getRoleCredential(
      did,
      namespace,
    );
    if (isVerifiableCredential(cachedRoleCredential)) {
      return cachedRoleCredential;
    }

    const credentials = await this.credentialsOf(did, didDocumentCache);
    credentials.forEach((credential) =>
      roleCredentialCache?.setRoleCredential(
        did,
        credential.credentialSubject.role.namespace,
        credential,
      ),
    );

    return credentials.find(
      (claim) =>
        claim.credentialSubject.role.namespace === namespace ||
        utils.namehash(claim.credentialSubject.role.namespace) === namespace,
    );
  }

  async getEIP191JWT(
    did: string,
    namespace: string,
    roleCredentialCache?: IRoleCredentialCache,
    didDocumentCache?: IDIDDocumentCache,
  ): Promise<RoleEIP191JWT | undefined> {
    const cachedRoleCredential = roleCredentialCache?.getRoleCredential(
      did,
      namespace,
    );
    if (isEIP191Jwt(cachedRoleCredential)) {
      return cachedRoleCredential;
    }

    const eip191Jwts = await this.eip191JwtsOf(did, didDocumentCache);
    eip191Jwts.forEach((eip191Jwt) => {
      const claimType = eip191Jwt?.payload?.claimData?.claimType;
      if (claimType) {
        roleCredentialCache?.setRoleCredential(did, claimType, eip191Jwt);
      }
    });

    return eip191Jwts.find(
      (jwt) =>
        jwt?.payload?.claimData?.claimType === namespace ||
        utils.namehash(jwt?.payload?.claimData?.claimType) === namespace,
    );
  }

  private async resolveFromDidStoreBatch(
    services: string[],
  ): Promise<string[]> {
    const batchSize = 10;
    const results: string[] = [];
    for (let i = 0; i < services.length; i += batchSize) {
      const batch = services.slice(i, i + batchSize);
      const resolvedBatch = await Promise.allSettled(
        batch.filter(isCID).map((service) => this.didStore.get(service)),
      );
      for (const r of resolvedBatch) {
        if (r.status === 'fulfilled' && r.value) {
          results.push(r.value);
        }
      }
    }
    return results;
  }
}
