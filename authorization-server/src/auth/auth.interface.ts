export interface IDidAccessTokenPayload {
  did: string;
  verifiedRoles: { name: string; namespace: string }[];
}

export interface IGenerateAccessTokenPayload {
  did: string;
  roles: string[];
}

export interface IGenerateRefreshTokenPayload {
  did: string;
  roles: string[];
}

export interface IAccessTokenPayload {
  id: string;
  did: string;
  roles: string[];
  iat: number;
  exp: number;
}

export interface IRefreshTokenPayload {
  id: string;
  did: string;
  roles: string[];
  iat: number;
  exp: number;
}
