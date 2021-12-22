import * as Crypto from 'crypto';

const verifiers: { state: string; codeVerifier: string }[] = [];

/**
 * Response of get access token
 */
interface GetAccessTokenResponse{
    access_token:string,
    token_type:string,
    expires_in:number,
    refresh_token:number
}

class EtsyClient {
  private apiKey: string;
  private apiSecret: string;
  private apiScope: string;
  private redirectUri: string;
  readonly BASE_URL = 'https://openapi.etsy.com';

  constructor(apiKey: string, apiSecret: string, apiScope: string, redirectUri: string) {
    this.apiKey = apiKey;
    this.apiSecret = apiSecret;
    this.apiScope = apiScope;
    this.redirectUri = redirectUri;
  }

  generateUserAuthorizationUrl = () => {
    const base64URLEncode = (str: Buffer) => {
      return str
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    };

    const sha256 = (buffer: string) =>
      Crypto.createHash('sha256')
        .update(buffer)
        .digest();

    const codeVerifier = base64URLEncode(Crypto.randomBytes(32));

    const codeChallenge = base64URLEncode(sha256(codeVerifier));

    const state = Math.random()
      .toString(36)
      .substring(7);

    verifiers.push({ state, codeVerifier });
    return `https://www.etsy.com/oauth/connect?response_type=code&redirect_uri=${this.redirectUri}&scope=${
      this.apiScope
    }&client_id=${this.apiKey}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  };

  /**
   * @name getAccessToken
   * @param {string} code 
   * @param {string} state 
   * @returns {GetAccessTokenResponse}
   */
  getAccessToken = async (code: string, state: string):Promise<GetAccessTokenResponse|undefined> => {
    const tokenUrl = 'https://api.etsy.com/v3/public/oauth/token';
    const requestOptions = {
      method: 'POST',
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: this.apiKey,
        redirect_uri: this.redirectUri,
        code: code,
        code_verifier: verifiers.find(item=>item.state === state)?.codeVerifier,
      }),
      headers: {
        'Content-Type': 'application/json',
      },
    };
    
    const response = await fetch(tokenUrl, requestOptions);

    if (response.ok) {
        const tokenData:GetAccessTokenResponse = await response.json();
        return tokenData
    }
  };

  
}

export default EtsyClient;
