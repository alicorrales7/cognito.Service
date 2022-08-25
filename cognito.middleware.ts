import axios from "axios";
import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";
import { Service } from "typedi";
import { CognitoJwtVerifier } from 'cognito-jwt-verify';

let pems: Array<string> = [];
@Service()
class AuthMiddleware {
  private poolRegion = "us-east-1";
  private userPoolId = "us-east-1_mAh9e0R95";
  private clientId = "7j8kd7m5nbbpbkvdo6jtq8r4j3"; 

  constructor() {
    this.setUp();
  }

  async veryfyToken(req: Request, res: Response, next: NextFunction){
    const token = req.header("Auth") as string;
    if (!token) res.status(401).json({message: "Emty  token "});

    const decodeJwt: any = jwt.decode(token, { complete: true });
    if (!decodeJwt) {
      res.status(401).json({message: "Emty decodeJWT "});
    }
    let kid = decodeJwt.header.kid;
    let payload = decodeJwt.payload;
    
    // const verifier = new CognitoJwtVerifier("us-east-1","us-east-1_mAh9e0R95","7j8kd7m5nbbpbkvdo6jtq8r4j3",false)
    //   console.log(verifier)
    //   const pay = await verifier.verify(
    //     token
    //   );
    //   console.log(pay);
    // try {
      
    //   console.log("Token is valid. Payload:", payload);
    // } catch {
    //   console.log("Token not valid!");
    // }
    

      next();

    };
  

  private async setUp() {
    const URL =
      "https://cognito-idp." +
      this.poolRegion +
      ".amazonaws.com/" +
      this.userPoolId +
      "/.well-known/jwks.json";

    try {
      const { data, status } = await axios.get(URL, {
        headers: {
          Accept: "application/json",
        },
      });
      
      if (status !== 200) { throw 'request failed'}

      const datas = data.keys;
      const keys: any[] = datas;
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const key_id = key.key_id;
        const modulus = key.n;
        const exponent = key.e;
        const key_type = key.kty;
        const jwk = { kty: key_type, n: modulus, e: exponent };
        const pem = jwkToPem(jwk);
        pems[key_id] = pem;
      }
      console.log("got all pems");
    } catch (erros) {
      console.log("sorry could not fetch jwk");
    }
  }
}

export default AuthMiddleware;