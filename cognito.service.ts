import AWS from "aws-sdk";
import crypto from "crypto";
import { Service } from "typedi";

@Service()
class CognitoService {
  private config = {
    region: "us-east-1",
  };
  private secretHash = "";
  private clientId = "7j8kd7m5nbbpbkvdo6jtq8r4j3";
  private cognitoIdentity;

  constructor() {
    this.cognitoIdentity = new AWS.CognitoIdentityServiceProvider(this.config);
  }

  public async singUpUser(
    username: string,
    password: string,
    userAttr: Array<any>
  ):Promise<boolean> {

    const params = {
      ClientId: this.clientId,
      Password: password,
      Username: username,
      SecretHash: this.generateHash(username),
      UserAttributes: userAttr,
    };

    try {
      const data = await this.cognitoIdentity.signUp(params).promise();
      console.log(data + "Here");
      return true;
    } catch (error) {
      console.log(error);
      return false;
    }
  }

  public async verifyAccount(username: string, code: string): Promise<boolean> {
    const params = {
      ClientId: this.clientId,
      ConfirmationCode: code,
      SecretHash: this.generateHash(username),
      Username: username,
    };
    try {
      await this.cognitoIdentity.confirmSignUp(params).promise();
      return true;
    } catch (error) {
      console.log(error);
      return false;
    }
  }

  public async signInUser(
    username: string,
    password: string
  ): Promise<boolean|AWS.CognitoIdentityServiceProvider.InitiateAuthResponse| AWS.AWSError> {
    const params = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: this.clientId,
      AuthParameters: {
        'USERNAME': username,
        'PASSWORD': password,
        'SERCRET_HASH': this.generateHash(username)
      },
    };
    try {
      const data = await this.cognitoIdentity.initiateAuth(params).promise();
      console.log(data);
      return data;
    } catch (error) {
      console.log(error);
      return false;
    }
  }

  private generateHash(username: string): string {
    return crypto
      .createHmac("SHA256", this.secretHash)
      .update(username + this.clientId)
      .digest("base64");
  }
}

export default CognitoService;
