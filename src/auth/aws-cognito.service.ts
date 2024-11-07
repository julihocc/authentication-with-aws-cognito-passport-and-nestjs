import { Injectable } from '@nestjs/common';
import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  InitiateAuthCommand,
  ChangePasswordCommand,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
  AuthFlowType,
} from '@aws-sdk/client-cognito-identity-provider';
import { AuthChangePasswordUserDto } from './dtos/auth-change-password-user.dto';
import { AuthLoginUserDto } from './dtos/auth-login-user.dto';
import { AuthRegisterUserDto } from './dtos/auth-register-user.dto';
import { AuthConfirmPasswordUserDto } from './dtos/auth-confirm-password-user.dto';
import { AuthForgotPasswordUserDto } from './dtos/auth-forgot-password-user.dto';

@Injectable()
export class AwsCognitoService {
  private cognitoClient: CognitoIdentityProviderClient;
  private userPoolId: string;
  private clientId: string;

  constructor() {
    this.cognitoClient = new CognitoIdentityProviderClient({});
    this.userPoolId = process.env.AWS_COGNITO_USER_POOL_ID;
    this.clientId = process.env.AWS_COGNITO_CLIENT_ID;
  }

  async registerUser(authRegisterUserDto: AuthRegisterUserDto) {
    const { name, email, password } = authRegisterUserDto;
    console.log(name, email, password);

    const command = new SignUpCommand({
      ClientId: this.clientId,
      Username: email,
      Password: password,
      UserAttributes: [
        {
          Name: 'name',
          Value: name,
        },
      ],
    });

    try {
      const result = await this.cognitoClient.send(command);
      console.log('result.user', result);
      return result;
    } catch (err) {
      throw err;
    }
  }

  async authenticateUser(authLoginUserDto: AuthLoginUserDto) {
    const { email, password } = authLoginUserDto;

    const command = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
      ClientId: this.clientId,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
      },
    });

    try {
      const result = await this.cognitoClient.send(command);
      return {
        accessToken: result.AuthenticationResult.AccessToken,
        refreshToken: result.AuthenticationResult.RefreshToken,
      };
    } catch (err) {
      console.error(`Error: ${err}`);
      throw err;
    }
  }

  async changeUserPassword(
    authChangePasswordUserDto: AuthChangePasswordUserDto,
  ) {
    const { email, currentPassword, newPassword } = authChangePasswordUserDto;

    const authCommand = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
      ClientId: this.clientId,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: currentPassword,
      },
    });

    try {
      const authResult = await this.cognitoClient.send(authCommand);
      const accessToken = authResult.AuthenticationResult.AccessToken;

      const changePasswordCommand = new ChangePasswordCommand({
        AccessToken: accessToken,
        PreviousPassword: currentPassword,
        ProposedPassword: newPassword,
      });

      const result = await this.cognitoClient.send(changePasswordCommand);
      return result;
    } catch (err) {
      throw err;
    }
  }

  async forgotUserPassword(
    authForgotPasswordUserDto: AuthForgotPasswordUserDto,
  ) {
    const { email } = authForgotPasswordUserDto;

    const command = new ForgotPasswordCommand({
      ClientId: this.clientId,
      Username: email,
    });

    try {
      const result = await this.cognitoClient.send(command);
      return result;
    } catch (err) {
      throw err;
    }
  }

  async confirmUserPassword(
    authConfirmPasswordUserDto: AuthConfirmPasswordUserDto,
  ) {
    const { email, confirmationCode, newPassword } = authConfirmPasswordUserDto;

    const command = new ConfirmForgotPasswordCommand({
      ClientId: this.clientId,
      Username: email,
      ConfirmationCode: confirmationCode,
      Password: newPassword,
    });

    try {
      await this.cognitoClient.send(command);
      return { status: 'success' };
    } catch (err) {
      throw err;
    }
  }
}
