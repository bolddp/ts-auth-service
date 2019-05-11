export interface LoginData {
    loginProvider: LoginProviderEnum;
    accessToken?: string;
    userName?: string;
    password?: string;
}
export declare enum LoginProviderEnum {
    AwsCognito = "aws_cognito",
    Facebook = "facebook",
    Google = "google"
}
