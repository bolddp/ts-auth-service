export declare enum UserGroup {
    Guest = 0,
    User = 1,
    SiteAdmin = 2
}
export declare class TokenInfo {
    isExpired: boolean;
    isValid: boolean;
    userName: string;
    group: UserGroup;
}
