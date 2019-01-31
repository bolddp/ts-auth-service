"use strict";
// export * from './AuthService';
// export * from './AwsAuthService';
function __export(m) {
    for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
}
Object.defineProperty(exports, "__esModule", { value: true });
var Claim;
(function (Claim) {
    Claim[Claim["Read"] = 0] = "Read";
    Claim[Claim["Create"] = 1] = "Create";
    Claim[Claim["Update"] = 2] = "Update";
    Claim[Claim["Delete"] = 3] = "Delete";
})(Claim = exports.Claim || (exports.Claim = {}));
;
__export(require("./auth/AuthError"));
__export(require("./auth/AwsAuthService"));
__export(require("./router/authRouter"));
__export(require("./TokenInfo"));
