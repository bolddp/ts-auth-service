"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
exports.authRouter = (authService, errorHandler, router = express_1.Router()) => {
    router.post('/signup', (req, rsp) => __awaiter(this, void 0, void 0, function* () {
        try {
            const signupData = req.body;
            yield authService.signup(signupData);
            rsp.status(201).send();
        }
        catch (error) {
            errorHandler.handle(rsp, error);
        }
    }));
    router.get('/refresh', (req, rsp) => __awaiter(this, void 0, void 0, function* () {
        try {
            const userSession = yield authService.refresh(req.header('Authorization'));
            rsp.status(200).send(userSession);
        }
        catch (error) {
            errorHandler.handle(rsp, error);
        }
    }));
    router.post('/login', (req, rsp) => __awaiter(this, void 0, void 0, function* () {
        try {
            const loginData = req.body;
            const userSession = yield authService.login(loginData);
            rsp.status(201).send(userSession);
        }
        catch (error) {
            errorHandler.handle(rsp, error);
        }
    }));
    router.post('/logout', (req, rsp) => __awaiter(this, void 0, void 0, function* () {
        try {
            yield authService.logout(req.header('Authorization'));
            rsp.status(200).send();
        }
        catch (error) {
            errorHandler.handle(rsp, error);
        }
    }));
    return router;
};
