"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
exports.authRouter = (authService, errorHandler, router = express_1.Router()) => {
    router.post('/signup', (req, rsp) => {
        const signupData = req.body;
        authService.signup(signupData)
            .then(() => rsp.status(201).send())
            .catch(error => errorHandler.handle(rsp, error));
    });
    router.get('/refresh', (req, rsp) => {
        authService.refresh(req.header('Authorization'))
            .then(userSession => rsp.status(200).send(userSession))
            .catch(error => errorHandler.handle(rsp, error));
    });
    router.post('/login', (req, rsp) => {
        const loginData = req.body;
        authService.login(loginData)
            .then(userSession => rsp.status(201).send(userSession))
            .catch(error => errorHandler.handle(rsp, error));
    });
    return router;
};
