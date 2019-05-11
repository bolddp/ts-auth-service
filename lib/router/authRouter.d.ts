import { ErrorHandler } from 'ts-common-server';
import { AuthService } from "../auth/AuthService";
import { Router } from "express";
export declare const authRouter: (authService: AuthService, errorHandler: ErrorHandler, router?: Router) => Router;
