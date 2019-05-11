import { ErrorHandler } from 'ts-common-server';
import { AuthService } from "../auth/AuthService";
import { Router, Request, Response } from "express";
import { SignupData } from "../SignupData";
import { LoginData } from "../LoginData";
import { LogoutData } from '../login/LogoutData';

export const authRouter = (authService: AuthService,
  errorHandler: ErrorHandler,
  router: Router = Router()): Router => {

  router.post('/signup', async (req: Request, rsp: Response) => {
    try {
      const signupData = <SignupData>req.body;
      await authService.signup(signupData);
      rsp.status(201).send();
    } catch (error) {
      errorHandler.handle(rsp, error)
    }
  });

  router.get('/refresh', async (req: Request, rsp: Response) => {
    try {
      const userSession = await authService.refresh(req.header('Authorization'));
      rsp.status(200).send(userSession);
    } catch (error) {
      errorHandler.handle(rsp, error);
    }
  });

  router.post('/login', async (req: Request, rsp: Response) => {
    try {
      const loginData = <LoginData>req.body;
      const userSession = await authService.login(loginData);
      rsp.status(201).send(userSession);
    } catch (error) {
      errorHandler.handle(rsp, error);
    }
  });

  router.post('/logout', async (req: Request, rsp: Response) => {
    try {
      await authService.logout(req.header('Authorization'));
      rsp.status(200).send();
    } catch (error) {
      errorHandler.handle(rsp, error);
    }
  });

  return router;
}