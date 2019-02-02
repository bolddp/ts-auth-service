import { ErrorHandler } from 'ts-common-server';
import { AuthService } from "../auth/AuthService";
import { Router, Request, Response } from "express";
import { SignupData } from "../SignupData";
import { LoginData } from "../LoginData";

export const authRouter = (authService: AuthService,
  errorHandler: ErrorHandler,
  router: Router = Router()) : Router => {

  router.post('/signup', (req: Request, rsp: Response) => {
    const signupData = <SignupData>req.body;
    authService.signup(signupData)
      .then(() => rsp.status(201).send())
      .catch(error => errorHandler.handle(rsp, error));
  });

  router.get('/refresh', (req: Request, rsp: Response) => {
    authService.refresh(req.header('Authorization'))
      .then(userSession => rsp.status(200).send(userSession))
      .catch(error => errorHandler.handle(rsp, error));
  });

  router.post('/login', (req: Request, rsp: Response) => {
    const loginData = <LoginData>req.body;
    authService.login(loginData)
      .then(userSession => rsp.status(201).send(userSession))
      .catch(error => errorHandler.handle(rsp, error));
  });

  return router;
}