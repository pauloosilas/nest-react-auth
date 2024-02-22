import { UserService } from './user.service';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
export declare class UserController {
    private userService;
    private jwtService;
    constructor(userService: UserService, jwtService: JwtService);
    register(body: any): Promise<any>;
    login(email: string, password: string, response: Response): Promise<{
        token: string;
    }>;
    user(request: Request): Promise<{
        id: number;
        first_name: string;
        last_name: string;
        email: string;
    }>;
}
