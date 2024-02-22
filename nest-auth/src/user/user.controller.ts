import { BadRequestException, Body, Controller, Get, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { UserService } from './user.service';
import * as bcryptjs from 'bcryptjs'
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';

@Controller()
export class UserController {

    constructor(
        private userService: UserService,
        private jwtService: JwtService
    ){}
    @Post('register')
    async register(@Body() body: any)
    {
        if(body.password !== body.password_confirm)
            throw new BadRequestException('Password not match...')
      
            return this.userService.save({
                first_name: body.first_name,
                last_name: body.last_name,
                email: body.email,
                password: await bcryptjs.hash(body.password, 12),
            });

    }

    @Post('login')
    async login(
        @Body('email') email: string,
        @Body('password') password: string,    
        @Res({passthrough: true}) response : Response    
    ) {
        const user = await this.userService.findOne({email:email});

        if(!user)
        {
            throw new BadRequestException('Invalid Credentials mail')
        }

        if(!await bcryptjs.compare(password, user.password))
        {
            throw new BadRequestException('Invalid Credentials')
        }

        const accessToken = await this.jwtService.signAsync({
            id: user.id
        }, {expiresIn: '1000s'});
       

        const refreshToken = await this.jwtService.signAsync({
            id: user.id
        });

        response.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            maxAge:7*24*60*60*1000
        })

        return {
            token: accessToken
        }
    }

    @Get('user')
    async user(
        @Req() request: Request
    ){
        try {
            const accessToken =  request.headers.authorization?.split(' ')[1]
            const {id} = await this.jwtService.verifyAsync(accessToken);
            const {password, ...data} = await this.userService.findOne({id});
            return data;
        } catch (error) {
            throw new UnauthorizedException();
        }
    }
}
