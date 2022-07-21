import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './Dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async login(auth: AuthDto): Promise<{ access_token: string }> {
    try {
      const { email, password } = auth;

      //find user by email
      const user = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });
      //if no user, throw exception
      if (!user) throw new ForbiddenException('Credentials incorrect');

      //compare password
      const pwMatch = await argon.verify(user.hash, password);
      //if wrong password, throw error
      if (!pwMatch) throw new ForbiddenException('Credentials incorrect');

      const token = this.signToken(user.id, user.email);
      return token;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }

  async signup(auth: AuthDto): Promise<{ access_token: string }> {
    try {
      const { email, password } = auth;
      //generate our password hash
      const hash = await argon.hash(password);

      //save new user to the db
      const user = await this.prisma.user.create({
        data: {
          email,
          hash,
        },
      });

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    });

    return { access_token: token };
  }
}
