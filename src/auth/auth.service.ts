import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './Dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async login(auth: AuthDto): Promise<any> {
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

      //return user
      user.hash = undefined;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }

  async signup(auth: AuthDto): Promise<any> {
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

      user.hash = undefined;

      //return saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }
}
