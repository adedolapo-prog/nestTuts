import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  login(): string {
    return 'I am logged in';
  }
  signup(): string {
    return 'I have signed up';
  }
}
