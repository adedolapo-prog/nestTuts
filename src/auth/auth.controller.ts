import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './Dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  login(@Body() auth: AuthDto) {
    return this.authService.login(auth);
  }

  @Post('signup')
  signup(@Body() auth: AuthDto) {
    return this.authService.signup(auth);
  }
}
