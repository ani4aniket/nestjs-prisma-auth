import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  constructor() {}

  async signup() {
    return { message: 'signup was successful' };
  }
  async signin() {
    return { message: 'signin was successful' };
  }
  async signout() {
    return { message: 'signout was successful' };
  }
}
