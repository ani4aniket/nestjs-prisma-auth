import { PrismaService } from 'prisma/prisma.service';
import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async getMyUser(id: string) {
    return { id };
  }

  async getUsers() {
    return await this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
      },
    });
  }
}
