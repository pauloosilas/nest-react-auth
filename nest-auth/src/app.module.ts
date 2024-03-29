import { Module } from '@nestjs/common';

import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './user/user.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: 'localhost',
      port: 3306,
      username: 'root',
      password: 'Pauloosilas@1',
      database: 'nestauth',
      autoLoadEntities: true,
      synchronize: true
    }),
    UserModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
