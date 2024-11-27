import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { User } from './entity/User';
import dotenv from 'dotenv';
import { RefreshToken } from './entity/RefreshToken';
import { BlackListToken } from './entity/BlackListToken';

dotenv.config();

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DATABASE,
  entities: [User, RefreshToken, BlackListToken],
  synchronize: false,
  migrations: ['./src/database/migration/**/*.ts'],
  logging: true,
});
