import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToMany,
  ManyToOne,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { User } from './User';

@Entity()
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id!: string;
  @Column()
  token!: string;
  @Column()
  expiration!: Date;
  @ManyToOne(() => User, (user) => user.refreshToken, { onDelete: 'CASCADE' })
  user!: User;
}
