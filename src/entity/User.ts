import { Entity, Column, PrimaryColumn, OneToMany } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { RefreshToken } from './RefreshToken';

@Entity()
export class User {
  @PrimaryColumn({ default: uuidv4() })
  id: string = uuidv4();
  @Column()
  name!: string;
  @Column()
  password!: string;
  @Column()
  passwordConfirm!: string;
  @Column()
  email!: string;
  @Column({ default: 'user' })
  role!: string;
  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshToken!: RefreshToken[];
}
