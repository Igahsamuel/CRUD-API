import { Entity, Column, PrimaryColumn, OneToMany } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { RefreshToken } from './RefreshToken';
import { BlackListToken } from './BlackListToken';
import { QRcode } from './QRcode';

@Entity()
export class User {
  @PrimaryColumn()
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
  @Column({ type: 'boolean', nullable: true })
  faEnable!: boolean | null;
  @Column({ type: 'text', nullable: true })
  twoFaSecret!: string | null;
  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshToken!: RefreshToken[];
  @OneToMany(() => BlackListToken, (blackListToken) => blackListToken.user)
  blackListToken!: BlackListToken[];
  @OneToMany(() => QRcode, (buffer) => buffer.user)
  buffer!: QRcode[];
}
