import { Entity, Column, PrimaryColumn, ManyToOne } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { User } from './User';

@Entity()
export class RefreshToken {
  @PrimaryColumn({ default: uuidv4() })
  id: string = uuidv4();
  @Column()
  token!: string;
  @Column()
  expiration!: Date;
  @ManyToOne(() => User, (user) => user.refreshToken, {
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    nullable: false,
    orphanedRowAction: 'delete',
  })
  user!: User;
}
