import { Entity, PrimaryColumn, Column, ManyToOne } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { User } from './User';

@Entity()
export class BlackListToken {
  @PrimaryColumn({ default: uuidv4() })
  id: string = uuidv4();
  @Column()
  token!: string;
  @Column()
  expiration!: Date;
  @ManyToOne(() => User, (user) => user.blackListToken, {
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    nullable: false,
    orphanedRowAction: 'delete',
  })
  user!: User;
}
