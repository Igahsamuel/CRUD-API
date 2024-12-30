import { Column, Entity, ManyToOne, PrimaryColumn } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { User } from './User';

@Entity()
export class QRcode {
  @PrimaryColumn()
  id: string = uuidv4();
  @Column({ type: 'bytea' })
  image!: Buffer;
  @ManyToOne(() => User, (user) => user.buffer, {
    onDelete: 'CASCADE',
  })
  user!: User;
}
