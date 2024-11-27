import { MigrationInterface, QueryRunner } from 'typeorm';

export class BlackListToken1732674013612 implements MigrationInterface {
  name = 'BlackListToken1732674013612';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "refresh_token" DROP CONSTRAINT "FK_8e913e288156c133999341156ad"`
    );
    await queryRunner.query(
      `CREATE TABLE "black_list_token" ("id" character varying NOT NULL DEFAULT '68b6f141-77ac-4a08-b994-248eb2191a00', "token" character varying NOT NULL, "expiration" TIMESTAMP NOT NULL, "userId" character varying NOT NULL, CONSTRAINT "PK_b2eb1b18d76da0cb9d9311f5bfb" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" ALTER COLUMN "id" SET DEFAULT '96b6a2c1-866b-4c68-b2f8-a8dc3e13e6a5'`
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "id" SET DEFAULT '142d0168-4464-42e0-b367-c4461c9d0769'`
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" ADD CONSTRAINT "FK_8e913e288156c133999341156ad" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE`
    );
    await queryRunner.query(
      `ALTER TABLE "black_list_token" ADD CONSTRAINT "FK_eb95e35c5e28e037df8883641d7" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "black_list_token" DROP CONSTRAINT "FK_eb95e35c5e28e037df8883641d7"`
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" DROP CONSTRAINT "FK_8e913e288156c133999341156ad"`
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "id" SET DEFAULT '57b365a3-3eee-4b4d-992e-76cb1724b6a1'`
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" ALTER COLUMN "id" SET DEFAULT '266d6b16-90b0-4b88-b9d3-359adbfd62aa'`
    );
    await queryRunner.query(`DROP TABLE "black_list_token"`);
    await queryRunner.query(
      `ALTER TABLE "refresh_token" ADD CONSTRAINT "FK_8e913e288156c133999341156ad" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }
}
