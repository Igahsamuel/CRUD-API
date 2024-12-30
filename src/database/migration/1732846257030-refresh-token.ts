import { MigrationInterface, QueryRunner } from 'typeorm';

export class RefreshToken1732846257030 implements MigrationInterface {
  name = 'RefreshToken1732846257030';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "refresh_token" ("id" character varying NOT NULL DEFAULT '3fe54031-9046-4a3b-a183-86957895ce72', "token" character varying NOT NULL, "expiration" TIMESTAMP NOT NULL, "userId" character varying NOT NULL, CONSTRAINT "PK_b575dd3c21fb0831013c909e7fe" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE TABLE "black_list_token" ("id" character varying NOT NULL DEFAULT '9c1d909a-1879-41b8-8c21-02a8f82a0d63', "token" character varying NOT NULL, "expiration" TIMESTAMP NOT NULL, "userId" character varying NOT NULL, CONSTRAINT "PK_b2eb1b18d76da0cb9d9311f5bfb" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE TABLE "q_rcode" ("id" character varying NOT NULL, "image" bytea NOT NULL, "userId" character varying, CONSTRAINT "PK_5b59ea2cb3507f14de1c0409b0a" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(`ALTER TABLE "user" ADD "faEnable" boolean`);
    await queryRunner.query(`ALTER TABLE "user" ADD "twoFaSecret" text`);
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "id" DROP DEFAULT`
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" ADD CONSTRAINT "FK_8e913e288156c133999341156ad" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE`
    );
    await queryRunner.query(
      `ALTER TABLE "black_list_token" ADD CONSTRAINT "FK_eb95e35c5e28e037df8883641d7" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE`
    );
    await queryRunner.query(
      `ALTER TABLE "q_rcode" ADD CONSTRAINT "FK_4bbee1fce3b6b8a097f84885d02" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "q_rcode" DROP CONSTRAINT "FK_4bbee1fce3b6b8a097f84885d02"`
    );
    await queryRunner.query(
      `ALTER TABLE "black_list_token" DROP CONSTRAINT "FK_eb95e35c5e28e037df8883641d7"`
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" DROP CONSTRAINT "FK_8e913e288156c133999341156ad"`
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "id" SET DEFAULT '0b42f0ca-accc-441e-8f90-60acc22b02de'`
    );
    await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "twoFaSecret"`);
    await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "faEnable"`);
    await queryRunner.query(`DROP TABLE "q_rcode"`);
    await queryRunner.query(`DROP TABLE "black_list_token"`);
    await queryRunner.query(`DROP TABLE "refresh_token"`);
  }
}
