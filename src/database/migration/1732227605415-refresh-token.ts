import { MigrationInterface, QueryRunner } from 'typeorm';

export class RefreshToken1732227605415 implements MigrationInterface {
  name = 'RefreshToken1732227605415';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "refresh_token" ("id" character varying NOT NULL DEFAULT '266d6b16-90b0-4b88-b9d3-359adbfd62aa', "token" character varying NOT NULL, "expiration" TIMESTAMP NOT NULL, "userId" character varying, CONSTRAINT "PK_b575dd3c21fb0831013c909e7fe" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "id" SET DEFAULT '57b365a3-3eee-4b4d-992e-76cb1724b6a1'`
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" ADD CONSTRAINT "FK_8e913e288156c133999341156ad" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "refresh_token" DROP CONSTRAINT "FK_8e913e288156c133999341156ad"`
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "id" SET DEFAULT '0b42f0ca-accc-441e-8f90-60acc22b02de'`
    );
    await queryRunner.query(`DROP TABLE "refresh_token"`);
  }
}
