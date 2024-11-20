import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import userRouter from './UserRouter';
import { AppDataSource } from './data-source';

dotenv.config();

AppDataSource.initialize()
  .then(async () => {
    console.log('Inserting a new user into the database...');
  })
  .catch((error) => console.log(error));

const port = process.env.PORT || 8050;
const app = express();

app.use(express.json());

app.use('/api/v1', userRouter);

app.listen(port, () => {
  console.log(`Server is running on port http://localhost:${port}`);
});
