import { Request, Response, NextFunction } from 'express';
import jwt, { JwtHeader } from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const authenticated = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const header = req.headers.authorization;
  if (!header) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }
  const token = header.split(' ')[1];
  // console.log(token);
  if (!token) {
    res.status(401).json({ message: 'unauthorized' });
    return;
  }
  try {
    const decoded = jwt.verify(token, process.env.SECRETTOKEN!);
    if (!decoded) {
      res.status(401).json({
        message: 'unauthorized',
      });
      return;
    }
    (req as any).header = { value: header, exp: (decoded as any).exp };
    (req as any).user = decoded;
    next();
  } catch (error: any) {
    console.log(error);
    if (error.name === 'TokenExpiredError') {
      res.status(401).json({
        status: 'unauthorized',
        message: 'Token Expired',
      });
      return;
    }
    if (error.name === 'JsonWebTokenError') {
      res.status(401).json({
        status: 'unauthorized',
        message: 'Invalid Token',
      });
      return;
    }
  }
};

export default authenticated;
