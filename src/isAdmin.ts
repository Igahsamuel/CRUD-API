import { Request, Response, NextFunction } from 'express';
import { User } from './entity/User';
import { AppDataSource } from './data-source';

type Role = 'admin' | 'landlord';

function isAdmin(roles: Role[] = []) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user: any = await AppDataSource.manager.findOne(User, {
      where: { id: (req as any).user?.id },
    });
    if (!user || !roles.includes(user.role as Role)) {
      res.status(403).json({ message: 'Access Denied ' });
      return;
    }
    next();
  };
}

export default isAdmin;
