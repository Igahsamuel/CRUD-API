import { NextFunction, raw, Router } from 'express';
import { Request, Response } from 'express';
import { AppDataSource } from './data-source';
import { User } from './entity/User';
import { hashPasswordAndValidate } from './authUtils';
import jwt, { JsonWebTokenError, JwtPayload } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import authenticated from './authenticated';
import isAdmin from './isAdmin';
import { RefreshToken } from './entity/RefreshToken';
import { BlackListToken } from './entity/BlackListToken';
import { authenticator } from 'otplib';
import qrcode from 'qrcode';
import crypto from 'crypto';
import NodeCache from 'node-cache';
import nodemailer from 'nodemailer';
import { userInfo } from 'os';

const router = Router();

const nodeCache = new NodeCache();

router.get('/users', async (req: Request, res: Response) => {
  try {
    const users = await AppDataSource.manager.find(User);
    res.status(200).json({
      status: 'success',
      data: {
        users,
      },
    });
  } catch (error) {
    // console.log(error);
    res.status(500).json({
      status: 'fail',
      message: 'Error fetching users',
    });
  }
});

router.post('/create', async (req: Request, res: Response) => {
  try {
    const { name, password, passwordConfirm, role, email } = req.body;
    const hashPassword = await hashPasswordAndValidate(
      password,
      passwordConfirm
    );

    if (!name || !email || !password || !passwordConfirm) {
      res.status(422).json({ message: 'Please input the necessary details' });
      return;
    }

    if (await AppDataSource.manager.findOne(User, { where: { email } })) {
      res.status(409).json({ message: 'Email already exist' });
      return;
    }

    const newUser = new User();
    (newUser.name = name),
      (newUser.email = email),
      (newUser.password = hashPassword),
      (newUser.passwordConfirm = hashPassword),
      (newUser.role = role);

    const saveuser = await AppDataSource.manager.save(newUser);
    res.status(201).json({
      status: 'success',
      data: {
        saveuser,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: 'fail',
      message: 'An Error occured',
    });
  }
});

// Login route
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(422).json({ message: 'Please input your email or password' });
      return;
    }

    const user = await AppDataSource.manager.findOne(User, {
      where: { email },
    });

    if (!user) {
      res.status(401).json({ message: 'Email or Password is incorrect' });
      return;
    }

    const passwordMatch = await bcrypt.compare(password, user?.password);

    if (!passwordMatch) {
      res.status(401).json({ message: 'Email or Password is incorrect' });
      return;
    }
    // if the user enables twofactor authentication
    if (user.faEnable) {
      const tempToken = crypto.randomUUID();
      nodeCache.set(
        process.env.CACHEPREFIX + tempToken,
        user.id,
        process.env.TOKENEXPIRESIN!
      );
      res
        .status(200)
        .json({ tempToken, expiresIN: process.env.TOKENEXPIRESIN });
    } else {
      const accessToken = jwt.sign({ id: user?.id }, process.env.SECRETTOKEN!, {
        expiresIn: process.env.EXPIRESIN,
      });

      const refreshToken = jwt.sign(
        { userId: user?.id },
        process.env.REFRESHTOKEN!,
        {
          expiresIn: process.env.REFRESHEXPIRES,
        }
      );

      const refresh_token: any = new RefreshToken();
      refresh_token.token = refreshToken;
      refresh_token.expiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      refresh_token.user = user;

      await AppDataSource.manager.save(refresh_token);

      res.status(200).json({
        status: 'success',
        accessToken,
        refreshToken,
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: 'failed',
      message: 'An error Occurred',
    });
  }
});

// Login 2fa
router.post('/login/2fa', async (req: Request, res: Response) => {
  try {
    const { tempToken, totp } = req.body;
    if (!tempToken || !totp) {
      res
        .status(401)
        .json({ message: 'Please fill in the tempToken, TOTP details' });
      return;
    }
    const userId = nodeCache.get<string>(process.env.CACHEPREFIX + tempToken);

    if (!userId) {
      res
        .status(401)
        .json({ message: 'Token provided is incorrect or expired' });
      return;
    }
    const user = await AppDataSource.manager.findOne(User, {
      where: { id: userId },
    });

    if (!user?.twoFaSecret) {
      res.status(401).json({ message: 'no secret ' });
      return;
    }

    // verify the totp
    const verify = authenticator.check(totp, user?.twoFaSecret);
    if (!verify) {
      res
        .status(401)
        .json({ message: 'The provided totp is incorrect or expired' });
      return;
    }
    // if everything is correct, then we need to generate accesstoken and refresh token and send it to the client
    const accessToken = jwt.sign({ id: user?.id }, process.env.SECRETTOKEN!, {
      expiresIn: process.env.EXPIRESIN,
    });

    const refreshToken = jwt.sign(
      { userId: user?.id },
      process.env.REFRESHTOKEN!,
      {
        expiresIn: process.env.REFRESHEXPIRES,
      }
    );

    const refresh_token: any = new RefreshToken();
    refresh_token.token = refreshToken;
    refresh_token.expiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    refresh_token.user = user;

    await AppDataSource.manager.save(refresh_token);

    res.status(200).json({
      status: 'success',
      accessToken,
      refreshToken,
    });
  } catch (error) {
    res.status(500).json({ message: 'internal Error' });
  }
});

// refreshToken
router.post('/refresh-token', async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(401).json({ message: 'Refresh Token not found' });
      return;
    }

    // decide and verify the token
    const decodedRefreshToken = jwt.verify(
      refreshToken,
      process.env.REFRESHTOKEN!
    ) as JwtPayload;

    // finding the token in the database
    const userRefreshToken = await AppDataSource.manager.findOne(RefreshToken, {
      where: { token: refreshToken },
      relations: ['user'],
    });

    if (userRefreshToken?.user && typeof userRefreshToken?.user !== 'object') {
      const user = await AppDataSource.manager.findOne(User, {
        where: { id: userRefreshToken.id },
      });
      if (!user) {
        res.status(404).json({ message: 'User not found' });
        return;
      }
      userRefreshToken.user = user;
    }

    // console.log(userRefreshToken);

    if (!userRefreshToken) {
      res.status(401).json({ message: 'Token is invalid or has expired' });
      return;
    }

    // remove the old refresh token from the database
    await AppDataSource.manager.remove(userRefreshToken);

    // Generating new access and refresh token
    const accessToken = jwt.sign(
      { token: decodedRefreshToken.token },
      process.env.SECRETTOKEN!,
      { expiresIn: process.env.EXPIRESIN }
    );

    const newRefreshToken = jwt.sign(
      { token: decodedRefreshToken.token },
      process.env.REFRESHTOKEN!,
      { expiresIn: process.env.REFRESHEXPIRES }
    );

    // saving the new refreshtoken in the database

    const newTokenEntity = new RefreshToken();
    newTokenEntity.token = newRefreshToken;
    newTokenEntity.expiration = new Date(
      Date.now() + parseInt(process.env.REFRESHEXPIRES!, 10) * 1000
    );
    newTokenEntity.user = userRefreshToken!.user;
    await AppDataSource.manager.save(newTokenEntity);

    // returns the new token
    res.status(200).json({
      status: 'success',
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error: any) {
    console.log(error);
    if (
      error.name === jwt.JsonWebTokenError ||
      error.name === jwt.TokenExpiredError
    ) {
      res.status(401).json({
        status: 'unauthorized',
        message: 'Token has expired ',
      });
      return;
    }
    res.status(500).json({
      status: 'fail',
      message: 'An Error Occured',
    });
    return;
  }
});

// two factor authentication
router.get(
  '/2fa/generate',
  authenticated,
  async (req: Request, res: Response) => {
    try {
      // fetch the user details
      const userDetails = await AppDataSource.manager.findOne(User, {
        where: { id: (req as any).user.id },
      });

      console.log(userDetails);
      if (!userDetails) {
        res.status(404).json({ message: 'user not found' });
        return;
      }

      const secret = authenticator.generateSecret();
      console.log(secret);
      const uri = authenticator.keyuri(
        userDetails.email,
        'igahsamuela2@gmail.com',
        secret
      );
      const result = await AppDataSource.manager.update(
        User,
        { id: (req as any).user.id },
        { twoFaSecret: secret }
      );

      const qrCode = await qrcode.toBuffer(uri, {
        type: 'png',
        margin: 1,
      });

      res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png');
      res.status(200).type('image/png').send(qrCode);
    } catch (error) {
      console.log(error);
      res.status(500).json({
        status: ' fail',
        message: 'internal Error ',
      });
    }
  }
);

// Validate TOTP
router.post(
  '/2fa/validate',
  authenticated,
  async (req: Request, res: Response) => {
    try {
      const { totp } = req.body;
      if (!totp) {
        res.status(422).json({ message: 'TOTP is required' });
        return;
      }
      const user = await AppDataSource.manager.findOne(User, {
        where: { id: (req as any).user.id },
      });

      if (!user?.twoFaSecret) {
        res.status(400).json({ message: '2fa is missing' });
        return;
      }

      // verify the totp
      const verifyToken = authenticator.check(totp, user.twoFaSecret);

      if (!verifyToken) {
        res.status(401).json({
          message: 'invalid 2fa token or has expired',
        });
        return;
      }

      await AppDataSource.manager.update(
        User,
        { id: (req as any).user.id },
        { faEnable: true }
      );
      res.status(200).json({ message: 'Token successfully verified' });
    } catch (error) {
      res.status(500).json({ message: 'internal Error' });
    }
  }
);

// current User
router.get(
  '/currentuser',
  authenticated,
  async (req: Request, res: Response) => {
    try {
      const user: any = await AppDataSource.manager.findOne(User, {
        where: { id: (req as any).user.id },
      });
      res.status(200).json({
        status: 'success',
        id: user?.id,
        name: user?.name,
        email: user?.email,
      });
      return;
    } catch (error) {
      console.log(error);
      res.status(500).json({
        status: 'fail',
        message: 'An error Occured',
      });
    }
  }
);

// logout route
router.get('/logout', authenticated, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    const token = req.headers.authorization?.split(' ')[1];
    await AppDataSource.manager.delete(RefreshToken, { id: user.id });
    if (!token) {
      res.status(401).json({ message: 'No token found' });
      return;
    }

    const blackListTokenEntity = new BlackListToken();
    (blackListTokenEntity.token = token),
      (blackListTokenEntity.user = user),
      (blackListTokenEntity.expiration = new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
      ));
    await AppDataSource.manager.save(blackListTokenEntity);

    res.status(200).json({
      status: 'success',
      message: 'Logout Successful',
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: 'fail',
      message: 'An error occured',
    });
  }
});

// admin route
router.get(
  '/admin',
  authenticated,
  isAdmin(['admin']),
  async (req: Request, res: Response) => {
    try {
      res.status(200).json({
        status: 'Success',
        message: 'Welcome Admin',
      });
    } catch (error) {
      res.status(500).json({
        status: 'fail',
        message: 'An error Occured',
      });
    }
  }
);

// admin/users
router.get(
  '/landlord-admin',
  authenticated,
  isAdmin(['admin', 'landlord']),
  async (req: Request, res: Response) => {
    try {
      res.status(200).json({
        status: 'Success',
        message: 'only landlords and admins can access this route',
      });
    } catch (error) {
      res.status(500).json({
        status: 'fail',
        message: 'An error Occured',
      });
    }
  }
);

// update user details
router.patch('/update/:id', async (req: Request, res: Response) => {
  try {
    const { name, email, password, passwordConfirm } = req.body;
    const userId = req.params.id;
    const user = await AppDataSource.manager.findOne(User, {
      where: { id: userId },
    });
    if (!user) {
      res.status(404).json({ message: 'User not found' });
    }
    user!.name = name;
    user!.email = email;
    user!.password = password;
    user!.passwordConfirm = passwordConfirm;

    const updateUser = await AppDataSource.manager.save(user);

    res.status(200).json({
      status: 'success',
      data: {
        updateUser,
      },
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: 'fail',
      message: 'An Error occured',
    });
  }
});

// delete User
router.delete('/delete/:id', async (req: Request, res: Response) => {
  try {
    const userId = req.params.id;
    const user = await AppDataSource.manager.findOne(User, {
      where: { id: userId },
    });
    if (!user) {
      res.status(404).json({ message: 'User does not exist' });
    }
    await AppDataSource.manager.remove(user);
    res.status(204).json({
      status: 'Deleted',
      message: 'You have successfully deleted a user',
    });
    return;
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: 'fail',
      message: 'An Error occured ',
    });
  }
});

// forgot password
router.post('/forgot', async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    // check if the user with this email exist
    const user = await AppDataSource.manager.findOne(User, {
      where: { email },
    });
    if (!user) {
      res
        .status(401)
        .json({ message: 'This user does not exist or has been deleted' });
    }

    // get the token
    const token = jwt.sign({ id: user?.id }, process.env.SECRETTOKEN!, {
      expiresIn: process.env.EXPIRESIN,
    });
    // CREATE THE TRANSPORTER
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'igahsamuela2@gmail.com',
        pass: process.env.NODEMAILERPASSWORD,
      },
    });

    const mailOptions = {
      to: user?.email,
      from: process.env.EMAIL,
      subject: 'Forgot password Request',
      text: `You are receiving this because you (or someone else) have requested the forgot password for your account. \n\n Please click on the following link, or paste this into your browser to complete the process: ${token} \n\n If you did not request this, please ignore this email and your password will remain unchanged.`,
    };
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'password reset link sent', token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'internal Error ' });
  }
});

// Reset password
router.post(
  '/resetpassword',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { token } = req.query;
      const { password } = req.body;

      if (!token) {
        res.status(401).json({ message: 'Missing token' });
      }

      // verify the sent token
      const verify = jwt.verify(token as string, process.env.SECRETTOKEN!);
      if (!verify) {
        res.status(401).json({ message: 'incorrect token or expired' });
      }

      // fetch the user
      const user = await AppDataSource.manager.findOne(User, {
        where: { id: (verify as any).id },
      });
      if (!user) {
        res.status(400).json({ message: 'User does not exist' });
        return;
      }

      const encryptedPassword = await bcrypt.hash(password, 12);

      await AppDataSource.manager.update(
        User,
        { id: user.id },
        { password: encryptedPassword }
      );
      // await AppDataSource.manager.save(updateUser);
      res.status(200).json({ message: 'Password has been reset' });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'internal error' });
    }
  }
);

export default router;
