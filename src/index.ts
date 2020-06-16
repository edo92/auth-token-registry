import jwt from 'jsonwebtoken';
import _ from 'lodash';

export const decode = async (refreshTokens: any, SECRET_2: any) => {
  return await jwt.decode(refreshTokens, SECRET_2);
}

export const verify = async (refreshToken: any, SECRET_2: any) => {
  await jwt.verify(refreshToken, SECRET_2);
}

export const createTokens = async (user: object, SECRET_1: string, SECRET_2: string) => {
  const createToken = jwt.sign(
    {
      user: _.pick(user, ['id', 'isAdmin']),
    },
    SECRET_1,
    {
      expiresIn: '1m',
    },
  );

  const createRefreshToken = jwt.sign(
    {
      user: _.pick(user, 'id'),
    },
    SECRET_2,
    {
      expiresIn: '7d',
    },
  );
  return Promise.all([createToken, createRefreshToken]);
};

export const refreshTokens = async (refreshToken: string, findUser: any, SECRET_1: any, SECRET_2: any) => { //, SECRET: string, SECRET_2: string, findUser
  let userId: string;

  try {
    const refreshDecoded: any = await decode(refreshToken, SECRET_2);
    const { id } = refreshDecoded.user;
    userId = id;
  }
  catch (err) {
    return {};
  }

  if (!userId) {
    return {};
  }

  const user = await findUser(userId);
  if (!user) {
    return {};
  }

  const refreshSecret = SECRET_2

  try {
    await verify(refreshToken, refreshSecret);
  }
  catch (err) {
    return {};
  }

  const [newToken, newRefreshToken] = await createTokens(user, SECRET_1, refreshSecret);

  return {
    token: newToken,
    refreshToken: newRefreshToken,
    user,
  };
};
