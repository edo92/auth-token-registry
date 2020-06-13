import jwt from 'jsonwebtoken';
import _ from 'lodash';

export const createTokens = async (user: object, secret: string, secret2: string) => {
  const createToken = jwt.sign(
    {
      user: _.pick(user, ['id', 'isAdmin']),
    },
    secret,
    {
      expiresIn: '1m',
    },
  );

  const createRefreshToken = jwt.sign(
    {
      user: _.pick(user, 'id'),
    },
    secret2,
    {
      expiresIn: '7d',
    },
  );
  return Promise.all([createToken, createRefreshToken]);
};

export const refreshTokens = async (refreshToken: string, findUser: any, SECRET_1: string, SECRET_2: string) => { //, SECRET: string, SECRET_2: string, findUser
  let userId: string
  try {
    const refreshDecoded: any = jwt.decode(refreshToken);
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
    await jwt.verify(refreshToken, refreshSecret);
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
