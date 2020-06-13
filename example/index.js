const { createTokens, refreshTokens, decode } = require('auth-token-registry');

// Create token when user logs in
function userLogin(user) {
    createUser(user).then(async res => {
        const [token, refreshToken] = await createTokens(user, SECRET_1, SECRET_2);
    });
}

// In auth middleware token gets refreshed when it's expired
async function authMiddleware() {
    try {
        // if can't decode throws error
        await decode(refreshToken, SECRET_2);
        // findUser is a function that receives user id and checks in db for user existance
        const newTokens = await refreshTokens(refreshToken, findUser, SECRET_1, SECRET_2);
    }
    catch (err) { throw err }
}