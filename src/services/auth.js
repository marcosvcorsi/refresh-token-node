const users = require('./user')
const crypto = require('./crypto')
const tokenService = require('./token')

// illustration purposes only
// for production-ready code, use error codes/types and a catalog (maps codes -> responses)

/* eslint-disable prefer-promise-reject-errors */
const authFailed = email => Promise.reject({
  status: 401,
  code: 'UNAUTHENTICATED',
  message: `Failed to authenticate user ${email || ''}`,
})

const generateTokens = async user => {
  const { token: refreshToken, expiresAt: refreshTokenExpiration } = await tokenService.createRefreshToken(user.id)

  const accessToken = tokenService.sign({ id: user.id, role: user.role })

  return {
    accessToken,
    refreshToken,
    refreshTokenExpiration,
  }
}

const authenticate = async ({ email, password }) => {
  const user = await users.findByEmail(email)

  if (!user) {
    return authFailed(email)
  }

  const isMatch = await crypto.compare(password, user.password)

  if (!isMatch) {
    return authFailed(email)
  }

  return generateTokens(user)
}

const isRefreshTokenValid = token => token && token.valid && token.expiresAt >= Date.now()

const refreshToken = async tokenValue => {
  const refreshTokenObject = await tokenService.getRefreshToken(tokenValue)

  if (isRefreshTokenValid(refreshTokenObject)) {
    await tokenService.invalidateRefreshToken(tokenValue)

    const user = await users.findById(refreshTokenObject.user_id)

    return generateTokens(user)
  }

  return authFailed
}

const logout = async ({ refreshTokenValue, allDevices }) => {
  if (allDevices) {
    return tokenService.invalidateAllUserRefreshTokens(refreshTokenValue)
  }

  return tokenService.invalidateRefreshToken(refreshTokenValue)
}

module.exports = {
  authenticate,
  refreshToken,
  logout,
}
