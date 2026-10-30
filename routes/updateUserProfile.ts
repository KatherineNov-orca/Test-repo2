/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import config from 'config'

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        next(new Error('User not found'))
        return
      }

      // Enforce same-origin as a real authorization guard instead of only
      // feeding the challenge-tracking callback below. This blocks
      // cross-site (CSRF) requests that only rely on the ambient auth cookie.
      const requestOrigin = req.headers.origin ?? req.headers.referer
      const selfOrigin = `${req.protocol}://${req.headers.host ?? ''}`
      const isSameOrigin = requestOrigin == null || requestOrigin.startsWith(selfOrigin)
      if (!isSameOrigin) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }

      challengeUtils.solveIf(challenges.csrfChallenge, () => {
        const url = config.get<string>('challenges.overwriteUrlForCsrfChallenge')
        return ((req.headers.origin?.includes('://' + url.replace(/^https?:\/\//, ''))) ??
          (req.headers.referer?.includes('://' + url.replace(/^https?:\/\//, '')))) &&
          req.body.username !== user.username
      })

      const savedUser = await user.update({ username: req.body.username })
      const userWithStatus = utils.queryResultToJson(savedUser)
      const updatedToken = security.authorize(userWithStatus)
      security.authenticatedUsers.put(updatedToken, userWithStatus)
      res.cookie('token', updatedToken, { sameSite: 'strict', secure: req.secure, httpOnly: true })
      res.location(process.env.BASE_PATH + '/profile')
      res.redirect(process.env.BASE_PATH + '/profile')
    } catch (error) {
      next(error)
    }
  }
}
