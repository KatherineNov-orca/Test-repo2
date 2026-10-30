/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function changePassword () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { query, connection } = req
    const currentPassword = query.current as string
    const newPassword = query.new as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = query.repeat

    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    // Identity is established by the isAuthorized() express-jwt middleware mounted on this
    // route, which verifies the JWT signature and expiry. The cache below only supplies the
    // already-authenticated user's cached data and must never be relied upon on its own.
    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) {
      res.status(401).send(res.__('Current password is not correct.'))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }

      await user.update({ password: newPasswordInString })
      challengeUtils.solveIf(
        challenges.changePasswordBenderChallenge,
        () => user.id === 3 && !currentPassword && user.password === security.hash('slurmCl4ssic')
      )
      res.json({ user })
    } catch (error) {
      next(error)
    }
  }
}
