/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'

export function getWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
    if (wallet != null) {
      res.status(200).json({ status: 'success', data: wallet.balance })
    } else {
      res.status(404).json({ status: 'error' })
    }
  }
}

// Only these fixed, server-defined denominations may be credited per top-up request.
// The client cannot be trusted to state how much it actually paid, so the credited
// amount must never be taken verbatim from req.body.balance without bounds checking.
const ALLOWED_TOP_UP_AMOUNTS = [5, 10, 20, 50, 100, 200]

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const amount = req.body.balance
    if (typeof amount !== 'number' || !Number.isFinite(amount) || !ALLOWED_TOP_UP_AMOUNTS.includes(amount)) {
      res.status(400).json({ status: 'error', message: 'Invalid top-up amount.' })
      return
    }
    const cardId = req.body.paymentId
    const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
    if (card != null) {
      try {
        await WalletModel.increment({ balance: amount }, { where: { UserId: req.body.UserId } })
        res.status(200).json({ status: 'success', data: amount })
      } catch {
        res.status(404).json({ status: 'error' })
      }
    } else {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
    }
  }
}
