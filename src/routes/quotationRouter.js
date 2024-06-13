import { Router } from 'express';
import { getOffers, getOffersPharmacist, offer , userDecline} from '../controllers/quotationController.js';
import validateToken from '../middleware/authentication.js';
import { wrongUrl } from '../controllers/customerController.js';
const quotationRouter = Router();

quotationRouter.use(validateToken);

/**
 * @swagger
 * tags:
 *   name: quotation
 *   description: (Operations on quotation)
 */

/**
 * @swagger
 * /quotation/offer:
 *   post:
 *     summary: (Get offers by pharmacist)
 *     tags: [quotation]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               orderId:
 *                 type: string
 *               medicines:
 *                 type: array
 *               isAvailable:
 *                 type: string
 *     responses:
 *       200:
 *         description: stores offers by pharmacist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: user unauthorized
 */

quotationRouter.post('/offer', offer);

/**
 * @swagger
 * /quotation/get-offers:
 *   get:
 *     summary: (Get all pharma offers)
 *     parameters:
 *      - in: path
 *        name: orderId
 *     tags: [quotation]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Got all pharma offers
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

quotationRouter.get('/get-offers', validateToken, getOffers);

/**
 * @swagger
 * /quotation/get-offers-pharmacist:
 *   get:
 *     summary: (Get all pharma offers for pharamcist)
 *     tags: [quotation]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Got all pharma offers
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

quotationRouter.get(
    '/get-offers-pharmacist',
    validateToken,
    getOffersPharmacist
);
quotationRouter.put('/user-decline', validateToken, userDecline);

quotationRouter.use(wrongUrl);

export default quotationRouter;
