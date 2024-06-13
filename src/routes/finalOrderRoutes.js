import { Router } from 'express';
import {
    addOrder,
    getOrderByIdPharmacist,
    getOrderByIdUser,
    getOrdersPharmacist,
    getOrdersUser,
    declineOrder,
    deliveredOrder
} from '../controllers/finalOrderController.js';
import validateToken from '../middleware/authentication.js';
import { wrongUrl } from '../controllers/customerController.js';

const finalOrderRouter = Router();
finalOrderRouter.use(validateToken);

/**
 * @swagger
 * tags:
 *   name: Final order
 *   description: (Operations on final orders)
 */

/**
 * @swagger
 * /final-order/get-order-user:
 *   get:
 *     summary: (Get a single user's order)
 *     parameters:
 *      - in: path
 *        name: orderId
 *     tags: [Final order]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: A single final orders by user.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 *       502:
 *         description: please enter orderId
 */

finalOrderRouter.get('/get-order-user', getOrderByIdUser),
    /**
     * @swagger
     * /final-order/get-order-pharmacist:
     *   get:
     *     summary: (Get a single pharmacist's orders)
     *     parameters:
     *      - in: path
     *        name: orderId
     *     tags: [Final order]
     *     security:
     *       - bearerAuth: []
     *     responses:
     *       202:
     *         description: A single final orders by pharmacist.
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *       401:
     *         description: User not authorized
     */

    finalOrderRouter.get('/get-order-pharmacist', getOrderByIdPharmacist);

/**
 * @swagger
 * /final-order/get-orders-user:
 *   get:
 *     summary: (Get all orders by a users)
 *     tags: [Final order]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: A list of final orders by pharmacist.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 *       400:
 *         description: please enter orderId in query
 */

finalOrderRouter.get('/get-orders-user', getOrdersUser);

/**
 * @swagger
 * /final-order/get-orders-pharmacist:
 *   get:
 *     summary: (Get all orders by a pharmacist)
 *     tags: [Final order]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: A list of final orders by pharmacist.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

finalOrderRouter.get('/get-orders-pharmacist', getOrdersPharmacist);

/**
 * @swagger
 * /final-order/add-order:
 *   post:
 *     summary: (Place new final order)
 *     tags: [Final order]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               quotationId:
 *                 type: string
 *     responses:
 *       200:
 *         description: User updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       404:
 *         description: User not found
 */

finalOrderRouter.post('/add-order', validateToken, addOrder);

/**
 * @swagger
 * /final-order/decline-order:
 *   delete:
 *     summary: (Decline final order)
 *     parameters:
 *      - in: path
 *        name: orderId
 *     tags: [Final order]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: order declied successflly
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User unauthorized
 */

finalOrderRouter.delete('/decline-order', validateToken, declineOrder);

/**
 * @swagger
 * /final-order/update-delivery-status:
 *   put:
 *     summary: (Update's final order's status)
 *     parameters:
 *      - in: path
 *        name: orderId
 *     tags: [Final order]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: order status updated successflly
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User unauthorized
 */

finalOrderRouter.put('/update-delivery-status', validateToken, deliveredOrder);

finalOrderRouter.use(wrongUrl);

export default finalOrderRouter;
