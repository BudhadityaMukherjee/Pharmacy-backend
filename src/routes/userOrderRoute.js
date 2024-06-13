import { Router } from 'express';
import { prescriptionUpload } from '../middleware/upload.js';
import {
    addOrder,
    closeOrder,
    deleteOrder,
    getOrder,
    pharmacistGetAll,
    userGetAll,
    getAll
} from '../controllers/userOrderController.js';
import validateToken from '../middleware/authentication.js';
import { wrongUrl } from '../controllers/customerController.js';

const userOrderRouter = Router();

userOrderRouter.use(validateToken);

/**
 * @swagger
 * tags:
 *   name: user orders
 *   description: (Operations on user orders)
 */

/**
 * @swagger
 * /user-order/make-order:
 *   post:
 *     summary: (Place order)
 *     tags: [user orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               addressId:
 *                 type: string
 *     responses:
 *       200:
 *         description: order placed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: user unauthorized
 */

userOrderRouter.post('/make-order', prescriptionUpload, addOrder);

/**
 * @swagger
 * /user-order/close-order:
 *   put:
 *     summary: (close order)
 *     parameters:
 *      - in: path
 *        name: orderId
 *     tags: [user orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Order closed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

userOrderRouter.put('/close-order', closeOrder);

/**
 * @swagger
 * /user-order/delete-order:
 *   delete:
 *     summary: (delete order)
 *     parameters:
 *      - in: path
 *        name: orderId
 *     tags: [user orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Order deleted
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

userOrderRouter.delete('/delete-order', deleteOrder);

/**
 * @swagger
 * /user-order/get-order:
 *   get:
 *     summary: (fetch all order by user and pharmacist)
 *     parameters:
 *      - in: path
 *        name: orderId
 *     tags: [user orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Fetch all Orders
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 *       400:
 *         description: Please give orderId in query parameter
 */

userOrderRouter.get('/get-order', getOrder);

/**
 * @swagger
 * /user-order/user-get-all:
 *   get:
 *     summary: (fetch all orders)
 *     tags: [user orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Fetched all Orders
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

userOrderRouter.get('/user-get-all', userGetAll);

/**
 * @swagger
 * /user-order/get-all:
 *   get:
 *     summary: (fetch all orders for admin)
 *     parameters:
 *      - in: path
 *        name: page
 *     tags: [user orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Fetched all Orders for admin
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

userOrderRouter.get('/get-all', getAll);

/**
 * @swagger
 * /user-order/pharmacist-get-all:
 *   get:
 *     summary: (fetch all orders for pharmacist)
 *     tags: [user orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Fetched all Orders for pharmacist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

userOrderRouter.get('/pharmacist-get-all', pharmacistGetAll);

userOrderRouter.use(wrongUrl);

export default userOrderRouter;
