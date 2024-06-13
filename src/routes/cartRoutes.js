import {
    updateCart,
    getCartData,
    wrongUrl
} from '../controllers/cartController.js';
import { Router } from 'express';
import validateToken from '../middleware/authentication.js';

const router = Router();
router.use(validateToken);

/**
 * @swagger
 * tags:
 *   name: User Cart
 *   description: (User cart operations)
 */

/**
 * @swagger
 * /cart/update-cart:
 *   put:
 *     summary: (Update user cart)
 *     tags: [User Cart]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               quantity:
 *                 type: number
 *               medicineId:
 *                 type: ObjectId
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

router.put('/update-cart', updateCart);

/**
 * @swagger
 * /cart/get-cart-data:
 *   get:
 *     summary: (Get user's cart data)
 *     tags: [User Cart]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of cart items
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       404:
 *         description: User not found
 */

router.get('/get-cart-data', getCartData);

router.use(wrongUrl);

export default router;
