import { Router } from 'express';
import {
    addAddress,
    deleteAddress,
    getAddresses,
    getAddressById,
    updateAddress,
    wrongUrl
} from '../controllers/addressController.js';
import validateToken from '../middleware/authentication.js';

const router = Router();
router.use(validateToken);

/**
 * @swagger
 * tags:
 *   name: User Address
 *   description: (Operations on user address.)
 */

/**
 * @swagger
 * /user-address/add-address:
 *   post:
 *     summary: (Get's new user address.)
 *     tags: [User Address]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               phone:
 *                 type: string
 *                 example: 1234567890
 *               receiverName:
 *                 type: string
 *                 example: John Doe
 *               type:
 *                 type: string
 *                 example: Home
 *               coordinates:
 *                 type: array
 *                 example: [ 22.5774516, 88.4315083 ]
 *               address:
 *                 type: object
 *     responses:
 *       202:
 *         description: New Address for user successfully added
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       500:
 *         description: Internal server error.
 *       401:
 *         description: User not authorized.
 */

router.post('/add-address', addAddress);

/**
 * @swagger
 * /user-address/get-address:
 *   get:
 *     summary: (Get's user address details)
 *     tags: [User Address]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: A list of users address
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized.
 */

router.get('/get-address', validateToken, getAddresses);

/**
 * @swagger
 * /user-address/get-single-address:
 *   get:
 *     summary: (Get single user address details)
 *     parameters:
 *      - in: path
 *        name: userId
 *     tags: [User Address]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: A user's address
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized.
 */

router.get('/get-single-address', validateToken, getAddressById);
router.put('/update-address', updateAddress);

/**
 * @swagger
 * /user-address/get-single-address:
 *   delete:
 *     summary: (Delete single user address )
 *     parameters:
 *      - in: path
 *        name: id
 *     tags: [User Address]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: A user's address
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized.
 */

router.delete('/delete-address', deleteAddress);

router.use(wrongUrl);

export default router;
