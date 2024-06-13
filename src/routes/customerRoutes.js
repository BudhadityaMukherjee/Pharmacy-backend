import {
    getAllCustomer,
    searchedCustomer,
    getCustomer,
    sendOtp,
    verifyOtp,
    updateCustomer,
    updateProfileImage,
    deleteCustomer,
    wrongUrl
} from '../controllers/customerController.js';
import { profileImageUpload } from '../middleware/upload.js';
import { Router } from 'express';
import validateToken from '../middleware/authentication.js';

const router = Router();

/**
 * @swagger
 * tags:
 *   name: User Details
 *   description: (Operations on user and it's details)
 */

/**
 * @swagger
 * /customers/get-all:
 *   get:
 *     summary: (Get all user's data)
 *     tags: [User Details]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: A list of all customers
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

router.get('/get-all', validateToken, getAllCustomer);

/**
 * @swagger
 * /customers/search:
 *   get:
 *     summary: (Search by user name)
 *     parameters:
 *      - in: path
 *        name: name
 *     tags: [User Details]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Searched by customer's name
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

router.get('/search', validateToken, searchedCustomer);

/**
 * @swagger
 * /customers/get-customer:
 *   get:
 *     summary: (Get data for single user)
 *     tags: [User Details]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Single user address
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

router.get('/get-customer', validateToken, getCustomer);

/**
 * @swagger
 * /customers/send-otp:
 *   post:
 *     summary: (Get otp for login)
 *     tags: [User Details]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: otp send
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Email is not valid
 */

router.post('/send-otp', sendOtp);

/**
 * @swagger
 * /customers/verify-otp:
 *   post:
 *     summary: (Get otp for login)
 *     tags: [User Details]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: otp verified.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Otp expired please generate a new otp!!!
 */

router.post('/verify-otp', verifyOtp);

/**
 * @swagger
 * /customers/update:
 *   put:
 *     summary: (Update user details)
 *     tags: [User Details]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               phone:
 *                 type: string
 *     responses:
 *       200:
 *         description: User details updated.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorised
 */

router.put('/update', validateToken, updateCustomer);
router.put(
    '/update-profile-image',
    validateToken,
    profileImageUpload,
    updateProfileImage
);

/**
 * @swagger
 * /customers/delete:
 *   delete:
 *     summary: (Delete user)
 *     parameters:
 *      - in: path
 *        name: id
 *     tags: [User Details]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: User deleted.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorised
 */

router.delete('/delete', validateToken, deleteCustomer);

router.use(wrongUrl);

export default router;
