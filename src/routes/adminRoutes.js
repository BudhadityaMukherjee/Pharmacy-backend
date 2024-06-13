import { Router } from 'express';
import validateToken from '../middleware/authentication.js';
import {
    adminLogin,
    registerAdmin,
    getAdminDetails,
    updateAdminDetails,
    updateAdminPassword,
    adminProfileImage
} from '../controllers/adminControllers.js';
import { profileImageUpload } from '../middleware/upload.js';
import { wrongUrl } from '../controllers/customerController.js';

const router = Router();
/**
 * @swagger
 * tags:
 *   name: Admin
 *   description: (Admin details)
 */

/**
 * @swagger
 * /admin/login:
 *   post:
 *     summary: (Admin login)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 example: abc@gmail.com
 *               password:
 *                 type: string
 *                 example: 1234567890
 *     responses:
 *       201:
 *         description: Admin logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Fields missing
 *       409:
 *         description: User already exists
 */

router.post('/login', adminLogin);

/**
 * @swagger
 * /admin/register:
 *   post:
 *     summary: (Register admin)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               phone:
 *                 type: string
 *               name:
 *                 type: string
 *               image:
 *                 type: string
 *               address:
 *                 type: object
 *     responses:
 *       201:
 *         description: Admin registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Fields missing
 *       409:
 *         description: Admin already exists
 */

router.post('/register', registerAdmin);

/**
 * @swagger
 * /admin/details:
 *   get:
 *     summary: (Get admin details)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of users
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 */

router.get('/details', validateToken, getAdminDetails);

/**
 * @swagger
 * /admin/update-details:
 *   put:
 *     summary: (Edit/Update admin detials)
 *     tags: [Admin]
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
 *                 example: abc@gmail.com
 *               name:
 *                 type: string
 *                 example: John Doe
 *               phone:
 *                 type: string
 *                 example: 1234567890
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

router.put('/update-details', validateToken, updateAdminDetails);

/**
 * @swagger
 * /admin/update-password:
 *   put:
 *     summary: (Update admin password)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               password:
 *                 type: string
 *                 example: 12345678
 *               newPassword:
 *                 type: string
 *                 example: 12346558790
 *     responses:
 *       200:
 *         description: Admin Password updated successfully!
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       404:
 *         description: Cannot update admin password!
 */

router.put('/update-password', validateToken, updateAdminPassword);
router.put(
    '/update-image',
    validateToken,
    profileImageUpload,
    adminProfileImage
);

router.use(wrongUrl);

export default router;
