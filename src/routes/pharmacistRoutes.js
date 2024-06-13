import { Router } from 'express';
import { StatusCodes } from 'http-status-codes';
import {
    register,
    login,
    getAll,
    getPharmacist,
    updatePharmacist,
    deletePharmacist,
    updatePharmacistPassword,
    updateProfileImage,
    sendOtp,
    verifyOtp,
    forgotPassword
} from '../controllers/pharmacistController.js';

import validateToken from '../middleware/authentication.js';
import { certificateUpload, profileImageUpload } from '../middleware/upload.js';
import { wrongUrl } from '../controllers/customerController.js';

const pharmacistRouter = Router();

/**
 * @swagger
 * tags:
 *   name: Pharmacist Details
 *   description: (Operations on pharmacist and it's details)
 */

/**
 * @swagger
 * /pharmacist/register:
 *   post:
 *     summary: (Register pharmacist)
 *     tags: [Pharmacist Details]
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
 *               password:
 *                 type: string
 *               registration_no:
 *                 type: string
 *               phone:
 *                 type: string
 *               address:
 *                 type: location
 *               location:
 *                 type: object
 *     responses:
 *       200:
 *         description: registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Email is not valid
 */

pharmacistRouter.post('/register', certificateUpload, register);

/**
 * @swagger
 * /pharmacist/login:
 *   post:
 *     summary: (login pharmacist)
 *     tags: [Pharmacist Details]
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
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: Internal server error
 */

pharmacistRouter.post('/login', login);

/**
 * @swagger
 * /pharmacist/get-all:
 *   get:
 *     summary: (Get all pharmacist)
 *     tags: [Pharmacist Details]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Otp send to pharmacist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

pharmacistRouter.get('/get-all', validateToken, getAll);

/**
 * @swagger
 * /pharmacist/send-otp:
 *   post:
 *     summary: (send otp)
 *     tags: [Pharmacist Details]
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
 *         description: logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: Internal server error
 */

pharmacistRouter.post('/send-otp', sendOtp);

/**
 * @swagger
 * /pharmacist/verify-otp:
 *   post:
 *     summary: (verify otp for pharmacist)
 *     tags: [Pharmacist Details]
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
 *         description: otp verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: Internal server error
 */

pharmacistRouter.post('/verify-otp', verifyOtp);

/**
 * @swagger
 * /pharmacist/verify-otp:
 *   put:
 *     summary: (update password for pharmacist)
 *     tags: [Pharmacist Details]
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
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: password updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 *       400:
 *         description: Internal server error
 */

pharmacistRouter.put('/forgot-password', forgotPassword);

/**
 * @swagger
 * /pharmacist/get-pharmacist:
 *   get:
 *     summary: (Get all pharmacist)
 *     tags: [Pharmacist Details]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: All data for pharmacist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

pharmacistRouter.get('/get-pharmacist', validateToken, getPharmacist);

/**
 * @swagger
 * /pharmacist/update-pharmacist:
 *   put:
 *     summary: (update details for pharmacist)
 *     tags: [Pharmacist Details]
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
 *         description: details updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 *       400:
 *         description: Internal server error
 */

pharmacistRouter.put('/update-pharmacist', validateToken, updatePharmacist);

/**
 * @swagger
 * /pharmacist/update-pharmacist-password:
 *   put:
 *     summary: (update password for pharmacist)
 *     tags: [Pharmacist Details]
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
 *     responses:
 *       200:
 *         description: password updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 *       400:
 *         description: Internal server error
 */

pharmacistRouter.put(
    '/update-pharmacist-password',
    validateToken,
    updatePharmacistPassword
);
pharmacistRouter.put(
    '/update-profile-image',
    validateToken,
    profileImageUpload,
    updateProfileImage
);
pharmacistRouter.delete('/delete-pharmacist', validateToken, deletePharmacist);

pharmacistRouter.use(wrongUrl);

export default pharmacistRouter;
