import { Router } from 'express';
import { certificateUpload } from '../middleware/upload.js';
import {
    getDetails,
    getAllDetails,
    approve,
    reject,
    searchedPharmacy
} from '../controllers/pharmaDataController.js';
import validateToken from '../middleware/authentication.js';
import { wrongUrl } from '../controllers/customerController.js';

const pharmaDataRouter = Router();

/**
 * @swagger
 * tags:
 *   name: Pharma data
 *   description: (Operations on pharams)
 */

/**
 * @swagger
 * /pharma-data/get-all:
 *   get:
 *     summary: (Get all pharma data)
 *     tags: [Pharma data]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Got all pharma data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

pharmaDataRouter.get('/get', validateToken, getDetails);

/**
 * @swagger
 * /pharma-data/search:
 *   get:
 *     summary: (Search by pharma name)
 *     parameters:
 *      - in: path
 *        name: name
 *     tags: [Pharma data]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Searched by pharma's name
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

pharmaDataRouter.get('/search', validateToken, searchedPharmacy);

/**
 * @swagger
 * /pharma-data/getAll:
 *   get:
 *     summary: (Details of  all pharmas)
 *     parameters:
 *      - in: path
 *        name: page
 *     tags: [Pharma data]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Searched by pharma's name
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

pharmaDataRouter.get('/getAll', validateToken, getAllDetails);

/**
 * @swagger
 * /pharma-data/approve:
 *   put:
 *     summary: (Details of  all pharmas)
 *     parameters:
 *      - in: path
 *        name: id
 *     tags: [Pharma data]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Approved pharma's name
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

pharmaDataRouter.put('/approve', validateToken, approve);

/**
 * @swagger
 * /pharma-data/reject:
 *   delete:
 *     summary: (Delete's data of a pharma)
 *     parameters:
 *      - in: path
 *        name: id
 *     tags: [Pharma data]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Approved pharma's name
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description: User not authorized
 */

pharmaDataRouter.delete('/reject', validateToken, reject);

pharmaDataRouter.use(wrongUrl);

export default pharmaDataRouter;
