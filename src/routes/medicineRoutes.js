import {
    addMedicine,
    getAll,
    getMedicine,
    updateMedicine,
    searchedMedicine,
    deleteMedicine,
    wrongUrl
} from '../controllers/medicineController.js';
import { Router } from 'express';
import validateToken from '../middleware/authentication.js';

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Medicines
 *   description: (Operations on products)
 */

/**
 * @swagger
 * /medicines/add-medicine:
 *   post:
 *     summary: (Add new medicine)
 *     tags: [Medicines]
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
 *               price:
 *                 type: string
 *               packSizeLabel:
 *                 type: string
 *               manufacturerName:
 *                 type: string
 *               compositions:
 *                 type: array
 *     responses:
 *       200:
 *         description: New medicines added
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description:User aunauthorized
 */

router.post('/add-medicine', validateToken, addMedicine);

/**
 * @swagger
 * /medicines/get-all:
 *   get:
 *     summary: (Get medicine list)
 *     parameters:
 *      - in: path
 *        name: page
 *     tags: [Medicines]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Get all medicines.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 */

router.get('/get-all', getAll);

/**
 * @swagger
 * /medicines/get-medicine:
 *   get:
 *     summary: (Get a single medicine from medicine list)
 *     parameters:
 *      - in: path
 *        name: medicineId
 *     tags: [Medicines]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Get's a single medicines.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 */

router.get('/get-medicine', getMedicine);

/**
 * @swagger
 * /medicines/search-medicine:
 *   get:
 *     summary: (Search from medicine list)
 *     parameters:
 *      - in: path
 *        name: name
 *     tags: [Medicines]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Searched medicines.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 */

router.get('/search-medicine', searchedMedicine);

/**
 * @swagger
 * /medicines/update-medicine:
 *   put:
 *     summary: (Update's existing medicine)
 *     tags: [Medicines]
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
 *               price:
 *                 type: string
 *               packSizeLabel:
 *                 type: string
 *               manufacturerName:
 *                 type: string
 *               compositions:
 *                 type: array
 *     responses:
 *       200:
 *         description: Medicines updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description:User aunauthorized
 */

router.put('/update-medicine', validateToken, updateMedicine);

/**
 * @swagger
 * /medicines/delete-medicine:
 *   delete:
 *     summary: (Delete a existing medicine)
 *     parameters:
 *      - in: path
 *        name: id
 *     tags: [Medicines]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Medicines delete
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         description:User aunauthorized
 */

router.delete('/delete-medicine', validateToken, deleteMedicine);

router.use(wrongUrl);

export default router;
