import { Router } from 'express';
import {
    getOrderId,
    paymentCallBack,
    cancel
} from '../controllers/paymentController.js';

const router = Router();

router.post('/orders', getOrderId);
router.post('/payment-callback', paymentCallBack);
router.get('/cancel', cancel);

export default router;
