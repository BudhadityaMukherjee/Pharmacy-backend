import Razorpay from 'razorpay';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { StatusCodes } from 'http-status-codes';
dotenv.config();

export const paymentCallBack = (req, res, next) => {
    try {
        const { razorpay_signature, razorpay_order_id, razorpay_payment_id } =
            req.body;
        const string = `${razorpay_order_id}|${razorpay_payment_id}`;
        const generated_signature = crypto
            .createHmac('sha256', process.env.Razorpay_Key_Secret)
            .update(string)
            .digest('hex');
        if (generated_signature === razorpay_signature) {
            return res.status(StatusCodes.OK).redirect(`http://localhost:5173/payment-success?id=${req.query.id}&total=${req.query.total}&paymentId=${razorpay_payment_id}`);
        }
    } catch (error) {
        next({ status: StatusCodes.BAD_REQUEST, message: error.message });
    }
};

export const cancel = (req, res, next) => {
    try {
        return res.status(StatusCodes.OK).redirect(`http://localhost:5173/payment-failed?id=${req.query.id}&total=${req.query.total}`);
    } catch (error) {
        next({ status: StatusCodes.BAD_REQUEST, message: error.message });
    }
};

export const getOrderId = (req, res, next) => {
    try {
        var instance = new Razorpay({
            key_id: process.env.Razorpay_Key_Id,
            key_secret: process.env.Razorpay_Key_Secret
        });
        const option = {
            amount: req.body.amount * 100,
            currency: 'INR',
            receipt: 'TXN' + Date.now(),
            partial_payment: false,
            notes: {
                key1: req.body.name,
                key2: req.body.email,
                Key3: req.body.number,
                Key3: req.body.address,
                Key5: req.body.product,
                Key6: req.body.profile_name
            }
        };
        instance.orders.create(option, function (error, order) {
            if (order) {
                res.status(StatusCodes.OK).json({
                    data: order.id,
                    message: null
                });
            } else {
                throw new Error(error);
            }
        });
    } catch (error) {
        next({
            status: StatusCodes.INTERNAL_SERVER_ERROR,
            message: error.message
        });
    }
};
