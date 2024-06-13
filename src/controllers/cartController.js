import Cart from '../models/cartModel.js';
import { StatusCodes } from 'http-status-codes';
import { verifyRole } from '../services/helper.js';
import loggerObject from '../services/loggerObject.js';
import CustomError from '../services/ErrorHandler.js';
import logActivity from '../services/logActivity.js';
const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

export const updateCart = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const cartData = await Cart.findOne({ userId: req.id });
        if (req.body.quantity === 0) {
            cartData.cartItems = cartData.cartItems.filter(
                (item) => String(item.medicineId) !== req.body.medicineId
            );
        } else {
            const index = cartData.cartItems.findIndex(
                (item) => String(item.medicineId) === req.body.medicineId
            );
            if (index !== -1)
                cartData.cartItems[index].quantity = req.body.quantity;
            else cartData.cartItems.push(req.body);
        }
        const updatedData = await Cart.findOneAndUpdate(
            { userId: req.id },
            {
                cartItems: cartData.cartItems,
                userId: req.id
            },
            { returnOriginal: false }
        );
        logActivity(
            loggerStatus.INFO,
            updatedData,
            'Cart Data Updated',
            null,
            OPERATIONS.CART.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data: updatedData
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CART.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const getCartData = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError('User not authorised');

        const cartData = await Cart.findOne({ userId: req.id }).populate({
            path: 'cartItems.medicineId'
        });
        logActivity(
            loggerStatus.INFO,
            cartData,
            'fetch Customer cart data',
            null,
            OPERATIONS.CART.RETRIEVE_BY_ID,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data: cartData
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CART.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const wrongUrl = (req, res) => {
    res.status(StatusCodes.BAD_REQUEST).json({
        data: null,
        message: 'Wrong url'
    });
};
