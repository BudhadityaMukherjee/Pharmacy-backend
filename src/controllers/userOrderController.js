import UserOrder from '../models/userOrderModel.js';
import Cart from '../models/cartModel.js';
import { StatusCodes } from 'http-status-codes';
import Pharmacy from '../models/prarmaDataModel.js';
import Address from '../models/addressModel.js';
import { verifyRole } from '../services/helper.js';
import Quotation from '../models/quotationModel.js';
import loggerObject from '../services/loggerObject.js';
import logActivity from '../services/logActivity.js';

const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

export const addOrder = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const userId = req.id;
        const files = req.files;
        const prescriptions =
            files !== undefined
                ? files.map((item) => `prescriptions/${item.filename}`)
                : '';
        const cartData = await Cart.findOne({ userId });
        if (cartData.cartItems.length === 0 && req.files.length === 0) {
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'No items in the cart! Unable to place order'
            );
        }
        const address = await Address.findOne({
            userId,
            _id: req.body.addressId
        });
        const newOrder = await UserOrder.create({
            userId,
            medicines: cartData.cartItems,
            prescriptions,
            address: address.address,
            location: address.location
        });
        await newOrder.save();
        await Cart.findOneAndUpdate(
            { userId },
            { cartItems: [] },
            { new: true }
        );
        logActivity(
            loggerStatus.INFO,
            newOrder,
            'order created successfully',
            null,
            OPERATIONS.USER_ORDER.CREATE,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            mesage: 'Order placed successfully'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.USER_ORDER.CREATE,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const closeOrder = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const userId = req.id;
        const orderId = req.query.orderId;
        const response = await UserOrder.findOneAndUpdate(
            { _id: orderId, userId },
            {
                isClosed: true
            },
            { new: true }
        );
        logActivity(
            loggerStatus.INFO,
            response,
            'order closed successfully',
            null,
            OPERATIONS.USER_ORDER.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res.status(StatusCodes.ACCEPTED).send({
            message: 'Order Successfully closed',
            data: response
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.USER_ORDER.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const deleteOrder = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const userId = req.id;
        const orderId = req.query.orderId;
        if (!orderId)
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'please enter the "orderId" in query'
            );
        const response = await UserOrder.findByIdAndDelete({
            userId,
            _id: orderId
        });
        logActivity(
            loggerStatus.INFO,
            response,
            'order deleted successfully',
            null,
            OPERATIONS.USER_ORDER.REMOVE,
            StatusCodes.ACCEPTED,
            METHODS.DELETE
        );
        return res.status(StatusCodes.ACCEPTED).send({
            message: 'Order Successfully deleted',
            data: response
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.USER_ORDER.REMOVE,
            error.status,
            METHODS.DELETE
        );
        next(error);
    }
};

export const getOrder = async (req, res, next) => {
    try {
        if (!verifyRole(['user', 'pharmacist'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const userId = req.id;
        const orderId = req.query.orderId;
        if (!orderId)
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'please give orderId in query parameter'
            );
        const data = await UserOrder.findOne({ _id: orderId, userId }).populate(
            {
                path: 'medicines.medicineId'
            }
        );
        logActivity(
            loggerStatus.INFO,
            data,
            'order fetched successfully',
            null,
            OPERATIONS.USER_ORDER.RETRIEVE_BY_ID,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .send({ message: 'Success', data });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.USER_ORDER.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const getAll = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const total = await UserOrder.find().count();
        const data = await UserOrder.find()
            .populate({
                path: 'medicines.medicineId'
            })
            .populate({ path: 'userId' })
            .skip(req.query.page * 10)
            .limit(10);
        logActivity(
            loggerStatus.INFO,
            data,
            'all orders fetched',
            null,
            OPERATIONS.USER_ORDER.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).send({
            message: 'Success',
            data: { orderData: data, total: total }
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.USER_ORDER.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const userGetAll = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const userId = req.id;
        const data = await UserOrder.find({ userId })
            .populate({
                path: 'medicines.medicineId'
            })
            .populate({ path: 'userId' });
        logActivity(
            loggerStatus.INFO,
            data,
            'all orders fetched for users',
            null,
            OPERATIONS.USER_ORDER.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).send({
            message: 'Success',
            data
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.USER_ORDER.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const pharmacistGetAll = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const id = req.id;
        const pharmacy = await Pharmacy.findOne({ pharmacistId: id });
        const coordinates = pharmacy.location.coordinates;
        console.log(coordinates)
        const data = await UserOrder.find({
            // location: {
            //     $near: {
            //         $geometry: { type: 'Point', coordinates },
            //         $minDistance: 0,
            //         $maxDistance: 100000
            //     }
            // },
            status: 'pending'
        })
            .populate({
                path: 'medicines.medicineId'
            })
            .populate({
                path: 'userId'
            });
        const quotationOrderIds = await Quotation.distinct('orderId', {
            pharmacistId: id
        });
        const myIds = quotationOrderIds.map((item) => item.toString());
        const response = data.filter(
            (order) => !myIds.includes(order._id.toString())
        );
        console.log(response)
        logActivity(
            loggerStatus.INFO,
            response,
            'orders fetched for pharmacist',
            null,
            OPERATIONS.USER_ORDER.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).send({
            message: 'Success',
            data: response
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.USER_ORDER.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};
