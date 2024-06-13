import { StatusCodes } from 'http-status-codes';
import FinalOrder from '../models/finalOrderModel.js';
import Quotation from '../models/quotationModel.js';
import { verifyRole } from '../services/helper.js';
import UserOrder from '../models/userOrderModel.js';
import loggerObject from '../services/loggerObject.js';
import CustomError from '../services/ErrorHandler.js';
import logActivity from '../services/logActivity.js';

const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

export const getOrderByIdUser = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const userId = req.id;
        const id = req.query.orderId;
        if (!id)
            throw new CustomError(
                StatusCodes.BAD_GATEWAY,
                'please enter orderId'
            );
        const response = await FinalOrder.findOne({
            orderId: id,
            userId: userId
        }).populate({
            path: 'quotationId',
            populate: {
                path: 'medicines.medicineId'
            }
        }).populate({path:'pharmacistId',populate:{path:'pharmacyId'}});
        logActivity(loggerStatus.INFO, response, 'final order for customer fetched', null, OPERATIONS.FINAL_ORDER.RETRIEVE_BY_ID, StatusCodes.ACCEPTED, METHODS.GET);
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
            OPERATIONS.FINAL_ORDER.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const getOrderByIdPharmacist = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const pharmacistId = req.id;
        const orderId = req.query.orderId;
        if (!orderId)
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'please enter orderId in query'
            );
        const response = await FinalOrder.findOne({
            orderId,
            pharmacistId
        }).populate({
            path: 'quotationId',
            populate: {
                path: 'medicines.medicineId'
            }
        });
        logActivity(
            loggerStatus.INFO,
            response,
            'final order for pharmacist fetched',
            null,
            OPERATIONS.FINAL_ORDER.RETRIEVE_BY_ID,
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
            OPERATIONS.FINAL_ORDER.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const addOrder = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const userId = req.id;
        const quotationId = req.body.quotationId;
        const quotation = await Quotation.findOne({ _id: quotationId });
        const newFinalOrder = new FinalOrder({
            userId,
            orderId: quotation.orderId,
            quotationId,
            pharmacistId: quotation.pharmacistId
        });
        await newFinalOrder.save();
        await UserOrder.findByIdAndUpdate(quotation.orderId, { status: 'confirmed' });
        await Quotation.findByIdAndUpdate(quotationId , { status: 'confirmed' });
        logActivity(
            loggerStatus.INFO,
            newFinalOrder,
            'new final order added',
            null,
            OPERATIONS.FINAL_ORDER.CREATE,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        res.status(StatusCodes.OK).send({
            message: 'Success',
            data: newFinalOrder
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.FINAL_ORDER.CREATE,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const getOrdersUser = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const userId = req.id;
        const response = await FinalOrder.find({ userId }).populate({
            path: 'quotationId',
            populate: {
                path: 'medicines.medicineId'
            }
        });
        logActivity(
            loggerStatus.INFO,
            response,
            'final orders for customer fetched',
            null,
            OPERATIONS.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );

        return res
            .status(StatusCodes.ACCEPTED)
            .send({ message: 'Success', data: response });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.FINAL_ORDER.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const getOrdersPharmacist = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const pharmacistId = req.id;
        const response = await FinalOrder.find({ pharmacistId })
            .populate({
                path: 'quotationId',
                populate: {
                    path: 'medicines.medicineId'
                }
            })
            .populate('orderId')
            .populate('pharmacistId');
        logActivity(
            loggerStatus.INFO,
            response,
            'final orders for pharmacist fetched',
            null,
            OPERATIONS.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .send({ message: 'Success', data: response });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.FINAL_ORDER.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const changeStatus = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const pharmacistId = req.id;
        const orderId = req.query.id;
        const state = req.query.state;
        if (!orderId)
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'please enter order id'
            );
        const response = FinalOrder.findOneAndUpdate(
            { pharmacistId, orderId },
            { status: state }
        );
        logActivity(
            loggerStatus.INFO,
            response,
            'order status changed',
            null,
            OPERATIONS.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );

        return res
            .status(StatusCodes.ACCEPTED)
            .send({ message: 'Success', data: response });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.FINAL_ORDER.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const deliveredOrder = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const pharmacistId = req.id;
        const orderId = req.query.id;
        if (!orderId) throw new Error('please enter order id');
        const response = await FinalOrder.findOneAndUpdate(
            { pharmacistId, orderId },
            { status: 'delivered' }
        );
        await UserOrder.findOneAndUpdate(
            { pharmacistId, orderId },
            { status: 'delivered' }
        );
        res.status(StatusCodes.OK).send({ message: 'Success', data: response });
    } catch (e) {
        next({ status: StatusCodes.CONFLICT, message: e.message });
    }
};

export const declineOrder = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const pharmacistId = req.id;
        const orderId = req.query.orderId;
        await FinalOrder.findOneAndDelete({ pharmacistId, orderId });
        await UserOrder.findByIdAndUpdate(orderId, { status: 'pending' });
        await Quotation.findOneAndUpdate(
            { pharmacistId, orderId },
            { status: 'declined' }
        );
        res.status(StatusCodes.OK).send({ message: 'Success', data: null });
        logActivity(
            loggerStatus.INFO,
            null,
            'final order declined and deleted',
            null,
            OPERATIONS.REMOVE,
            StatusCodes.ACCEPTED,
            METHODS.DELETE
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .send({ message: 'Success', data: null });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.FINAL_ORDER.REMOVE,
            error.status,
            METHODS.DELETE
        );
        next(error);
    }
};
