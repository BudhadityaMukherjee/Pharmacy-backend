import { StatusCodes } from 'http-status-codes';
import Quotation from '../models/quotationModel.js';
import { verifyRole } from '../services/helper.js';
import loggerObject from '../services/loggerObject.js';
import CustomError from '../services/ErrorHandler.js';
import logActivity from '../services/logActivity.js';

const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

export const offer = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const pharmacistId = req.id;
        const quotation = await Quotation.findOne({
            pharmacistId,
            orderId: req.body.orderId
        });
        if (!!quotation)
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'Offer already made'
            );

        const newOffer = await Quotation.create({
            pharmacistId,
            ...req.body
        });
        const response = await newOffer.save();
        logActivity(
            loggerStatus.INFO,
            response,
            'Quotation submitted successfully',
            null,
            OPERATIONS.QUOTATION.CREATE,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            mesage: 'Quotation submitted successfully',
            data: response
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.QUOTATION.CREATE,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const deleteOffer = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const pharmacistId = req.id;
        const offerId = req.query.offerId;
        if (!offerId) {
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'please mention offerId'
            );
        }
        const response = await Quotation.findByIdAndDelete({
            offerId,
            pharmacistId
        });
        logActivity(
            loggerStatus.INFO,
            response,
            'Quotation deleted successfully',
            null,
            OPERATIONS.QUOTATION.REMOVE,
            StatusCodes.ACCEPTED,
            METHODS.DELETE
        );
        return res.status(StatusCodes.ACCEPTED).json({
            mesage: 'Offer deleted successfully',
            data: response
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.QUOTATION.REMOVE,
            error.status,
            METHODS.DELETE
        );
        next(error);
    }
};

export const getOffersPharmacist = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const pharmacistId = req.id;
        const response = await Quotation.find({ pharmacistId }).populate({
            path: 'medicines.medicineId'
        });
        logActivity(
            loggerStatus.INFO,
            response,
            'Quotation fetched successfully',
            null,
            OPERATIONS.QUOTATION.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            mesage: 'success',
            data: response
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            response,
            error.message,
            null,
            OPERATIONS.QUOTATION.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const getOffers = async (req, res, next) => {
    try {
        if (!verifyRole(['user', 'admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const orderId = req.query.orderId;
        const response = await Quotation.find({ orderId }).populate({
            path: 'medicines.medicineId'
        }).populate({path:'pharmacistId',populate:{path:'pharmacyId'}});
        logActivity(
            loggerStatus.INFO,
            response,
            'Quotations fetched successfully',
            null,
            OPERATIONS.QUOTATION.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            mesage: 'success',
            data: response
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.QUOTATION.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const userDecline = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role)) throw new CustomError(StatusCodes.UNAUTHORIZED, 'User not authorised');
        const quotationId = req.query.quotationId;
        const response = await Quotation.findByIdAndUpdate(quotationId,{status:'declined'});
        logActivity(loggerStatus.INFO, response, 'Quotations declined successfully', null, OPERATIONS.QUOTATION.RETRIEVE, StatusCodes.ACCEPTED, METHODS.GET);
        return res.status(StatusCodes.ACCEPTED).json({
            mesage: 'success',
            data: null
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.QUOTATION.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};
