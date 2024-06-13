import Address from '../models/addressModel.js';
import { StatusCodes } from 'http-status-codes';
import { verifyRole } from '../services/helper.js';
import loggerObject from '../services/loggerObject.js';
import logActivity from '../services/logActivity.js';
import CustomError from '../services/ErrorHandler.js';
const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

export const addAddress = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        console.log(req.body);
        const address = new Address({
            ...req.body,
            userId: req.id,
            location: { coordinates: req.body.coordinates }
        });
        await address.save();
        logActivity(
            loggerStatus.INFO,
            address,
            'Address Successfully added',
            null,
            OPERATIONS.ADDRESS.CREATE,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data: req.body
        });
    } catch (error) {
        next(error);
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.ADDRESS.CREATE,
            error.status,
            METHODS.POST
        );
    }
};

export const getAddresses = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const addressData = await Address.find({ userId: req.id });
        logActivity(
            loggerStatus.INFO,
            addressData,
            'Addresses Successfully fetched',
            null,
            OPERATIONS.ADDRESS.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: addressData });
    } catch (error) {
        next(error);
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.ADDRESS.RETRIEVE,
            error.status,
            METHODS.GET
        );
    }
};

export const getAddressById = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const addressData = await Address.findById(req.query.id);
        logActivity(
            loggerStatus.INFO,
            addressData,
            'Address fetched Successfully',
            null,
            OPERATIONS.ADDRESS.RETRIEVE_BY_ID,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: addressData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.ADDRESS.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const updateAddress = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const addressData = await Address.findByIdAndUpdate(
            req.query.id,
            req.body,
            { returnOriginal: false }
        );
        logActivity(
            loggerStatus.INFO,
            addressData,
            'Address Successfully Updated',
            null,
            OPERATIONS.ADDRESS.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: addressData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.ADDRESS.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const deleteAddress = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const addressData = await Address.findByIdAndDelete(req.query.id);
        logActivity(
            loggerStatus.INFO,
            addressData,
            'Address Successfully Deleted',
            null,
            OPERATIONS.ADDRESS.REMOVE,
            StatusCodes.ACCEPTED,
            METHODS.DELETE
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: addressData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.ADDRESS.REMOVE,
            error.status,
            METHODS.DELETE
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
