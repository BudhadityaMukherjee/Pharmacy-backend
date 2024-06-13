import { StatusCodes } from 'http-status-codes';
import Pharmacy from '../models/prarmaDataModel.js';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { verifyRole } from '../services/helper.js';
import Pharmacist from '../models/pharmacistModel.js';
import loggerObject from '../services/loggerObject.js';
import logActivity from '../services/logActivity.js';

const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const getAllDetails = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'user not authorized'
            );

        const page = req.query.page;
        const total = await Pharmacy.find().count();
        const data = await Pharmacy.find()
            .populate({
                path: 'pharmacistId'
            })
            .skip(page * 10)
            .limit(page);

        logActivity(
            loggerStatus.INFO,
            data,
            'all pharmacy details fetched ',
            null,
            OPERATIONS.PHARMACY_DATA.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data: { pharmaData: data, total },
            message: 'Success'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACY_DATA.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const getDetails = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist', 'admin'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const data = await Pharmacy.findOne({ pharmacistId: req.id }).populate({
            path: 'pharmacistId'
        });
        logActivity(
            loggerStatus.INFO,
            data,
            'pharmacy details fetched',
            null,
            OPERATIONS.PHARMACY_DATA.RETRIEVE_BY_ID,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data,
            message: 'Success'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            null,
            OPERATIONS.PHARMACY_DATA.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const searchedPharmacy = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role)) {
            throw new Error('User not authorised');
        }
        let pharmacyName = req.query.name;
        const pharmacyData = await Pharmacy.find({
            name: { $regex: pharmacyName, $options: 'i' }
        })
            .populate({ path: 'pharmacistId' })
            .sort({ name: 1 })
            .limit(10);
        return res
            .status(StatusCodes.OK)
            .json({ message: 'success', data: pharmacyData });
    } catch (error) {
        next({
            status: StatusCodes.INTERNAL_SERVER_ERROR,
            message: error.message
        });
    }
};

export const approve = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(StatusCodes.ACCEPTED, 'User not authorised');

        const id = req.query.id;
        const data = await Pharmacy.findByIdAndUpdate(
            id,
            { isApproved: true },
            { returnOriginal: false }
        );
        await Pharmacist.findByIdAndUpdate(data.pharmacistId, {
            pharmacyId: id
        });
        res.status(StatusCodes.OK).json({
            data,
            message: 'Success'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            null,
            OPERATIONS.PHARMACY_DATA.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const reject = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role)) {
            throw new Error('User not authorised');
        }
        const id = req.query.id;
        const data = await Pharmacy.findById(id);
        await Pharmacist.findByIdAndDelete(data.pharmacistId);
        await Pharmacy.findByIdAndDelete(id);
        logActivity(
            loggerStatus.INFO,
            data,
            'pharmacy is approved',
            null,
            OPERATIONS.PHARMACY_DATA.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data,
            message: 'Success'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACY_DATA.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const deleteDetails = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role)) {
            throw new CustomError(StatusCodes.ACCEPTED, 'user not authorised');
        }
        const data = await Pharmacy.deleteOne({ pharmacistId: req.id });
        logActivity(
            loggerStatus.INFO,
            data,
            'pharmacy deleted successfully',
            null,
            OPERATIONS.PHARMACY_DATA.REMOVE,
            StatusCodes.ACCEPTED,
            METHODS.DELETE
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data,
            message: 'Success'
        });
    } catch (error) {
        logActivity(
            loggerStatus.INFO,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACY_DATA.REMOVE,
            error.status,
            METHODS.DELETE
        );
        next(error);
    }
};
