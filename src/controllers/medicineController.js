import Medicine from '../models/medicineModel.js';
import { StatusCodes } from 'http-status-codes';
import { verifyRole } from '../services/helper.js';
import addMedicineDetails from '../validator/medicineAddDetails.js';
import updateMedicineDetails from '../validator/medicineUpdateDetails.js';
import loggerObject from '../services/loggerObject.js';
import logActivity from '../services/logActivity.js';
import CustomError from '../services/ErrorHandler.js';

const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

export const addMedicine = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const nameArray = req.body.name.split(' ');
        const capitalisedName = nameArray.map(
            (word) => `${word[0].toUpperCase()}${word.slice(1).toLowerCase()}`
        );
        const medicineName = capitalisedName.join(' ');
        const medicine = new Medicine({
            ...req.body,
            name: medicineName
        });
        const data = await medicine.save();
        logActivity(
            loggerStatus.INFO,
            medicine,
            'new medicine added',
            null,
            OPERATIONS.MEDICINE.CREATE,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.MEDICINE.CREATE,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const getAll = async (req, res, next) => {
    try {
        const skipData = req.query.page * 12;
        const medicineData = await Medicine.find().skip(skipData).limit(12);
        const total = await Medicine.find().count();
        logActivity(
            loggerStatus.INFO,
            medicineData,
            'new medicine added',
            null,
            OPERATIONS.MEDICINE.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: { medicineData, total } });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.MEDICINE.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const getMedicine = async (req, res, next) => {
    try {
        const medicineData = await Medicine.findById(req.query.medicineId);
        const updatedData = {
            ...medicineData.toObject(),
            previewImage: 'medicine/drop.png',
            previewTop: 'medicine/dropBack.png',
            previewBottom: 'medicine/dropFront.png',
            previewMiddle: 'medicine/dropTop.png'
        };
        logActivity(
            loggerStatus.INFO,
            updatedData,
            'get a medicine',
            null,
            OPERATIONS.MEDICINE.RETRIEVE_BY_ID,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: updatedData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.MEDICINE.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const updateMedicine = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const nameArray = req.body.name.split(' ');
        const capitalisedName = nameArray.map(
            (word) => `${word[0].toUpperCase()}${word.slice(1).toLowerCase()}`
        );
        const medicineName = capitalisedName.join(' ');
        const medicineData = await Medicine.findByIdAndUpdate(
            req.query.id,
            {
                ...req.body,
                name: medicineName
            },
            { returnOriginal: false }
        );
        logActivity(
            loggerStatus.INFO,
            medicineData,
            'updated a medicine',
            null,
            OPERATIONS.MEDICINE.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: medicineData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.MEDICINE.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const deleteMedicine = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const medicineData = await Medicine.findByIdAndDelete(req.query.id);
        logActivity(
            loggerStatus.INFO,
            medicineData,
            'deleted a medicine',
            null,
            OPERATIONS.MEDICINE.REMOVE,
            StatusCodes.ACCEPTED,
            METHODS.DELETE
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: medicineData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.MEDICINE.REMOVE,
            error.status,
            METHODS.DELETE
        );
        next(error);
    }
};

export const searchedMedicine = async (req, res, next) => {
    try {
        let medicineName = req.query.name;
        medicineName = medicineName[0].toUpperCase() + medicineName.slice(1);
        const medicineData = await Medicine.find({
            name: { $regex: medicineName }
        })
            .sort({ name: 1 })
            .limit(10);

        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: medicineData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.MEDICINE.RETRIEVE,
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
