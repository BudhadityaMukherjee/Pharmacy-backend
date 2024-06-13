import { StatusCodes } from 'http-status-codes';
import Pharmacist from '../models/pharmacistModel.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { verifyRole } from '../services/helper.js';
import Pharmacy from '../models/prarmaDataModel.js';
import otpGenerator from 'otp-generator';
import Otp from '../models/otpModel.js';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import updatePassword from '../validator/passwordDetails.js';
import {
    pharmacistEmailDetails,
    pharmacistPasswordDetails,
    pharmacistRegisterDetails
} from '../validator/pharmacistRegisterDetails.js';
import CustomError from '../services/ErrorHandler.js';
import logActivity from '../services/logActivity.js';
import loggerObject from '../services/loggerObject.js';

const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const register = async (req, res, next) => {
    try {
        pharmacistRegisterDetails.parse(req.body);
        pharmacistPasswordDetails.parse(req.body);
        pharmacistEmailDetails.parse(req.body);
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const { name, image, email } = req.body;
        const pharmacistData = new Pharmacist({
            name,
            image,
            email,
            password: hashedPassword
        });
        await pharmacistData.save();
        const {
            pharmacyName,
            registration_no,
            phone,
            building,
            area,
            landmark,
            pin,
            latitude,
            longitude
        } = req.body;
        const pharmacyData = {
            pharmacistId: pharmacistData._id,
            name: pharmacyName,
            registration_no,
            phone,
            address: { building, area, landmark, pin },
            certificates: [
                `registrations/${req.files[0].filename}`,
                `registrations/${req.files[1].filename}`
            ],
            location: { coordinates: [latitude, longitude] }
        };
        const newPharmacy = new Pharmacy(pharmacyData);
        await newPharmacy.save();
        const response = await Pharmacist.findOneAndUpdate(
            {
                email: req.body?.email
            },
            { pharmacyId: newPharmacy._id }
        );
        logActivity(
            loggerStatus.INFO,
            pharmacistData,
            'pharmacist successfully registered',
            null,
            OPERATIONS.PHARMACIST.CREATE,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data: pharmacistData,
            message: 'pharmacisr registered successfully'
        });
    } catch (error) {
        const pharmacist = await Pharmacist.findOne({ email: req.body.email });
        const pharmacy = await Pharmacy.findOne({
            pharmacistId: pharmacist?._id
        });
        if (pharmacist && !pharmacy) {
            await Pharmacist.deleteOne({ email: req.body.email });
        }
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.CREATE,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const login = async (req, res, next) => {
    try {
        pharmacistPasswordDetails.parse(req.body);
        pharmacistEmailDetails.parse(req.body);
        const userAuth = await Pharmacist.findOne({ email: req.body.email });
        if (!userAuth) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                "User doesn't exist"
            );
        } else {
            const passwordMatch = await bcrypt.compare(
                req.body.password,
                userAuth.password
            );
            if (!passwordMatch) {
                throw new CustomError(
                    StatusCodes.BAD_REQUEST,
                    'password does not match'
                );
            }
            const pharmacy = Pharmacy.findOne({ pharmacistId: userAuth._id });
            if (pharmacy.isApproved === false) {
                throw new Error('You are not yet authorised by the admin');
            }
            const secretKey = process.env.SECRET_KEY;
            const accessToken = jwt.sign(
                {
                    id: userAuth._id,
                    role: 'pharmacist'
                },
                secretKey,
                { expiresIn: '30d' }
            );
            logActivity(
                loggerStatus.INFO,
                null,
                'Login is successful',
                null,
                OPERATIONS.PHARMACIST.LOGIN,
                StatusCodes.ACCEPTED,
                METHODS.POST
            );
            return res.status(StatusCodes.ACCEPTED).json({
                data: { token: accessToken, name: userAuth.name },
                message: 'Succesfully logged in'
            });
        }
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            null,
            OPERATIONS.PHARMACIST.RETRIEVE,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const sendOtp = async (req, res, next) => {
    try {
        if (!(await Pharmacist.findOne({ email: req.body.email }))) {
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                "pharmacist doesn't exist"
            );
        }
        const otp = otpGenerator.generate(4, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false
        });
        console.log(otp);
        const hashedOtp = await bcrypt.hash(otp, 10);
        await Otp.findOneAndDelete({ email: req.body.email });
        const otpData = await Otp.create({
            email: req.body.email,
            otp: hashedOtp
        });
        logActivity(
            loggerStatus.INFO,
            null,
            'pharmacist succesfully Signed in',
            null,
            OPERATIONS.PHARMACIST.SEND_OTP,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data: otpData,
            message: 'Succesfully Signed in'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.SEND_OTP,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const verifyOtp = async (req, res, next) => {
    try {
        const otpData = await Otp.findOne({ email: req.body.email });
        if (otpData === undefined)
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'Otp expired try again'
            );
        const check = await bcrypt.compare(req.body.otp, otpData.otp);
        if (!check) throw new CustomError(StatusCodes.BAD_REQUEST, 'Wrong otp');
        logActivity(
            loggerStatus.INFO,
            null,
            'otp verification successful',
            null,
            OPERATIONS.PHARMACIST.VERIFY_OTP,
            StatusCodes.BAD_REQUEST,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data: null,
            message: 'Access granted'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.VERIFY_OTP,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const getAll = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const pharmacistData = await Pharmacist.find({});
        logActivity(
            loggerStatus.INFO,
            pharmacistData,
            'fetched all pharmacists',
            null,
            OPERATIONS.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: pharmacistData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const getPharmacist = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist', 'admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        const pharmacistData = await Pharmacist.findById(req.id).populate({
            path: 'pharmacyId'
        });
        if (pharmacistData.isBlocked) {
            throw new Error('You have been blocked by the admin');
        }
        // const pharmacyData = await Pharmacy.findOne({ pharmacistId: req.id }).populate({path:'pharmacistId'});
        // const pharmacistData = {
        //     ...data.toObject(),
        //     pharmacyName: pharmacyData.name,
        //     registrationNo: pharmacyData.registration_no
        // };
        logActivity(
            loggerStatus.INFO,
            pharmacistData,
            'fetched a pharmacist',
            null,
            OPERATIONS.RETRIEVE_BY_ID,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data: pharmacistData
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const updatePharmacist = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        pharmacistRegisterDetails.parse(req.body);
        const pharmacistId = req.id;
        const pharmacistData = await Pharmacist.findByIdAndUpdate(
            pharmacistId,
            { name: req.body.name },
            {
                returnOriginal: false
            }
        ).populate({ path: 'pharmacyId' });
        const pharmacyData = await Pharmacy.findOneAndUpdate(
            { pharmacistId: req.id },
            { phone: req.body?.phone },
            {
                returnOriginal: false
            }
        );
        logActivity(
            loggerStatus.INFO,
            pharmacistData,
            'update a pharmacist',
            null,
            OPERATIONS.PHARMACIST.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        const response = await Pharmacist.findById(pharmacistId).populate({
            path: 'pharmacyId'
        });
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: response });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const forgotPassword = async (req, res, next) => {
    try {
        pharmacistPasswordDetails.parse(req.body);
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const usersData = await Pharmacist.findOneAndUpdate(
            { email: req.body.email },
            {
                password: hashedPassword
            },
            {
                returnOriginal: false
            }
        );
        logActivity(
            loggerStatus.INFO,
            null,
            'new password updated',
            null,
            OPERATIONS.PHARMACIST.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: usersData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const deletePharmacist = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const pharmacistId = req.id;
        const pharmacistData = await Pharmacist.findByIdAndDelete(pharmacistId);
        logActivity(
            loggerStatus.INFO,
            pharmacistData,
            'delete a pharmacists',
            null,
            OPERATIONS.PHARMACIST.REMOVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: usersdata });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.REMOVE,
            error.status,
            METHODS.DELETE
        );
        next(error);
    }
};

export const updateProfileImage = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const unmodifiedData = await Pharmacist.findById(req.id);
        if (!unmodifiedData.image.includes('defaultPharmacistImage')) {
            fs.unlink(
                path.join(__dirname, `../assets/${unmodifiedData.image}`),
                function (err) {
                    if (err) throw err;
                }
            );
        }
        const pharmacistData = await Pharmacist.findByIdAndUpdate(
            req.id,
            {
                image: `profileImages/${req.file.filename}`
            },
            {
                returnOriginal: false
            }
        );
        logActivity(
            loggerStatus.INFO,
            pharmacistData,
            'pharmacist profile image updated',
            null,
            OPERATIONS.PHARMACIST.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res
            .status(StatusCodes.ACCEPTED)
            .json({ message: 'success', data: pharmacistData.image });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const updatePharmacistPassword = async (req, res, next) => {
    try {
        if (!verifyRole(['pharmacist'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        updatePassword.parse(req.body);
        let matchOldPassword = await Pharmacist.findById(req.id);
        const checkPassword = await bcrypt.compare(
            req.body.password,
            matchOldPassword.password
        );

        if (!checkPassword)
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                "Old password doesn't match"
            );
        if (bcrypt.compare(req.body.newPassword, matchOldPassword.password))
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'New Password Cannot be your Old password'
            );
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        const pharmacistData = await Pharmacist.findByIdAndUpdate(
            req.id,
            { password: hashedPassword },
            {
                returnOriginal: false
            }
        );
        logActivity(
            loggerStatus.INFO,
            pharmacistData,
            'pharmacist password updated',
            null,
            OPERATIONS.PHARMACIST.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data: pharmacistData.password
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.PHARMACIST.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};
