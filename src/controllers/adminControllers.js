import Admin from '../models/adminModel.js';
import { StatusCodes } from 'http-status-codes';
import { verifyRole } from '../services/helper.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import adminUpdateDetails from '../validator/adminUpdateDetails.js';
import updatePassword from '../validator/passwordDetails.js';
import loggerObject from '../services/loggerObject.js';
import CustomError from '../services/ErrorHandler.js';
import logActivity from '../services/logActivity.js';
const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const adminLogin = async (req, res, next) => {
    try {
        const adminData = await Admin.findOne({ email: req.body.email });
        if (!adminData)
            throw new CustomError(StatusCodes.NOT_FOUND, 'Email not found!');
        const checkPassword = await bcrypt.compare(
            req.body.password,
            adminData.password
        );
        if (!checkPassword)
            throw new CustomError(StatusCodes.BAD_REQUEST, 'Invalid password!');

        const secretKey = process.env.SECRET_KEY;
        const accessToken = jwt.sign(
            {
                id: adminData._id,
                role: 'admin'
            },
            secretKey,
            { expiresIn: '30d' }
        );
        logActivity(
            loggerStatus.INFO,
            null,
            'Admin Successfully logged in',
            null,
            OPERATIONS.ADMIN.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data: {
                token: accessToken,
                loggedAt: new Date()
            },
            message: 'Succesfully Signed in'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.ADMIN.RETRIEVE,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const getAdminDetails = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }
        const adminData = await Admin.findById(req.id);
        logActivity(
            loggerStatus.INFO,
            adminData,
            'Admin details fetched',
            null,
            OPERATIONS.ADMIN.RETRIEVE_BY_ID,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data: adminData
        });
    } catch (error) {
        logActivity(
            loggerStatus.INFO,
            null,
            error.message,
            error,
            OPERATIONS.ADMIN.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const registerAdmin = async (req, res, next) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const adminData = new Admin({
            email: req.body.email,
            name: req.body.name,
            password: hashedPassword,
            phone: req.body.phone,
            address: { ...req.body.address }
        });
        await adminData.save();
        // logActivity(loggerStatus.INFO, null, error.message, error, OPERATIONS.ADMIN.CREATE, StatusCodes.ACCEPTED, METHODS.POST);
        return res.status(StatusCodes.ACCEPTED).json({
            data: { adminData: adminData },
            message: 'Succesfully Registered'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.ADMIN.CREATE,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const updateAdminDetails = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        adminUpdateDetails.parse(req.body);
        const adminData = await Admin.findByIdAndUpdate(req.id, req.body, {
            returnOriginal: false
        });
        logActivity(
            loggerStatus.INFO,
            adminData,
            'Admin details updated',
            null,
            OPERATIONS.ADMIN.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );

        return res.status(StatusCodes.OK).json({
            message: 'success',
            data: {
                name: adminData.name,
                email: adminData.email,
                address: {
                    building: adminData.address.building,
                    area: adminData.address.area,
                    landmark: adminData.address.landmark,
                    pin: adminData.address.pin
                },
                phone: adminData.phone
            }
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.ADMIN.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const updateAdminPassword = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        updatePassword.parse(req.body);
        let matchOldPassword = await Admin.findById(req.id);
        const checkPassword = await bcrypt.compare(
            req.body.password,
            matchOldPassword.password
        );

        if (!checkPassword) throw new CustomError("Old password doesn't match");
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        const adminData = await Admin.findByIdAndUpdate(
            req.id,
            { password: hashedPassword },
            {
                returnOriginal: false
            }
        );
        logActivity(
            loggerStatus.INFO,
            adminData,
            'Admin password updated',
            null,
            OPERATIONS.ADMIN.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data: adminData.password
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            null,
            OPERATIONS.ADMIN.MODIFY,
            error.status,
            METHODS.PUT
        );

        next(error);
    }
};

export const adminProfileImage = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const unmodifiedData = await Admin.findById(req.id);
        if (!unmodifiedData.image.includes('defaultImage')) {
            fs.unlink(
                path.join(__dirname, `../assets/${unmodifiedData.image}`),
                function (err) {
                    if (err) throw err;
                }
            );
        }
        const adminData = await Admin.findByIdAndUpdate(
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
            adminData,
            'Admin profile image updated',
            null,
            OPERATIONS.ADMIN.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res
            .status(StatusCodes.OK)
            .json({ message: 'success', data: adminData.image });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error.status,
            OPERATIONS.ADMIN.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};
