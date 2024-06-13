import { StatusCodes } from 'http-status-codes';
import Customer from '../models/customerModel.js';
import Cart from '../models/cartModel.js';
import jwt from 'jsonwebtoken';
import { sendEmail } from '../services/nodeMailer.js';
import otpGenerator from 'otp-generator';
import Otp from '../models/otpModel.js';
import bcrypt from 'bcrypt';
import { verifyRole } from '../services/helper.js';
import Address from '../models/addressModel.js';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import {
    customerUpdateName,
    customerUpdatePhone
} from '../validator/customerUpdateDetails.js';
import customerLoginDetails from '../validator/customerLoginDetails.js';
import logActivity from '../services/logActivity.js';
import loggerObject from '../services/loggerObject.js';
import CustomError from '../services/ErrorHandler.js';
const { OPERATIONS, loggerStatus, METHODS } = loggerObject;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const getAllCustomer = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const customersData = await Customer.find()
            .skip(req.query.page * 10)
            .limit(10)
            .populate({ path: 'addressId' });
        const totalCustomer = await Customer.find().count();
        logActivity(
            loggerStatus.INFO,
            totalCustomer,
            'All Customers fetched',
            null,
            OPERATIONS.CUSTOMERS.RETRIEVE,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            total: totalCustomer,
            data: customersData
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CUSTOMERS.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const searchedCustomer = async (req, res, next) => {
    try {
        if (!verifyRole(['admin'], req.role)) {
            throw new Error('User not authorised');
        }
        const customersData = await Customer.find({
            name: { $regex: req.query.name, $options: 'i' }
        })
            .limit(10)
            .populate({ path: 'addressId' });
        return res.status(StatusCodes.OK).json({
            message: 'success',
            data: customersData
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CUSTOMERS.RETRIEVE,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const getCustomer = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        let customerData = await Customer.findById(req.id);
        if (customerData?.dob)
            customerData = {
                ...customerData.toObject(),
                dob: `${customerData?.dob?.toISOString()?.substring(0, 10)}`
            };
        logActivity(
            loggerStatus.INFO,
            customerData,
            'Fetched Customer Data',
            null,
            OPERATIONS.CUSTOMERS.RETRIEVE_BY_ID,
            StatusCodes.ACCEPTED,
            METHODS.GET
        );
        return res.status(StatusCodes.ACCEPTED).json({
            message: 'success',
            data: customerData
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CUSTOMERS.RETRIEVE_BY_ID,
            error.status,
            METHODS.GET
        );
        next(error);
    }
};

export const sendOtp = async (req, res, next) => {
    try {
        customerLoginDetails.parse(req.body);
        await Otp.findOneAndDelete({ email: req.body.email });
        const otp = otpGenerator.generate(4, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false
        });
        console.log(otp);
        // sendEmail(req.body.email,otp);
        const hashedOtp = await bcrypt.hash(otp, 10);
        const otpData = new Otp({
            email: req.body.email,
            otp: hashedOtp
        });
        await otpData.save();
        logActivity(
            loggerStatus.INFO,
            null,
            'otp sent successfully',
            null,
            OPERATIONS.CUSTOMERS.OTP,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res
            .status(StatusCodes.OK)
            .json({ message: 'success', data: hashedOtp });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CUSTOMERS.OTP,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const verifyOtp = async (req, res, next) => {
    try {
        const dbData = await Otp.findOne({ email: req.body.email });
        if (!dbData)
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'Otp expired please generate a new otp!!!'
            );
        const userAuth = await bcrypt.compare(req.body.otp, dbData.otp);
        if (!userAuth)
            throw new CustomError(StatusCodes.BAD_REQUEST, 'Enter a valid Otp');

        const oldCustomer = await Customer.findOne({ email: req.body.email });
        if (oldCustomer && oldCustomer.isBlocked === true)
            throw new CustomError(StatusCodes.BAD_REQUEST, 'Enter a valid Otp');

        if (!oldCustomer) {
            const customerData = new Customer({
                ...req.body
            });
            await customerData.save();
            const findCustomer = await Customer.findOne({
                email: req.body.email
            });
            const createCart = new Cart({
                userId: findCustomer._id
            });
            await createCart.save();
        }
        const CustomerData = await Customer.findOne({ email: req.body.email });
        const secretKey = process.env.SECRET_KEY;
        const accessToken = jwt.sign(
            {
                id: CustomerData._id,
                role: 'user'
            },
            secretKey,
            { expiresIn: '1d' }
        );
        logActivity(
            loggerStatus.INFO,
            null,
            'Otp verified successfully',
            null,
            OPERATIONS.CUSTOMERS.VERIFY_OTP,
            StatusCodes.ACCEPTED,
            METHODS.POST
        );
        return res.status(StatusCodes.ACCEPTED).json({
            data: {
                token: accessToken,
                customerData: CustomerData,
                TTL: '1d',
                loggedAt: new Date()
            },
            message: 'Succesfully Signed in'
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error.status,
            OPERATIONS.CUSTOMERS.VERIFY_OTP,
            error.status,
            METHODS.POST
        );
        next(error);
    }
};

export const updateCustomer = async (req, res, next) => {
    try {
        if (!verifyRole(['user', 'admin'], req.role)) {
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );
        }

        if (req.body.phone !== '' && req?.body?.phone !== undefined) {
            customerUpdatePhone.parse(req.body);
        }
        if (req.body.name !== '' && req?.body?.name !== undefined) {
            customerUpdateName.parse(req.body);
        }
        let id = req.id;
        if (req.role === 'admin') {
            id = req.query.id;
        }
        const customersData = await Customer.findByIdAndUpdate(id, req.body, {
            returnOriginal: false
        });
        logActivity(
            loggerStatus.INFO,
            customersData,
            'Customer updated',
            null,
            OPERATIONS.CUSTOMERS.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res
            .status(StatusCodes.OK)
            .json({ message: 'success', data: customersData });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CUSTOMERS.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const updateProfileImage = async (req, res, next) => {
    try {
        if (!verifyRole(['user'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const unmodifiedData = await Customer.findById(req.id);
        if (!unmodifiedData.image.includes('defaultImage')) {
            fs.unlink(path.join(__dirname, `../assets/${unmodifiedData.image}`), function (err) {
                if (err) console.log(err);
            });
        }
        const customersData = await Customer.findByIdAndUpdate(
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
            customersData,
            'customer profile image updated',
            null,
            OPERATIONS.CUSTOMERS.MODIFY,
            StatusCodes.ACCEPTED,
            METHODS.PUT
        );
        return res
            .status(StatusCodes.OK)
            .json({ message: 'success', data: customersData.image });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CUSTOMERS.MODIFY,
            error.status,
            METHODS.PUT
        );
        next(error);
    }
};

export const deleteCustomer = async (req, res, next) => {
    try {
        if (!verifyRole(['user', 'admin'], req.role))
            throw new CustomError(
                StatusCodes.UNAUTHORIZED,
                'User not authorised'
            );

        const id = req.role === 'admin' ? req.query.id : req.id;
        const customersData = await Customer.findByIdAndDelete(id);
        await Cart.findOneAndDelete({ userId: id });
        await Address.deleteMany({ userId: id });
        const totalCustomer = await Customer.find().count();
        logActivity(
            loggerStatus.INFO,
            customersData,
            'Customer deleted successfully',
            null,
            OPERATIONS.CUSTOMERS.REMOVE,
            StatusCodes.ACCEPTED,
            METHODS.DELETE
        );
        return res.status(StatusCodes.OK).json({
            message: 'success',
            data: customersData,
            totalCustomer: totalCustomer
        });
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.CUSTOMERS.REMOVE,
            error.status,
            METHODS.DELETE
        );
        next(error);
    }
};

export const wrongUrl = async (req, res) => {
    res.status(StatusCodes.BAD_REQUEST).json({
        data: null,
        message: 'Wrong url'
    });
};
