import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { StatusCodes } from 'http-status-codes';
import CustomError from '../services/ErrorHandler.js';
import logActivity from '../services/logActivity.js';
import loggerObject from '../services/loggerObject.js';

const { OPERATIONS, loggerStatus, METHODS } = loggerObject;
dotenv.config();

const secretKey = process.env.SECRET_KEY;

const validateToken = async (req, res, next) => {
    try {
        let token;
        let authHeader = req.headers.Authorization || req.headers.authorization;

        if (authHeader && authHeader.startsWith('Bearer')) {
            token = authHeader.split(' ')[1];
            jwt.verify(token, secretKey, (error, decoded) => {
                if (error) {
                    throw new CustomError(
                        StatusCodes.UNAUTHORIZED,
                        'User is not authorized'
                    );
                }
                req.id = decoded.id;
                req.role = decoded.role;
                next();
            });
        } else {
            throw new CustomError(
                StatusCodes.BAD_REQUEST,
                'Token is missing!!!'
            );
        }
    } catch (error) {
        logActivity(
            loggerStatus.ERROR,
            null,
            error.message,
            error,
            OPERATIONS.AUTHENTICATION,
            error.status
        );
        next(error);
    }
};

export default validateToken;
