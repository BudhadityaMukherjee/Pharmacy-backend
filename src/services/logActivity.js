import { logger } from '../config/logger.js';
import { StatusCodes } from 'http-status-codes';

const logActivity = (
    status,
    data,
    errMsg,
    errObj,
    operation,
    statusCode,
    httpMethod
) => {
    const errLog = {
        status,
        data: data,
        statusMsg: errMsg,
        errorObj: errObj,
        operation: operation,
        statusCode: statusCode ? statusCode : StatusCodes.INTERNAL_SERVER_ERROR,
        httpMethod
    };
    if (status === 'info') {
        logger.info(JSON.stringify(errLog));
    } else {
        logger.error(JSON.stringify(errLog));
    }
};

export default logActivity;
