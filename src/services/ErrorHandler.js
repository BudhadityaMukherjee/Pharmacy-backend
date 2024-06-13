import { StatusCodes } from 'http-status-codes';

class CustomError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status ? status : StatusCodes.BAD_REQUEST;
        this.message = message ? message : 'An error has Occured';
    }
}
export default CustomError;
