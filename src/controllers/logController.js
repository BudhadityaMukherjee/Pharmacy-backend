import Applog from '../models/loggerModel.js';
import moment from 'moment';

export const getAllLogs = async (req, res, next) => {
    try {
        const logdata = await Applog.find({});
        if (logdata && logdata.length > 0) {
            let formatedLog = [];
            logdata.forEach((log) => {
                let logObj = {
                    id: log._id,
                    timestamp: moment(log.timestamp).format(
                        'DD-MM-YYYY HH:mm:ss'
                    ),
                    value: JSON.parse(log.message)
                };
                formatedLog.push(logObj);
            });

            return res.send(formatedLog);
        }
    } catch (e) {
        return res.status(400).json({
            msg: 'No logs found.!! Please try again.'
        });
    }
};
