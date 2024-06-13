import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        if (file.fieldname === 'certificates') {
            cb(null, path.join(__dirname, '../assets/certificates'));
        } else if (file.fieldname === 'prescription') {
            cb(null, path.join(__dirname, '../assets/prescriptions'));
        } else if (file.fieldname === 'profile') {
            cb(null, path.join(__dirname, '../assets/profileImages'));
        }
    },
    filename: (req, file, cb) => {
        const file_name = Date.now() + '-' + file.originalname;
        cb(null, file_name);
    }
});

const upload = multer({ storage: storage });

export const certificateUpload = (req, res, next) => {
    try {
        upload.array('certificates', 2)(req, res, function (err) {
            next();
        });
    } catch (error) {
        console.log(error.message);
    }
};

export const prescriptionUpload = (req, res, next) => {
    try {
        upload.array('prescription', 2)(req, res, function (err) {
            next();
        });
    } catch (error) {
        console.log(error.message);
    }
};

export const profileImageUpload = (req, res, next) => {
    try {
        upload.single('profile')(req, res, function (err) {
            next();
        });
    } catch (error) {
        console.log(error.message);
    }
};
