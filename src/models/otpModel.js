import mongoose from 'mongoose';

const { Schema } = mongoose;

const otpSchema = new Schema(
    {
        email: { type: String, lowercase: true, required: true },
        otp: { type: String }
    },
    { timestamps: true }
);

const Otp = mongoose.model('otpData', otpSchema);

export default Otp;
