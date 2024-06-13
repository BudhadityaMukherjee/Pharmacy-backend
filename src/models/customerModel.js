import mongoose from 'mongoose';

const { Schema } = mongoose;

const userSchema = new Schema(
    {
        name: { type: String, lowercase: true, default: 'Skyler123' },
        addressId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'customer-address'
        },
        image: { type: String, default: 'profileImages/defaultImage.png' },
        phone: { type: String },
        email: { type: String, required: true, lowercase: true },
        dob: { type: Date },
        isBlocked: { type: Boolean, required: true, default: false }
    },
    { timestamps: true }
);

const Customer = mongoose.model('customer', userSchema);
export default Customer;
