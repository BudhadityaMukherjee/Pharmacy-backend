import mongoose from 'mongoose';
const { Schema } = mongoose;

const adminSchema = new Schema(
    {
        name: { type: String },
        email: { type: String, required: true, lowercase: true },
        password: { type: String, required: true },
        phone: { type: String, required: true },
        image: { type: String, default: 'profileImages/defaultImage.png' },
        address: {
            building: { type: String, required: true },
            area: { type: String, required: true },
            landmark: { type: String },
            pin: { type: Number, required: true }
        }
    },
    { timestamps: true }
);

const Admin = mongoose.model('admin', adminSchema);
export default Admin;
