import mongoose from 'mongoose';
const { Schema } = mongoose;

const pharmacyDataSchema = new Schema(
    {
        pharmacistId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'pharmacist',
            required: true
        },
        name: {
            type: String,
            required: true
        },
        registration_no: {
            type: String,
            required: true,
            unique: true
        },
        phone: {
            type: Number,
            required: true,
            unique: true
        },
        address: {
            building: { type: String, required: true },
            area: { type: String, required: true },
            landmark: { type: String },
            pin: { type: Number, required: true }
        },
        location: {
            type: {
                type: String,
                enum: ['Point'],
                default: 'Point'
            },
            coordinates: {
                type: [Number],
                required: true
            }
        },
        certificates: [
            {
                type: String,
                required: true
            }
        ],
        isApproved: {
            type: Boolean,
            default: false,
            required: true
        }
    },
    { timestamps: true }
);

pharmacyDataSchema.index({ location: '2dsphere' });

const Pharmacy = mongoose.model('pharmacy', pharmacyDataSchema);

export default Pharmacy;
