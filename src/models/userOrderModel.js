import mongoose from 'mongoose';

const userOrderSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'customer',
            required: true
        },
        medicines: [
            {
                medicineId: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'medicines',
                    required: true
                },
                quantity: {
                    type: Number,
                    required: true
                }
            }
        ],
        prescriptions: [
            {
                type: String
            }
        ],
        status: {
            type: String,
            enum: ['pending', 'confirmed', 'delivered'],
            default: 'pending'
        },
        address: {
            building: { type: String, required: true },
            area: { type: String, required: true },
            city: { type: String, required: true },
            state: { type: String, required: true },
            postcode: { type: Number, required: true },
            country: { type: String, required: true }
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
        }
    },
    { timestamps: true }
);

userOrderSchema.index({ location: '2dsphere' });

const UserOrder = mongoose.model('userOrder', userOrderSchema);

export default UserOrder;
