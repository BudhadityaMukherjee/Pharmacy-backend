import mongoose from 'mongoose';

const pharmacistSchema = new mongoose.Schema(
    {
        name: { type: String, required: true },
        image: {
            type: String,
            default: 'profileImages/defaultPharmacistImage.png'
        },
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        pharmacyId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'pharmacy'
        },
        isBlocked: { type: Boolean, required: true, default: false }
    },
    { timestamps: true }
);

const Pharmacist = mongoose.model('pharmacist', pharmacistSchema);

export default Pharmacist;
