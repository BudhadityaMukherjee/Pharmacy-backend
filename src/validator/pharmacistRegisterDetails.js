import { z } from 'zod';

const pharmacistRegisterDetails = z.object({
    name: z
        .string({ required_error: 'Name is required' })
        .trim()
        .min(2, { message: 'Name must be atleast 2 characters' })
        .max(20, { message: 'Name must be within 20 characters' }),
    phone: z
        .string()
        .trim()
        .min(10, { message: 'Phone number must be atleast 10 digits' })
        .max(10, { message: 'Phone number must be within 10 digits' })
        .refine((value) => /^[0-9]{10,10}$/.test(value), {
            message: 'Mobile Number Invalid'
        })
});

const pharmacistEmailDetails = z.object({
    email: z
        .string({ required_error: 'email is required' })
        .email({ message: 'email is not valid' })
        .trim()
});

const pharmacistPasswordDetails = z.object({
    password: z
        .string({ required_error: 'password is required' })
        .min(6, { message: 'Password must be atleast 6 characters' })
        .max(16, { message: 'Password shold be less than 16 characters' })
        .refine((value) => /^[a-zA-Z0-9!@#$%^&*]{6,16}$/.test(value))
});

export {
    pharmacistPasswordDetails,
    pharmacistRegisterDetails,
    pharmacistEmailDetails
};
