import { z } from 'zod';

const adminUpdateDetails = z.object({
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
        }),
    email: z
        .string({ required_error: 'email is required' })
        .email({ message: 'email is not valid' })
        .trim()
});

export default adminUpdateDetails;
