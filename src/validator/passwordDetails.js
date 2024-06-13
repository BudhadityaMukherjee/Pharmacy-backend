import { z } from 'zod';

const updatePassword = z.object({
    password: z.string({ required_error: 'Old Password is required' }),
    newPassword: z
        .string()
        .min(6, { message: 'Password must be atleast 6 characters' })
        .max(16, { message: 'Password shold be less than 16 characters' })
        .refine((value) => /^[a-zA-Z0-9!@#$%^&*]{6,16}$/.test(value))
});
export default updatePassword;
