import { z } from 'zod';

const customerUpdateName = z.object({
    name: z
        .string({ required_error: 'Name is required' })
        .trim()
        .min(2, { message: 'Name must be atleast 2 characters' })
        .max(20, { message: 'Name must be within 20 characters' })
});
const customerUpdatePhone = z.object({
    phone: z
        .string()
        .trim()
        .optional()
        .refine((value) => /^[0-9]{10,10}$/.test(value))
});
export { customerUpdatePhone, customerUpdateName };
