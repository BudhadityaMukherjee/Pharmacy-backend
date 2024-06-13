import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'kkeshavkumar1209@gmail.com',
        pass: process.env.PASSWORD
    }
});

export function sendEmail(email, otp) {
    transporter.sendMail({
        from: '"Pharmacy App Team" <kkeshavkumar1209@gmail.com>',
        to: `${email}`,
        subject: 'OTP VERIFICATION',
        html: `<div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2"><div style="margin:50px auto;width:70%;padding:20px 0"><div style="border-bottom:1px solid #eee"><a href="" style="font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600">Pharmacy APP</a></div><p style="font-size:1.1em">Hi,</p><p>Thank you for choosing Our Brand. Use the following OTP to change your password. OTP is valid for 5 minutes</p><h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">${otp}</h2><p style="font-size:0.9em;">Regards,<br />Pharmacy App</p><hr style="border:none;border-top:1px solid #eee" /><div style="float:right;padding:8px 0;color:#aaa;font-size:0.8em;line-height:1;font-weight:300"><p>Pharmacy App Inc</p><p>DN-53 , Kolkata</p><p>West Bengal</p></div></div></div>`
    });
}
