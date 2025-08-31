import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE , PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    // ✅ Check for missing fields
    if (!name || !email || !password) {
        return res.json({ success: false, message: 'Missing details' });
    }

    try {
        // ✅ Check if the user already exists
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.json({ success: false, message: "User already exists" });
        }

        // ✅ Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // ✅ Save new user
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        // ✅ Generate JWT token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        // ✅ Set cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        //sending Welcome Email
        const mailOptions = {
            from:process.env.SENDER_EMAIL,
            to:email,
            subject : 'Welcomt to Auth App',
            text : `Welcome to Quth App your account has been created with email id : ${email}`

        }

        await transporter.sendMail(mailOptions)

        return res.json({ success: true, message: "Registration successful", token });
    } 
    
    
    catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;

    // ✅ Check for missing fields
    if (!email || !password) {
        return res.json({ success: false, message: 'Email and password are required' });
    }

    try {
        // ✅ Find user
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: 'Invalid email' });
        }

        // ✅ Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid password' });
        }

        // ✅ Generate JWT token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        // ✅ Set cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.json({ success: true, message: "Login successful", token });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

// ✅ Logout function
export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        return res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};


//send verification otp to the users Email

export const sendVerifyOtp = async(req,res) =>{
    try{
        const {userId} =  req.body;
        const user = await userModel.findById(userId)

        if(user.isAccountVerified){
            return res.json({success:false , message: "Account has been already verified"})

        }

        const otp = String(Math.floor(100000 +  Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24*60*60*1000
        await user.save();

        const mailOptions = {
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject : 'Account verification OtP',
            // text : `Your  Otp is ${otp} . Verify your account using this OTP `,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp). replace("{{email}}" , user.email)

        }
    await transporter.sendMail(mailOptions)

    res.json({success:true , message:"Verification OTP send to the Email"})


    }

catch(error){
res.json({success:false , message: error.message})
}}

//verify Email 
export const verifyEmail = async(req,res)=>{
const {userId, otp} = req.body;

if(!userId || !otp){
    return res.json({success:false , message: "Missing Details"})

}
try {
    
    const user = await userModel.findById(userId)
    if(!user){
        return res.json({success: false , messsage:"User not found "})
    }

    if(user.verifyOtp === '' || user.verifyOtp !==otp) {
        return res.json({success:false , message:"Invalid Otp"});
        
    }

    if(user.verifyOtpExpiresAt < Date.now()){
        return res.json({success:false , message:"OTP expired !! "})
    }

    user.isAccountVerified = true;

    user.verifyOtp = '';
    user.verifyOtpExpireAt = 0;

    await user.save();

    return res.json({success:true , message:"Email verified successfully "})

} catch (error) {
    return json({success:false , message: error.message})
    
}
}


//Is authenticated or not

export const isAuthenticated = async (req , res)=>{
    try {
        
        return res.json({success:true})

    } catch (error) {
        res.json({success:false , message:error.message})
        
    }
}

// Send Password Reset OTP
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ success: false, message: "Email is required" });
    }

    try {
        // ✅ Find user by email
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        // ✅ Generate 6-digit OTP
        const otp = String(Math.floor(100000 + Math.random() * 900000));

        // ✅ Store OTP in database with expiration time (10 minutes)
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 10 * 60 * 1000; // 10 minutes from now
        await user.save();

        // ✅ Email details
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Your OTP for resetting your password is ${otp}. Reset your password using this OTP.`,
            html: PASSWORD_RESET_TEMPLATE . replace("{{otp}}" , otp).replace("{{email}}" , user.email)
        };

        // ✅ Send email
        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: "OTP sent to your email" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

// Reset User Password
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: "Email, OTP, and new password are required" });
    }

    try {
        // ✅ Find user by email
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        // ✅ Check if OTP is expired
        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP expired" });
        }

        // ✅ Check if OTP is correct
        if (user.resetOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        // ✅ Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // ✅ Update user password and clear OTP fields
        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;

        await user.save();

        return res.json({ success: true, message: "Password has been reset successfully" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};