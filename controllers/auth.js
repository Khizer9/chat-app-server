const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const crypto = require('crypto');

const User = require('../models/user');
const filterObj = require('../utils/filterObj');
const { promisify } = require('util');

const signToken = (userId) => jwt.sign({userId}, process.env.JWT_SECRET);

// Register new User

exports.register = async (req, res, next) => {
    const {firstName, lastName, email, password} = req.body;

    const filterBody = filterObj(req.body, 'firstName', 'lastName', 'password', 'email');

    const existingUser = await User.findOne({email: email});

    if(existingUser && existingUser.verified){
        res.status(400).json({
            status: 'error',
            message: 'Email is already in use, Please login!',
        })
    }else if(existingUser){
        await User.findOneAndUpdate({email: email}, filterBody, {new: true, validateModifiedOnly: true} )

        req.userId = existingUser._id;
        next();
    }else{
        // if user record is not available in DB
        const new_user = await User.create(filterBody)

        // generate OTP and send email to user
        req.userId = existingUser._id;
        next();
    }
}

exports.sendOTP = async (req, res, next) => {
    const {userId} = req

    const new_otp = otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false })

    const otp_expiry_time = Date.now() + 10*60*1000 // 10 mints

    await User.findByIdAndUpdate(userId, {
        otp: new_otp,
        otp_expiry_time,
    });

    // send email

    res.status(200).json({
        status: 'success',
        message: 'OTP send successfully!',
    })
}

exports.verifyOTP = async (req, res, next) => {
    // verify OTP and update user record acordingly

    const {email, otp} = req.body;

    const user = await User.findOne({
        email,
        otp_expiry_time: {$gt: Date.now()}
    })

    if(!user){
        res.status(400).json({
            status:'error',
            message: 'Email is invalid or OTP is expired!'
        })
    }

    if(!await user.correctOTP(otp, user.otp)){
        res.status(400).json({
            status:'error',
            message: 'OTP is incorrect!'
        })
    }

    // OTP is correct 

    user.verified = true;
    user.otp = undefined;

    await user.save({new: true, validateModifiedOnly: true})

    const token = signToken(user._id);

    res.status(200).json({
        status: 'success',
        message: 'OTP verified successfully!',
        token,
    })
}
exports.login = async (req, res, next) => {
    const {email, password} = req.body;

    if(!email || !password){
        res.status(400).json({
            status: 'error',
            message: 'Email and password both are required!'
        })
    }

    const userDoc = await User.findOne({email: email}).select('+password');
    console.log(userDoc, "UserDoc")

    if(!userDoc || !(await userDoc.correctPassword(password, userDoc.password))){
        res.status(400).json({
            status: "error",
            message: 'Email or Password is incorrect!',
        })
    }

    const token = signToken(userDoc._id);

    res.status(200).json({
        status: 'success',
        message: 'Logged in successfully!',
        token,
    })
};

exports.protect = async (req, res, next) => {
   // Getting token (JWT) and check if its true
   let token;

   if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
    token = req.headers.authorization.split(" ")[1]

   }
    else if(req.cookies.jwt){
        token = req.cookies.jwt
    }else{
        res.status(400).json({
            status: 'error',
            message: 'You are not loggedin!, Please Login to get access.'
        })

        return;
    }

    // Verification of token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET)

    // Check user is still exists
    const this_user = await User.findById(decoded.userId);

    if(!this_user){
        res.status(400).json({
            status: 'error',
            message: 'The User doesnot exist!'
        })
    }

    // Check if user change their password after token was issued
    if(this_user.changePasswordAfter(decoded.iat)){
        res.status(400).json({
            status: 'error',
            message: 'User recently change the password, Please login again!'
        })
    }
    
    req.user = this_user;
    next();
   }


exports.forgotPassword = async (req, res, next) => {
     // 1. Get user email
     const user = await User.findOne({email: req.body.email});

     if(!user){
         res.status(400).json({
             status:'error',
             message:'There is no user with given email address',
         })
         return;
     }
 
     // 2. Generate random reset token
     const resetToken = user.createPasswordResetToken();
 
     const resetURL = `https://tawk.com/auth/reset-password/?code=${resetToken}`
 
     try {
         // TODO => send email with reset URL
 
         res.status(200).json({
             status: 'success',
             message: 'Reset Password link send to email',
         })
     } catch (error) {
         user.passwordResetToken = undefined;
         user.passwordResetExpires = undefined
 
         await user.save({validateBeforeSave: false});   
 
         res.status(500).json({
             status:'error',
             message:'There was an error sending email, Please try again later!'
         })
     }
}

exports.resetPassword = async (req, res, next) => {
    // 1. Get user based on token
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: {$gt: Date.now()},
    });

    // If token has expired || user is out of time 

    if(!user){
        res.status(400).json({
            status:'error',
            message: 'Token is invalid or expired!'
        })
        return;
    }

    // update user password and set reset token and expiry to undefined.
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;

    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

    // login user and send new jwt // send alert to user about password reset.
    const token = signToken(user._id)

    res.status(200).json({
        status: 'success',
        message: 'Password reset successfully!',
        token,
    })

}