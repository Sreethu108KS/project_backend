import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new mongoose.Schema({
    name : {
        type: String,
        required: [true, "Pleasee provide your name!"],
        minLength: [3, "Name must contain at least 3 characters!"],
        maxLength: [30, "Name cannot exceed 30 characters!"]
    },
    email : {
        type: String,
        required: [true, "Pleasee provide your email!"],
        validate: [validator.isEmail, "Please provide a valid email!"]
    },
    phone : {
        type: Number,
        required: [true, "Pleasee provide your phone number."]
    },
    password : {
        type: String,
        required: [true, "Pleasee provide your password!"],
        minLength: [8, "Password must contain at least 8 characters!"],
        maxLength: [20, "Password cannot exceed 20 characters!"],
        select: false
    }, 
    role : {
        type: String,
        required: [true, "Pleasee provide your role!"],
        enum: ["Job Seeker", "Employer"]
    },    
    createdAt : {
        type: Date,
        default: Date.now
    } 
});

//Hasing the password
userSchema.pre("save", async function(next){
    if (!this.isModified("password")){
        next();
    }
    this.password = await bcrypt.hash(this.password, 10);
});

//comparing password
userSchema.methods.comparePassword = async function (enteredPassword){
    return await bcrypt.compare(enteredPassword,this.password);
};

//generating a JWT token authorization
userSchema.methods.getJWTToken = function(){
    return jwt.sign({id: this._id}, process.env.JWT_SECRET_KEY, {
        expiresIn: process.env.JWT_EXPIRE
    });
};


export const User = mongoose.model("User",userSchema);