import { model, Schema, Document } from 'mongoose';
import  bcrypt from 'bcrypt'; 

export interface IUser extends Document {
  email: string;
  password: string;
  comparePassword: (password: string) => Promise<boolean>;
}

const userSchema = new Schema({
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  }
});

// cifrar contraseña
userSchema.pre<IUser>('save', async function (next) {
    const user = this;
    if (!user.isModified('password')) return next(); // basicamente si el usuario es nuevo continua con eñl codigo

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(user.password, salt);
    user.password = hash;
    next();
});

userSchema.methods.comparePassword = async function (password: string): Promise<boolean> {
  return await bcrypt.compare(password, this.password)
}

export default model<IUser>('User', userSchema);