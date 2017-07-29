import * as bcrypt from "bcrypt-nodejs";
import * as mongoose from "mongoose";
import * as crypto from "crypto";

export type UserModel = mongoose.Document & {
  email: string,
  password: string,
  tokenId: string,

  facebook: string,

  profile: {
    displayName: string,
    picture: string
  },

  comparePassword: (candidatePassword: string, cb: (err: any, isMatch: any) => {}) => void
};

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, index: true },
  password: String,
  tokenId: String,

  facebook: String,

  profile: {
    displayName: String,
    picture: String
  }

});

/**
 * Password hash middleware.
 */
userSchema.pre("save", function save(next) {
  const user = this;
  if (!user.isModified("password")) { return next(); }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) { return next(err); }
    bcrypt.hash(user.password, salt, undefined, (err: mongoose.Error, hash) => {
      if (err) { return next(err); }
      user.password = hash;
      next();
    });
  });
});

/**
 * Helper method for getting user's gravatar.
 */
userSchema.methods.gravatar = function (size: number) {
  if (!size) {
    size = 200;
  }
  if (!this.email) {
    return `https://gravatar.com/avatar/?s=${size}&d=retro`;
  }
  const md5 = crypto.createHash("md5").update(this.email).digest("hex");
  return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};


userSchema.methods.comparePassword = function (candidatePassword: string, cb: (err: any, isMatch: any) => {}) {
  bcrypt.compare(candidatePassword, this.password, (err: mongoose.Error, isMatch: boolean) => {
    cb(err, isMatch);
  });
};

export const User = mongoose.model<UserModel>("User", userSchema);