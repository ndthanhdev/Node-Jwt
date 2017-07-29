import { Request, Response, NextFunction } from "express";
import { User, UserModel } from "../models/User";
import * as passport from "passport";
import * as jwt from "jsonwebtoken";
import { JwtOptions } from "../config/passport";
import { ApiMessage } from "../dto/ApiMessage";
import { v1 as uuidv1 } from "uuid";
import { WriteError } from "mongodb";
const request = require("express-validator");

/**
 * POST /login
 * Sign in using email and password.
 */
export let postLogin = (req: Request, res: Response, next: NextFunction) => {
    req.assert("email", "Email is not valid").isEmail();
    req.assert("password", "Password cannot be blank").notEmpty();
    req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

    const errors = req.validationErrors();

    if (errors) {
        // Parameter error
        return res.json(new ApiMessage(1, errors));
    }

    User.findOne({ email: req.body.email.toLowerCase() }, (err, user) => {
        if (err) {
            //  Database error
            return next(err);
        }
        if (!user) {
            //  User isn't exist
            return res.json(new ApiMessage(2));
        }
        user.comparePassword(req.body.password, (password_err: Error, isMatch: boolean) => {
            if (password_err) {
                //  Password is incorrect
                return res.json(new ApiMessage(3));
            }
            if (isMatch) {
                const token = generateJwt(user);
                return res.json(new ApiMessage(0, token));
            }
            else {
                //  Password isn't match
                return res.json(new ApiMessage(4));
            }
        });
    });
};

/**
 * GET /logout
 */
export let getLogout = (req: Request, res: Response, next: NextFunction) => {
    User.findById(req.user.id, (err, existingUser) => {
        if (err) {
            //  Database error
            return next(err);
        }
        if (!existingUser) {
            // Account with that id address is not exists.
            return res.json(new ApiMessage(1));
        }
        existingUser.tokenId = "";
        existingUser.save((err) => {
            if (err) { return next(err); }
            res.json(new ApiMessage(0));
        });
    });


};

/**
 * POST /signup
 * Create a new local account.
 */
export let postSignup = (req: Request, res: Response, next: NextFunction) => {
    req.assert("email", "Email is not valid").isEmail();
    req.assert("password", "Password must be at least 4 characters long").len({ min: 4 });
    req.assert("confirmPassword", "Passwords do not match").equals(req.body.password);
    req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });
    req.assert("displayName", "DisplayName must be at least 3 characters long").len({ min: 4 });
    const errors = req.validationErrors();

    if (errors) {
        // Invalid parameter.
        return res.json(new ApiMessage(1, errors));
    }

    const user = new User({
        email: req.body.email,
        password: req.body.password,
        profile: {
            displayName: req.body.displayName
        }
    });

    User.findOne({ email: req.body.email }, (err, existingUser) => {
        if (err) {
            //  Database error
            return next(err);
        }
        if (existingUser) {
            // Account with that email address already exists.
            return res.json(new ApiMessage(2));
        }
        user.save((err) => {
            if (err) { return next(err); }
            res.json(new ApiMessage(0));
        });
    });
};

/**
 * GET /auth/facebook/callback
 * Generate jwt from facebook's callback request
 */
export let getAuthFacebookCallback = (req: Request, res: Response, next: NextFunction) => {
    const token = generateJwt(req.user);
    return res.json(new ApiMessage(0, token));
};

/**
 * POST /account/profile
 * Update profile information.
 */
export let postUpdateProfile = (req: Request, res: Response, next: NextFunction) => {
    req.assert("email", "Please enter a valid email address.").isEmail();
    req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });
    req.assert("displayName", "DisplayName must be at least 3 characters long").len({ min: 4 });

    const errors = req.validationErrors();

    if (errors) {
        // Parameter errors
        return res.json(new ApiMessage(1, errors));
    }

    User.findById(req.user.id, (err, user: UserModel) => {
        if (err) {
            //  Database error
            return next(err);
        }
        user.email = req.body.email || "";
        user.profile.displayName = req.body.displayName || "";
        user.save((err: WriteError) => {
            if (err) {
                if (err.code === 11000) {
                    // The email address you have entered is already associated with an account.
                    return res.json(new ApiMessage(2));
                }
                return next(err);
            }
            // Profile information has been updated.
            return res.json(new ApiMessage(0));
        });
    });
};

/**
 * POST /account/password
 * Update current password.
 */
export let postUpdatePassword = (req: Request, res: Response, next: NextFunction) => {
    req.assert("password", "Password must be at least 4 characters long").len({ min: 4 });
    req.assert("confirmPassword", "Passwords do not match").equals(req.body.password);

    const errors = req.validationErrors();

    if (errors) {
        // Parameter errors
        return res.json(new ApiMessage(1, errors));
    }

    User.findById(req.user.id, (err, user: UserModel) => {
        if (err) {
            //  Database error
            return next(err);
        }
        user.password = req.body.password;
        user.save((err: WriteError) => {
            if (err) {
                //  Database error
                return next(err);
            }
            // Password has been changed.
            res.json(new ApiMessage(0));
        });
    });
};

/**
 * POST /account/delete
 * Delete user account.
 */
export let postDeleteAccount = (req: Request, res: Response, next: NextFunction) => {
    User.remove({ _id: req.user.id }, (err) => {
        if (err) {
            //  Database error
            return next(err);
        }
        // Account has been deleted.
        res.json(new ApiMessage(0));
    });
};

/**
 * GET /account/unlink/:provider
 * Unlink OAuth provider.
 */
// export let getOauthUnlink = (req: Request, res: Response, next: NextFunction) => {
//     const provider = req.params.provider;
//     User.findById(req.user.id, (err, user: any) => {
//         if (err) {
//             //  Database error
//             return next(err);
//         }
//         user[provider] = undefined;
//         user.tokens = user.tokens.filter((token: AuthToken) => token.kind !== provider);
//         user.save((err: WriteError) => {
//             if (err) { return next(err); }
//             req.flash("info", { msg: `${provider} account has been unlinked.` });
//             res.redirect("/account");
//         });
//     });
// };

/**
 * GET /user
 * Get current User.
 */
export let getUser = (req: Request, res: Response, next: NextFunction) => {
    res.json({ user: req.user });
};

/**
 * Get Jwt for current User.
 */
export function generateJwt(user: UserModel): string {
    const jwtId: string = uuidv1();
    user.tokenId = jwtId;
    user.save();
    const payload = {
        id: user.id,
        email: user.email,
        profile: user.profile
    };
    const token = jwt.sign(payload, JwtOptions.secretOrKey, {
        jwtid: jwtId
    });
    return token;
}