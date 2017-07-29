import * as request from "request"; // wtf ???
import * as passport from "passport";
import { ExtractJwt, Strategy as JwtStrategy, StrategyOptions as JwtStrategyOptions } from "passport-jwt";
import { Request, Response, NextFunction } from "express";
import { User } from "../models/User";
import { Strategy as FacebookStrategy } from "passport-facebook";

export const JwtOptions: JwtStrategyOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeader(),
    secretOrKey: process.env.JWT_SECRET,
};

passport.use(new JwtStrategy(JwtOptions, (jwt_payload, next) => {
    //  Get user from database
    User.findById(jwt_payload._id, (err, user) => {
        if (err) {
            //
            return next(err);
        }
        if (!user) {
            //
            return next(undefined);
        }
        if (user.tokenId !== jwt_payload.jti) {
            //  TokenId do not match
            return next(undefined);
        }
        return next(undefined, user);
    });
}));

/**
 * Sign in with Facebook.
 */
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: "/auth/facebook/callback",
    profileFields: ["name", "email"],
    passReqToCallback: true
}, (req: any, accessToken, refreshToken, profile, done) => {
    User.findOne({ facebook: profile.id }, (err, existingUser) => {
        if (err) {
            return done(err);
        }
        if (existingUser) {
            return done(undefined, existingUser);
        }
        User.findOne({ email: profile._json.email }, (err, existingEmailUser) => {
            if (err) { return done(err); }
            if (existingEmailUser) {
                existingEmailUser.facebook = profile.id;
                existingEmailUser.save();
                return done(undefined, existingEmailUser);
            } else {
                const user = new User();
                user.email = profile._json.email;
                user.facebook = profile.id;
                user.profile.displayName = `${profile.name.givenName} ${profile.name.familyName}`;
                user.profile.picture = `https://graph.facebook.com/${profile.id}/picture?type=large`;
                user.save((err: Error) => {
                    done(err, user);
                });
            }
        });
    });
}));

/**
 * Login Required middleware.
 */
export let isAuthenticated = passport.authenticate("jwt", { session: false });
