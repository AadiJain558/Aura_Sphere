import passport from "passport";
import GitHubStrategy from 'passport-github2';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { User } from './models/user.model.js';
import dotenv from 'dotenv';

dotenv.config({ path: './.env' });

// Serialize and deserialize user
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if emails array is available
        const emails = profile.emails || [];
        const primaryEmail = emails.length > 0 ? emails[0].value : null;

        if (!primaryEmail) {
            console.error('No email associated with this Google account');
            return done(null, false, { message: 'No email found' });
        }

        const existingUser = await User.findOne({ email: primaryEmail });
        if (existingUser) {
            return done(null, existingUser);
        }

        const newUser = await User.create({
            username: profile.displayName,
            email: primaryEmail,
            // Optionally, you can skip the password for OAuth users
            // password: 'dummyPassword' 
        });
        done(null, newUser);
    } catch (error) {
        done(error);
    }
}));

// GitHub OAuth strategy
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if emails array is provided and has at least one email
        const emails = profile.emails || [];
        const primaryEmail = emails.length > 0 ? emails[0].value : null;

        if (!primaryEmail) {
            console.error('No email associated with this GitHub account');
            return done(null, false, { message: 'No email found' });
        }

        let user = await User.findOne({ email: primaryEmail });
        if (user) return done(null, user);

        user = await User.create({
            username: profile.username,
            email: primaryEmail,
            password: 'dummyPassword'
        });
        done(null, user);
    } catch (error) {
        done(error);
    }
}));

export default passport;
