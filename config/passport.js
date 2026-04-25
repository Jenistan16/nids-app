const LocalStrategy  = require('passport-local').Strategy;
const User = require('../models/User');

module.exports = function(passport) {

  // ── Local Strategy ─────────────────────────────────────────────────────────
  passport.use('local', new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
      const user = await User.findOne({ email: email.toLowerCase().trim() });
      if (!user)          return done(null, false, { message: 'No account found with that email address.' });
      if (!user.password) return done(null, false, { message: 'This account uses Google login. Please sign in with Google.' });

      const isMatch = await user.matchPassword(password);
      if (!isMatch) return done(null, false, { message: 'Incorrect password. Please try again.' });

      user.lastLogin = new Date();
      await user.save();
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }));

  // ── Google OAuth Strategy (only register if credentials are configured) ─────
  const gClientId = process.env.GOOGLE_CLIENT_ID;
  const gSecret   = process.env.GOOGLE_CLIENT_SECRET;

  if (gClientId && gSecret && !gClientId.includes('your_google')) {
    const GoogleStrategy = require('passport-google-oauth20').Strategy;
    passport.use('google', new GoogleStrategy({
      clientID:     gClientId,
      clientSecret: gSecret,
      callbackURL:  process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        // Try to find by googleId
        let user = await User.findOne({ googleId: profile.id });
        if (user) {
          user.lastLogin = new Date();
          await user.save();
          return done(null, user);
        }

        // Try to merge with existing email account
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        if (email) {
          user = await User.findOne({ email: email.toLowerCase() });
          if (user) {
            user.googleId  = profile.id;
            user.avatar    = (profile.photos && profile.photos[0]) ? profile.photos[0].value : user.avatar;
            user.lastLogin = new Date();
            await user.save();
            return done(null, user);
          }
        }

        // Create new user
        user = new User({
          name:      profile.displayName || 'Google User',
          email:     email ? email.toLowerCase() : `google_${profile.id}@nids.local`,
          googleId:  profile.id,
          avatar:    (profile.photos && profile.photos[0]) ? profile.photos[0].value : '',
          lastLogin: new Date()
        });
        await user.save();
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }));
    console.log('✅ Google OAuth configured');
  } else {
    console.log('ℹ️  Google OAuth not configured (set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET in .env to enable)');
  }

  // ── Serialise / Deserialise ────────────────────────────────────────────────
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id).lean();
      done(null, user);
    } catch (err) {
      done(err);
    }
  });
};
