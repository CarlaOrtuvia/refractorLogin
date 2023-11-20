import local from 'passport-local';
import passport from 'passport';
import GithubStrategy from 'passport-github2';
import { hashPassword, validatePassword } from '../utils/bcrypt.js';
import { userManager } from '../dao/models/userManager.js';




const LocalStrategy = local.Strategy;

const InitializePassport = () => {
    
    passport.use('signup', new LocalStrategy({
        usernameField: 'email',
        passReqToCallback: true
    }, async (req, username, password, done) => {

        const { first_name, last_name, email, age } = req.body;
        try {
            
            const user = await userManager.findByEmail(email);
            console.log('user:',user)
            debugger

            
            if (user) {
                return done(null, false, { message: 'El usuario ya existe' });
            }

            
            const hashPass = await hashPassword(password);
            console.log(hashPass);
            const createUser = await userManager.create({ 
                first_name,
                last_name,
                email,
                age,
                password: hashPass
            });
            return done(null, createUser, { message: 'Usuario creado exitosamente.' });
            

        } catch (error) {
            return done(error);
        }
    }));

    
    passport.use('login', new LocalStrategy(
        { usernameField: 'email' } , async (email, password, done) => {
            try {
                const user = await userManager.findByEmail(email);

                
                if (!user) {
                    return done(null, false, { message: 'El usuario no existe.' });
                }

                
                if (!validatePassword(password, user.password)) {
                    console.log('Contraseña incorrecta')
                    return done(null, false, { message: 'La contraseña es incorrecta.' });
                }

                
                console.log('Usuario logueado correctamente')
                return done(null, user);
            }
            catch (error) {
                return done(error);
            }
    }))


    passport.use('github', new GithubStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: process.env.CALLBACK_URL
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            console.log('accessToken:',accessToken)
            console.log('refreshToken:',refreshToken)
            console.log('profile:',profile)
            console.log(profile._json.email)
            console.log(profile._json.name)
            const user = await userManager.findByEmail(profile._json.email);
            if (user) {
                return done(null, user);
            } else {
                const hashPass = await hashPassword(profile._json.email);
                const newUser = await userManager.create({
                    first_name: profile._json.name,
                    last_name: ' ',
                    email: profile._json.email,
                    age: 18,
                    password: hashPass
                });
                return done(null, newUser);
            }
        } catch (error) {
            return done(error);
        }
    }));

    
    passport.serializeUser((user, done) => {
        console.log('serialed user:',user)
        done(null, user._id);
    });

    
    passport.deserializeUser(async (id, done) => {
        try {
            console.log('deserializer_id:',id)
            const user = await userManager.findById(id);
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    });
}

export default InitializePassport;