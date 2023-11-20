import { Router } from "express";
import passport from "passport";


const sessionRouter = Router()

sessionRouter.post('/login',passport.authenticate('login'), async (req, res) => {
    try {
      if(!req.user){
        return res.status(401).send({mensaje:"Usuario Invalido"});
      }  
      req.session.user = {
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        age: req.user.age,
        email: req.user.email
      }
      res.status(200).send({ payload: req.user })
    } catch (error) {
        res.status(500).send({mensaje:`Error al iniciar sesion ${error}`})
    }
   
});

sessionRouter.post('/register',passport.authenticate('register'), async (req, res) => {
    try {
      if(!req.user){
        return res.status(400).send({mensaje:"Usuario ya existente "});
      }  
     
      res.status(200).send({ mensaje:'Usuario registrado' });
    } catch (error) {
        res.status(500).send({mensaje:`Error al registar el usuario ${error}`})
    }
   
});

sessionRouter.get('/github', passport.authenticate('github' ,{scope:['user:email']}), async(req,res) => {
    res.status(200).send({mensaje:'Usuario Registrado'});
});

sessionRouter.get('/githubCallBack', passport.authenticate('github'), async(req,res) => {
    res.session.user = req.user
    res.status(200).send({mensaje: 'Usuario logeado'});
});

sessionRouter.get('/logout', (req, res) => {
    if (req.session && req.session.user) {
        req.session.destroy((err) => {
            if (err) {
                console.error("Error al destruir la sesión:", err);
                res.status(500).send({ resultado: 'Error interno al desloguear' });
            } else {
                res.clearCookie('userData'); 
                res.status(200).send({ resultado: 'Usuario deslogueado' });
            }
            
        });
    }
        ;
})

export default sessionRouter