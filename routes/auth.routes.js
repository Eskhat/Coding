const {Router}=require('express')
const bcrypt=require('bcrypt')
const config=require('config')
const jwt=require('jsonwebtoken')
const {check,validationResult}=require('express-validator')
const User=require('../models/User')

const router =Router()



router.post(
    '/register',
    [
      check('email','false email').isEmail(),
        check('password','min 6 buk')
            .isLength({min:6})
    ],
    async (req, res) => {
    try {
        const errors=validationResult(req)
        if(!errors.isEmpty()){
            return res.status(400).json({
                errors:errors.array(),
                message:'error in registration'
            })
        }

        const {email, password} = req.body

        const candidate = await User.findOne({email})

        if(candidate){
            return res.status(400).json({message:'email used'})
        }

        const hashedPassword= await bcrypt.hash(password,12)
        const user=new User({email,password:hashedPassword})
        await user.save()

        res.status(201).json({message:'Registed'})


    } catch (e) {
        res.status(500).json({message: 'Error in reg'})
    }
})
router.post(
    '/login',
    [
      check('email','in true email').normalizeEmail().isEmail(),
        check('password','input password').exists()
    ],
    async (req, res) => {

    try {
        console.log('Body',req.body)

        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'error in login'
            })
        }

        const {email,password}=req.body
        const user=await User.findOne({email})

        if(!user){
            return res.status(400).json({message:'underfined user'})
        }

        const isMatch=await bcrypt.compare(password, user.password)
        if(!isMatch){
            return res.status(400).json({message:'wrong password'})
        }

        const token=jwt.sign(
        {userId:user.id},
        config.get('jwtSecret'),
            {expiresIn: '1h'}
        )

        res.json({token,userId:user.id})



    } catch (e) {
        res.status(500).json({message: 'Error'})
    }
})

module.exports=router