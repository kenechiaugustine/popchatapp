const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const cookieParser = require('cookie-parser');
const { engine } = require('express-handlebars');

const JWT_SECRET = 'kene-secret';

const User = require('./model/user.model');
const bcryptjs = require('bcryptjs');


const app = express()

// Connect to MongoDB
const mongoUri = `mongodb+srv://testcaseuser:testcaseuser@testcase-cluster.pafmj.mongodb.net/sample-dev?retryWrites=true&w=majority`


mongoose.connect(mongoUri).then(() => {
    console.log('Connected to MongoDB')
}).catch((err) => {
    console.log('Error connecting to MongoDB: ' + err)
})


app.use(cookieParser());
app.use(express.json());
app.use(express.static(path.join(__dirname, './public')))


////////////////////////
app.engine('.hbs', engine({
    extname: '.hbs',
    defaultLayout: `_base`,
    // layoutsDir: path.join(__dirname, 'views/filelayout')
}));

app.set('view engine', '.hbs');

app.set('views', path.join(__dirname, 'views'));


async function isLoggedIn(req, res, next) {

    try {
        // check if user is logged in
        const token = req.cookies.jwt;
        if (!token) return res.status(401).json('You are not logged in');

        // validate token
        const decoded = await promisify(jwt.verify)(token, JWT_SECRET)
        if (!decoded) return res.status(400).json('Invalid token. Login again');

        // check user from token
        const user = await User.findById(decoded.id)
        if (!user) return res.status(400).json('No user found in this token. Login again');


        req.user = user;

        // console.log(req.user)

        next()
    } catch (error) {
        // console.log(error)

        if (error.name === 'JsonWebTokenError') {
            res.status(400).json('Invalid token. Login again');
        } else {
            res.status(400).json('Invalid token. Login again');
        }
    }

}


function authorize(...roles) {
    return async (req, res, next) => {

        // Get the user from the request
        const user = req.user;

        // check role privileges
        if (!roles.includes(user.role)) {
            return res.status(403).json(`You can't access this route with your role: ${user.role}`);
        }

        // call next
        next()
    }
}




app.get('/register', (req, res) => {
    res.render('register')
})

app.get('/login', (req, res) => {
    res.render('login')
})


/////////////////////////////////////////

app.get('/', isLoggedIn, (req, res) => {

    res.render('chats', {user: req.user})

})



/////////////////////////////////////////
app.get('/admin', isLoggedIn, authorize('admin'), (req, res) => {
    res.send('Welcome to the Admin page')
    return
})



///////////////////////////////////////////

app.post('/register', async (req, res) => {
    let { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send('Please enter an email and password')
    }
    try {
        password = await bcrypt.hash(password, 10)
        const user = await User.create({
            email,
            password
        })
        const token = jwt.sign({ id: user._id }, JWT_SECRET)
        res.cookie('jwt', token)
        res.status(200).json({
            message: 'User registered successfully',
            data: user,
            token
        })
    } catch (error) {
        if (error.code === 11000) {
            res.status(400).json({
                message: 'User already exists'
            })
        } else {
            console.log(error)
            res.status(500).json({
                message: 'Error registering user'
            })
        }
    }
})


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send('Please enter an email and password')
    }
    try {
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(400).send('Invalid email or password')
        }
        const validPassword = await bcrypt.compare(password, user.password)
        if (!validPassword) return res.status(400).json({message: 'Invalid email or password'})
        const token = jwt.sign({ id: user._id }, JWT_SECRET)
        res.cookie('jwt', token)
        res.status(200).json({
            message: 'User logged in successfully',
            success: true,
            token
        })
        return;
    } catch (error) {
        res.status(500).json({
            message: 'Error logging in user',
            error
        })
        return
    }
})


app.get('/logout', (req, res) => {
    res.clearCookie('jwt')
    res.status(200).json({
        message: 'User logged out successfully'
    })
})



app.all('*', (req, res) => {
    res.status(404).send(`404 Not Found\n The Route: ${req.protocol}://${req.get('host')}/${req.originalUrl} does not exist`)
})




const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Server running on PORT ${PORT}`))