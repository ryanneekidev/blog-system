const express = require('express');
const db = require('./db');
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
const {Prisma} = require('@prisma/client');

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

app.use(cors({
    origin: '*',
    methods: ['GET,HEAD,PUT,PATCH,POST,DELETE']
}));


passport.use(new LocalStrategy({usernameField: 'username', passwordField: 'password', session: false}, async (username, password, done)=>{
    const user = await db.getUserByUsername(username);

    if(!user){
        return done(null, false, {code: 400, message: 'Incorrect username'})
    }

    if(!(await bcrypt.compare(password, user.password))){
        return done(null, false, {code: 400, message: 'Incorrect password'})
    }

    return done(null, user)
}))

// GET routes

app.get('/api', (req, res)=>{
    res.status(200).send('Hello, world!')
});

app.get('/api/users', verifyAuth, async (req, res)=>{
    const users = await db.getUsers();
    res.status(200).json(users)
});

app.get('/api/posts', async (req, res)=>{
    const posts = await db.getPosts();
    res.status(200).json(posts)
})

// POST routes

app.post('/api/posts', verifyAuth, async (req, res)=>{
    const title = req.body.title;
    const content = req.body.content;
    const postStatus = req.body.postStatus;
    const authHeaders = req.headers.authorization;
    const token = authHeaders.split(' ')[1];
    let user;
    jwt.verify(token, 'mysecret', (err, decoded)=>{
        if(err){
            return res.status(401).json({ message: "Token is expired or invalid" });
        }
        user = decoded;
    })
    const authorId = user.id;
    await db.createPost(title, content, authorId, postStatus);
    res.status(200).json({
        message:'Post created successfully'
    })
})

app.post('/api/login', (req, res, next)=>{
    passport.authenticate("local", {session: false}, (err, user, info)=>{

        if(err){
            return next(err)
        }
        if(!user){
            return res.status(400).json(info)
        }

        const payload = {
            id: user.id,
            username: user.username,
            email: user.email,
            joinedAt: user.joinedAt,
            role: user.role,
            posts: user.posts,
            comments: user.comments,
            like: user.like
        }

        const token = jwt.sign(payload, 'mysecret', { expiresIn: "1h" });

        res.status(200).json({
            token: token
        })
    })(req, res, next);
})

app.post('/api/register', async (req, res)=>{
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    const hashedPassword = await bcrypt.hash(password, 10);
    if(username&&email&&password){
        try {
            let usernameExists = await db.getUserByUsername(username);
            let emailExists = await db.getUserByEmail(email);
            if(usernameExists&&emailExists){
                return res.status(400).json({
                    message: `Username ${username} and email address ${email} are not available`,
                    code: 400
                })
            }
            if(usernameExists){
                return res.status(400).json({
                    message: `Username ${username} is not available`,
                    code: 400
                })
            }
            if(emailExists){
                return res.status(400).json({
                    message: `Email address ${email} is not available`,
                    code: 400
                })
            }
            await db.createUser(username, email, hashedPassword);
            res.status(200).json({
                message: "User created successfully!",
                code: 200
            })
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError) {
                res.status(400).json({
                    message: error.message,
                    code: error.code
                }) 
            }
        }
    }
})

app.post('/api/posts/like', async (req, res) => {
    let userId = req.body.userId;
    let postId = req.body.postId;
    await db.likePost(userId, postId);
    res.status(200).json({
        updatedLikes: await db.getUserLikedPosts(userId),
        message:'Post liked successfully'
    })
})

app.post('/api/posts/dislike', async (req, res) => {
    let userId = req.body.userId;
    let postId = req.body.postId;
    let likeId = req.body.likeId;
    await db.dislikePost(userId, postId, likeId);
    res.status(200).json({
        updatedLikes: await db.getUserLikedPosts(userId),
        message:'Post disliked successfully'
    })
})

app.post('/api/comment', async (req, res) => {
    let userId = req.body.authorId;
    let postId = req.body.postId;
    let content = req.body.content;
    await db.createComment(content, userId, postId)
    res.status(200).json({
        message: 'Comment created successfully'
    })
})

app.post('/api/post', async (req, res)=> {
    let postId = req.body.postId
    const post = await db.getPost(postId)
    res.status(200).json({
        post: post,
        message: 'Post retrieved successfully'
    })
})

app.listen(3000, (req, res)=>{
    console.log('Server started at http://127.0.0.1:3000')
})


function verifyAuth(req, res, next){
    const authorizationHeaders = req.headers.authorization;

    if(!authorizationHeaders){
        return res.status(401).json({ message: "No token provided, you must be logged in" });
    }

    const parts = authorizationHeaders.split(' ');
    const token = parts[1];

    jwt.verify(token, 'mysecret', (err, decoded)=>{
        if(err){
            return res.status(401).json({ message: "Token is expired or invalid" });
        }
        req.user = decoded;
        next()
    })
}