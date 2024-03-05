import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy } from 'passport-local';
import GoogleStrategy from 'passport-google-oauth20';
import session from 'express-session';
import mongoose from 'mongoose';

const app = express();
const port = 3000;
const saltRounds = 10;

const mongoURI='mongodb://0.0.0.0:27017/Blogs';

// Connect to MongoDB using Mongoose
mongoose.connect(mongoURI);
mongoose.set("useCreateIndex", true);

const db=mongoose.connection;
db.on('error',console.error.bind(console,'MongoDB connection error'))

db.once('open',()=>{
  console.log('MongoDB connected');
})

const userSchema = new mongoose.Schema({
    id:String,
    email:String,
    password:String,
    googleId:String
});


const blogSchema=new mongoose.Schema({
  id:String,
  blogTitle:String,
  blogContent:String,
  authorId:String,
  subscribedUserId:String,
  activeSubscriber:Boolean 
  })

const User = mongoose.model('User', userSchema);
const Blog=mongoose.model('Blog', blogSchema);
app.use(
  session({
    secret: 'Hello',
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.send('homeejs');
});

app.get('/login', (req, res) => {
  res.send('login.ejs');
});

app.get('/register', (req, res) => {
  res.send('registered successfully');
});

app.get('/logout', (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});

app.get('/secrets', (req, res) => {
  if (req.isAuthenticated()) {
    res.send('secrets.ejs');
  } else {
    res.redirect('/login');
  }
});


app.post('/register', async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const user = await User.findOne({ email });

    if (user) {
      res.redirect('/login');
    } else {
      const hash = await bcrypt.hash(password, saltRounds);
      const newUser = new User({ email, password: hash });
      await newUser.save();
      req.login(newUser, (err) => {
        if (err) {
          console.error('Error during login:', err);
        } else {
          res.redirect('/secrets');
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  'local',
  new Strategy(async function verify(username, password, cb) {
    try {
      const user = await User.findOne({ email: username });

      if (user) {
        const storedHashedPassword = user.password;
        const valid = await bcrypt.compare(password, storedHashedPassword);

        if (valid) {
          return cb(null, user);
        } else {
          return cb(null, false);
        }
      } else {
        return cb('User not found');
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
    'google',
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: 'http://localhost:3000/auth/google/secrets',
        userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
      },
      async (accessToken, refreshToken, profile, cb) => {
        try {
          console.log(profile);
          
          // Check if the user already exists in the database
          const user = await User.findOne({ email: profile.email });
  
          if (!user) {
            // If the user does not exist, create a new user
            const newUser = new User({
              email: profile.email,
              password: 'google', // You might want to handle this more securely
            });
  
            await newUser.save();
            return cb(null, newUser);
          } else {
            // If the user already exists, return the existing user
            return cb(null, user);
          }
        } catch (err) {
          return cb(err);
        }
      }
    )
  );

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const user = await User.findById(id);
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});
app.post('/api/blogs/insert',async(req,res)=>{
  try {
    const {id,blogTitle,blogContent,authorId,subscribedUserId,activeSubscriber}=req.body
    if (req.body) {
    const newblog=new Blog({id,blogTitle,blogContent,authorId,subscribedUserId,activeSubscriber})
    await newblog.save();
    res.send('done and dusted')
    }
  } catch (error) {
    res.status(500).json({error:'Internal Server Error'})
  }
  });
  
  app.get('/getBlogs/:authorId',async(req,res)=>{
  try {
    const aggregationPipeline=[{$match:{
      activeSubscriber:true
    },
  },
  {
    $group:{
      _id:"$authorId",
      totalBlogs:{$sum:1},
      blogTitle:{$first:'$blogTitle'},
      avgBlogLength:{$avg:{$strLenCP:"$blogContent"}}
    },
  },
  {
  $sort:{
    totalBlogs:-1
  },
  },
  {
    $project:{
      _id:0,
      authorId:"$_id",
      totalBlogs:1,
      blogTitle:1,
      avgBlogLength:1,
    },
  },
  ]
  const aggregateData=await Blog.aggregate(aggregationPipeline).exec();
  res.json(aggregateData);
  } catch (error) {
    res.status(500).json({error:'Internal Server Error'})
  }
  })
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
