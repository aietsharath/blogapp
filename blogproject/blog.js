import logger from "./logger.js";

/*
try {
    throw new Error('This is a sample error.');
} catch (error) {
    logger.error(`Error: ${error.message}`);
}



logger.warn('This is a warning message.');


logger.info('This is an information message.');
*/

import express from "express"

import mongoose from "mongoose";

import NodeCache from "node-cache";

const app=express();

app.use(express.json())

const mongoURI='mongodb://0.0.0.0:27017/Blogs'

mongoose.connect(mongoURI);

const db = mongoose.connection;        

db.on('error', console.error.bind(console, 'MongoDB connection error:'));

db.once('open', () => {
  console.log('Connected to MongoDB');
});

const blogSchema = new mongoose.Schema({
  id: String,
  blogTitle: String,
  blogContent: String,
  authorId: { type: String, index: true },
  subscribedUserId: String,
  activeSubscriber: Boolean,
});

const Blog = mongoose.model('Blog', blogSchema);

const cache = new NodeCache();

app.get('/getBlogs/:authorId', async (req, res) => {
  try {

     const authorId=req.params.authorId;
     const cachedData=cache.get(authorId);

 if (cachedData) {
   console.log('Retriving data from cache itself');
   return res.json(cachedData)
 }


 debugger; // Debugger will pause here


    const aggregationPipeline=[{$match:{
      activeSubscriber:true,
    },
  },
{
  $group:{
    _id:"$authorId",
    totalBlogs:{$sum:1},
    blogTitle: { $first: "$blogTitle" },
    avgBlogLength:{$avg:{$strLenCP:"$blogContent"}}
  },
},
{
  $sort: {
    totalBlogs: -1,
  },
},
{
  $project: {
    _id: 0,
    authorId: "$_id",
    totalBlogs: 1,
    blogTitle:1,
    avgBlogLength: 1,
  },
},
]
      const aggregateData=await Blog.aggregate(aggregationPipeline).exec();
      cache.set(authorId, aggregateData, 60);
      console.log(aggregateData);
      res.json(aggregateData);
  } catch (error) {
      console.error('Error fetching total blogs:', error);
      res.status(500).json({ error: 'Internal Server Error' });
  }
});

  

app.post('/api/blogs/insert', async (req, res) => {
    try {
        const {id,blogTitle,blogContent,authorId,subscribedUserId,activeSubscriber}=req.body
        if (req.body) {
            const newblog=new Blog({id,blogContent,blogTitle,authorId,subscribedUserId,activeSubscriber})
            await newblog.save();   
        }
        res.send('sucsessfully inserted');
    } catch (error) {
        console.error('Error inserting blog:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
  });
 



  app.delete('/api/blogs/deleteOne', async (req, res) => {
    try {
        let deleted;
        if (req.body) {
            deleted=await Blog.deleteOne(req.body);
            console.log(deleted);
        }
      res.json(deleted);
    } catch (error) {
      console.error('Error fetching notes:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  app.put('/api/blogs/updateOne/:id', async (req, res) => {
    try {  
        let updated;
        if (req.body) {
            updated=await Note.findOneAndUpdate({authorId:req.params.id},req.body);
        }
          res.json(updated);
    } catch (error) {
      console.error('Error fetching notes:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });

  export default app;