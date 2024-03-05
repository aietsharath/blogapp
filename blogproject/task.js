Blogs.aggregate([
    {
      $group: {
        _id: "$blogTitle",
        totalActiveSubscribers:
         { $sum: 
          { $cond: 
            [{ $eq: ["$activeSubscriber",
             true] }, 1, 0] } }
      }
    }
  ])