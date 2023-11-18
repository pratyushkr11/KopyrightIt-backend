const mongoose = require('mongoose')

const ImageDetailSchema = new mongoose.Schema(
    {
        image:String
    },
    {
        collection: "ImageDetails"
    }
);

mongoose.model("ImageDetails", ImageDetailSchema)