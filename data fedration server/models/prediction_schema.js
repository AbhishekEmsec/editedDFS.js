const mongoose = require('mongoose');
const prediction_schema = mongoose.Schema({ },{ strict : false } );
module.exports=mongoose.model("prediction_schema",prediction_schema);