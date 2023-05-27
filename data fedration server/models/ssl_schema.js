const mongoose = require('mongoose');
const ssl_schema= mongoose.Schema({ },{ strict : false } );
module.exports=mongoose.model("ssl_schema",ssl_schema);