const mongoose = require('mongoose');
// const Schema = mongoose.Schema;

const LiterarySchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users', 
        required: true
    },
    formType:{
        type: String,
        required: true
    },
    dairyNo:{
        type: String,
    },
    status:{
        type: String,
        default: "Pending"
    },
    date: {
        type: Date,
        default: Date.now
    },
    keyValue: {
        fileKey1: {
            type: String
        },
        imageKey1: {
            type: String
        }
    },
    form1: {
        option: {
            type: String,
            required: true,
        },
        name: {
            type: String,
            required: true,
        },
        name1: {
            type: String,
            
        },
        name2: {
            type: String,
            required: true,
        },
        mail: {
            type: String,
            required: true,
        },
        address: {
            type: String,
            required: true,
        },
        mobile: {
            type: String,
            required: true,
        },
        country: {
            type: String,
            required: true,
        },
        state: {
            type: String,
            required: true,
        },
        city: {
            type: String,
            required: true,
        },
        zip: {
            type: Number,
            required: true,
        }
    },
    form2: {
        isOriginalWork: {
            type: Boolean,
        },
        workTranslation: {
            type: String,
        },
        workTranslationCopyright: {
            type: String,
        },
        workAdaption: {
            type: String,
        },
        workAdaptionCopyright: {
            type: String,
        },
    },
    form3: {
        particularsNatureOfWork: {
            type: String,
        },
        particularsClassOfWork: {
            type: String,
        },
        particularsDescription: {
            type: String,
        },
        particularsTitle: {
            type: String,
        },
        particularsLanguageOfWork: {
            type: String,
        },
        isAuthorAlive: {
            type: Boolean,
        },
        particularsNameOfAuthor: {
            type: String,
        },
        particularsAddressOfAuthor: {
            type: String,
        },
        particularsNationalityOfAuthor: {
            type: String,
        },
        particularsDateOfDecease: {
            type: Date,
        }
    },
    
});

const Formmodel = mongoose.model('LiteraryForm', LiterarySchema);
module.exports = Formmodel