var mongoose = require('mongoose'),
    path = require('path');

var rootPath = path.normalize(__dirname + '/..');
var MODEL_POSTFIX = "model.server.js";
var DEFAULT_MODEL_FOLDER = "./models";

exports.initMongooseAndLoadModel = function (app, config) {
    if (!config) {
        console.log('Error initializing mongo, please set config params (2 params) with object.models and object.connection');
        return;
    }

    if (!config.hasOwnProperty(('connection'))) {
        console.log('Error, initizializing mongo, please add params object.connection');
    }

    if (!config.hasOwnProperty(('models'))) {
        config.models =DEFAULT_MODEL_FOLDER;
    }

    if(app){
        app.set('mongoose', mongoose);
    }

    var modelPath = rootPath + '/' + config.models;
    var modelLoaded = loadModels(mongoose, modelPath, false, app);
    mongoose.connect(config.connection);

    mongoose.connection.on('connected', function () {
        console.info('\x1b[32m_______________________________________________________________\x1b[0m');
        console.info(':: Mongo DB - start info log');
        console.log(' ');
        console.info('\x1b[32m*\x1b[0m URL:\x1b[0m' + config.connection);

        for (var i = 0; i < modelLoaded.length; i++) {
            console.info('\x1b[32m* \x1b[0mModel: \x1b[35m' + modelLoaded[i] + '\x1b[0m');
        }
        console.info('\x1b[32m_______________________________________________________________\x1b[0m');
        console.info('');
    });

    mongoose.connection.on('error', console.error.bind(console, '\x1b[31m* MONGODB CONNECTION ERROR\x1b[0m'));

    mongoose.connection.on('disconnected', console.error.bind(console, '\x1b[31m* MONGODB DISCONNECTED\x1b[0m'));

    mongoose.connection.on('reconnected', console.error.bind(console, '\x1b[32m* MONGODB RECONNECTED\x1b[0m'));

    process.on('SIGINT', function () {
        mongoose.connection.close(function () {
            console.log('Mongoose default connection disconnected through app termination');
            process.exit(0);
        });
    });

    return mongoose;
}


function loadModels(mongoose, loadPath, recursive, app) {
    var fs = require('fs')
        , path = require('path')
        , modelName = [];

    if (!mongoose) {
        mongoose = require('mongoose');
    }

    mongoose.models = {};

    if (!loadPath) {
        loadPath = './models';
    }

    var walk = function (dir) {
        var results = [];
        var list = fs.readdirSync(dir);
        list.forEach(function (file) {
            file = dir + '/' + file;
            var stat = fs.statSync(file);
            if (stat && stat.isDirectory()) results = results.concat(walk(file));
            else results.push(file)
        });
        return results;
    };

    var files = [];
    if (!recursive) {
        files = fs.readdirSync(loadPath);
    } else {
        files = walk(loadPath);
    }

    var models = {};

    for (var i in files) {

        var file = '';
        if (!recursive) {
            file = path.resolve(loadPath, files[i]);
        } else {
            file = path.resolve(files[i]);
        }

        if (fs.statSync(file).isFile()) {
            var name = path.basename(file);
            name = name.replace(MODEL_POSTFIX, '');
            require(file)(mongoose, app);
            modelName.push(name);
        }
    }

    return modelName;
}