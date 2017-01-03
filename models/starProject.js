module.exports = function(mongoose) {
	var Schema = mongoose.Schema;
	var starProject_schema = new Schema({
		owner: String,
		projectName: String,
		starNum: String,
		forkNum: String,
		updateTime: String,
	});
	mongoose.model('starProjects', starProject_schema);
}