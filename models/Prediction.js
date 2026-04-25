const mongoose = require('mongoose');

const PredictionSchema = new mongoose.Schema({
  userId:          { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  predictionType:  { type: String, enum: ['parameter','random','csv'], default: 'parameter' },
  model:           { type: String, enum: ['knn','random_forest','cnn','lstm'], required: true },
  classType:       { type: String, enum: ['binary','multiclass'], required: true },
  inputParameters: { type: mongoose.Schema.Types.Mixed, default: {} },
  binaryResult:    { type: String, default: null },
  multiclassResult:{ type: String, default: null },
  attackProbability:{ type: Number, default: null },
  attackCategory:  { type: String, default: null },
  isBatchPrediction:{ type: Boolean, default: false },
  batchResults:    [{ type: mongoose.Schema.Types.Mixed }],
  csvFileName:     { type: String, default: null },
  createdAt:       { type: Date, default: Date.now, index: true }
});

module.exports = mongoose.model('Prediction', PredictionSchema);
