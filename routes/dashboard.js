const express = require('express');
const router = express.Router();
const { ensureAuthenticated } = require('../middleware/auth');
const Prediction = require('../models/Prediction');

// GET /dashboard
router.get('/', ensureAuthenticated, async (req, res) => {
  try {
    const [recentPredictions, totalPredictions, attackCount, attackTypes, modelUsage] = await Promise.all([
      Prediction.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(10).lean(),
      Prediction.countDocuments({ userId: req.user._id }),
      Prediction.countDocuments({ userId: req.user._id, binaryResult: 'Attack' }),
      Prediction.aggregate([
        { $match: { userId: req.user._id, multiclassResult: { $exists: true, $ne: null, $ne: '' } } },
        { $group: { _id: '$multiclassResult', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]),
      Prediction.aggregate([
        { $match: { userId: req.user._id } },
        { $group: { _id: '$model', count: { $sum: 1 } } }
      ])
    ]);

    res.render('dashboard', {
      user: req.user,
      recentPredictions,
      stats: {
        totalPredictions,
        attackCount,
        normalCount: totalPredictions - attackCount
      },
      attackTypes,
      modelUsage
    });
  } catch (err) {
    console.error('Dashboard error:', err.message);
    res.render('dashboard', {
      user: req.user,
      recentPredictions: [],
      stats: { totalPredictions: 0, attackCount: 0, normalCount: 0 },
      attackTypes: [],
      modelUsage: []
    });
  }
});

// GET /dashboard/history
router.get('/history', ensureAuthenticated, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 15;
    const skip  = (page - 1) * limit;

    const [predictions, total] = await Promise.all([
      Prediction.find({ userId: req.user._id }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      Prediction.countDocuments({ userId: req.user._id })
    ]);

    res.render('history', {
      user: req.user,
      predictions,
      currentPage: page,
      totalPages: Math.ceil(total / limit) || 1,
      total
    });
  } catch (err) {
    console.error('History error:', err.message);
    res.render('history', {
      user: req.user,
      predictions: [],
      currentPage: 1,
      totalPages: 1,
      total: 0
    });
  }
});

module.exports = router;
