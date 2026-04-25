const express = require('express');
const router = express.Router();
const { forwardAuthenticated } = require('../middleware/auth');

router.get('/', forwardAuthenticated, (req, res) => {
  res.render('landing');
});

module.exports = router;
