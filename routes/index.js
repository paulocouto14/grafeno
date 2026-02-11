const express = require('express');
const router = express.Router();

/* GET home page. */
router.get('/', (req, res, next) => {
  res.render('index', { title: 'Express' });
});

router.get('/grafeno', (req, res, next) => {
  res.render('grafeno', { title: 'Grafeno' });
});

router.post('/grafeno', (req, res, next) => {
  // Processar login aqui
  // Por enquanto, apenas redireciona de volta
  res.redirect('/grafeno');
});

module.exports = router;
