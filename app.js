const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const indexRouter = require('./routes/index');

const app = express();

app.use(logger('dev'));

// Segurança: COOKIE_SECRET em produção (evita falsificação de cookie do operador)
const cookieSecret = process.env.COOKIE_SECRET;
if (!cookieSecret && process.env.NODE_ENV === 'production') {
  console.warn('Segurança: defina COOKIE_SECRET no ambiente em produção.');
}

// Headers de segurança (XSS, clickjacking, MIME sniffing, etc.)
app.use(helmet({
  contentSecurityPolicy: false, // desative se precisar de inline scripts; ajuste depois se quiser CSP
  crossOriginEmbedderPolicy: false
}));

// Limite de tamanho do body (evita payload gigante)
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));

app.use(cookieParser(cookieSecret || 'grafeno-operador-secret'));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limit global leve (proteção contra abuso em geral)
app.use(rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 300,
  message: { error: 'Muitas requisições. Tente de novo em instantes.' },
  standardHeaders: true,
  legacyHeaders: false
}));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use('/', indexRouter);


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler (não expõe stack/detalhes em produção)
app.use(function(err, req, res, next) {
  const isDev = req.app.get('env') === 'development';
  res.locals.message = isDev ? err.message : 'Erro interno.';
  res.locals.error = isDev ? err : {};

  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
