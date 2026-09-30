"""Testes automatizados da funcionalidade de autenticação (TDD).

Regras de negócio cobertas (ver caso de uso no relatório):
  RN1  O formulário deve ter e-mail e senha preenchidos.
  RN2  O e-mail deve ter formato válido.
  RN3  E-mail e senha devem corresponder a um usuário cadastrado.
  RN4  Usuário inativo não acessa o sistema.
  RN5  O usuário precisa ter a permissão exigida para o acesso.
  RN6  Falhas de credencial não revelam se o e-mail existe.
  RN7  Senhas nunca são guardadas em texto puro.

Ordem de avaliação: RN1 -> RN2 -> RN3 -> RN4 -> RN5.
"""
import pytest

from autenticacao import (
    PERMISSAO_ACESSO,
    CodigoResultado,
    RepositorioUsuarios,
    ResultadoAutenticacao,
    ServicoAutenticacao,
    Usuario,
)

SENHA = "Senha@123"


@pytest.fixture(scope="module")
def repositorio():
    repo = RepositorioUsuarios()
    repo.adicionar(Usuario.criar("ana@empresa.com", SENHA, ativo=True,
                                 permissoes={PERMISSAO_ACESSO}))
    repo.adicionar(Usuario.criar("bruno@empresa.com", SENHA, ativo=False,
                                 permissoes={PERMISSAO_ACESSO}))
    repo.adicionar(Usuario.criar("carla@empresa.com", SENHA, ativo=True,
                                 permissoes=set()))
    repo.adicionar(Usuario.criar("admin@empresa.com", SENHA, ativo=True,
                                 permissoes={PERMISSAO_ACESSO, "administrar"}))
    repo.adicionar(Usuario.criar("diego@empresa.com", SENHA, ativo=False,
                                 permissoes=set()))
    return repo


@pytest.fixture(scope="module")
def servico(repositorio):
    return ServicoAutenticacao(repositorio)


def _assert_negado(resultado, codigo):
    assert isinstance(resultado, ResultadoAutenticacao)
    assert resultado.autorizado is False
    assert resultado.codigo is codigo
    assert resultado.usuario is None
    assert resultado.mensagem  # toda negativa explica o motivo ao usuário


# --------------------------------------------------------------------------
# CENÁRIOS DE SUCESSO
# --------------------------------------------------------------------------
class TestSucesso:
    def test_autoriza_usuario_ativo_com_dados_corretos_e_permissao(self, servico):
        r = servico.autenticar("ana@empresa.com", SENHA)
        assert r.autorizado is True
        assert r.codigo is CodigoResultado.AUTORIZADO

    def test_retorna_o_usuario_autenticado(self, servico):
        r = servico.autenticar("ana@empresa.com", SENHA)
        assert r.usuario is not None
        assert r.usuario.email == "ana@empresa.com"

    def test_ignora_espacos_e_maiusculas_no_email(self, servico):
        r = servico.autenticar("  ANA@Empresa.COM  ", SENHA)
        assert r.autorizado is True

    def test_autoriza_quando_possui_a_permissao_especifica_exigida(self, servico):
        r = servico.autenticar("admin@empresa.com", SENHA,
                               permissao_exigida="administrar")
        assert r.autorizado is True
        assert r.codigo is CodigoResultado.AUTORIZADO


# --------------------------------------------------------------------------
# ERROS DE VALIDAÇÃO DO FORMULÁRIO (RN1 e RN2)
# --------------------------------------------------------------------------
class TestValidacaoDoFormulario:
    @pytest.mark.parametrize("email", ["", "   ", None])
    def test_nega_quando_email_obrigatorio_nao_informado(self, servico, email):
        _assert_negado(servico.autenticar(email, SENHA),
                       CodigoResultado.CAMPO_OBRIGATORIO)

    @pytest.mark.parametrize("senha", ["", None])
    def test_nega_quando_senha_obrigatoria_nao_informada(self, servico, senha):
        _assert_negado(servico.autenticar("ana@empresa.com", senha),
                       CodigoResultado.CAMPO_OBRIGATORIO)

    def test_nega_quando_todos_os_campos_estao_vazios(self, servico):
        _assert_negado(servico.autenticar("", ""),
                       CodigoResultado.CAMPO_OBRIGATORIO)

    @pytest.mark.parametrize("email", [
        "ana", "ana@", "@empresa.com", "ana@empresa", "ana empresa@x.com",
        "ana@@empresa.com",
    ])
    def test_nega_quando_formato_do_email_e_invalido(self, servico, email):
        _assert_negado(servico.autenticar(email, SENHA),
                       CodigoResultado.FORMATO_INVALIDO)

    def test_valida_o_formulario_antes_de_consultar_o_repositorio(self):
        class RepositorioEspiao:
            consultas = 0

            def buscar_por_email(self, email):
                self.consultas += 1

        espiao = RepositorioEspiao()
        ServicoAutenticacao(espiao).autenticar("", "")
        ServicoAutenticacao(espiao).autenticar("invalido", SENHA)
        assert espiao.consultas == 0


# --------------------------------------------------------------------------
# ERROS DE CREDENCIAIS (RN3 e RN6)
# --------------------------------------------------------------------------
class TestCredenciais:
    def test_nega_quando_senha_esta_incorreta(self, servico):
        _assert_negado(servico.autenticar("ana@empresa.com", "SenhaErrada!1"),
                       CodigoResultado.CREDENCIAIS_INVALIDAS)

    def test_senha_diferencia_maiusculas_de_minusculas(self, servico):
        _assert_negado(servico.autenticar("ana@empresa.com", SENHA.lower()),
                       CodigoResultado.CREDENCIAIS_INVALIDAS)

    def test_nega_quando_usuario_nao_esta_cadastrado(self, servico):
        _assert_negado(servico.autenticar("ninguem@empresa.com", SENHA),
                       CodigoResultado.CREDENCIAIS_INVALIDAS)

    def test_mensagem_nao_revela_se_o_email_existe(self, servico):
        senha_errada = servico.autenticar("ana@empresa.com", "SenhaErrada!1")
        inexistente = servico.autenticar("ninguem@empresa.com", SENHA)
        assert senha_errada.mensagem == inexistente.mensagem

    def test_mensagem_de_negativa_nunca_contem_a_senha(self, servico):
        r = servico.autenticar("ana@empresa.com", "SenhaErrada!1")
        assert "SenhaErrada!1" not in r.mensagem


# --------------------------------------------------------------------------
# USUÁRIO ATIVO x INATIVO (RN4)
# --------------------------------------------------------------------------
class TestUsuarioInativo:
    def test_nega_usuario_inativo_com_credenciais_corretas(self, servico):
        _assert_negado(servico.autenticar("bruno@empresa.com", SENHA),
                       CodigoResultado.USUARIO_INATIVO)

    def test_inativo_com_senha_errada_nao_revela_o_status(self, servico):
        _assert_negado(servico.autenticar("bruno@empresa.com", "SenhaErrada!1"),
                       CodigoResultado.CREDENCIAIS_INVALIDAS)

    def test_inatividade_tem_prioridade_sobre_a_falta_de_permissao(self, servico):
        _assert_negado(servico.autenticar("diego@empresa.com", SENHA),
                       CodigoResultado.USUARIO_INATIVO)


# --------------------------------------------------------------------------
# PERMISSÕES DE ACESSO (RN5)
# --------------------------------------------------------------------------
class TestPermissoes:
    def test_nega_usuario_ativo_sem_nenhuma_permissao(self, servico):
        _assert_negado(servico.autenticar("carla@empresa.com", SENHA),
                       CodigoResultado.SEM_PERMISSAO)

    def test_nega_quando_falta_a_permissao_especifica_exigida(self, servico):
        _assert_negado(
            servico.autenticar("ana@empresa.com", SENHA,
                               permissao_exigida="administrar"),
            CodigoResultado.SEM_PERMISSAO)


# --------------------------------------------------------------------------
# SEGURANÇA DO ARMAZENAMENTO DE SENHAS (RN7)
# --------------------------------------------------------------------------
class TestArmazenamentoDeSenha:
    def test_senha_nao_e_guardada_em_texto_puro(self):
        u = Usuario.criar("x@empresa.com", SENHA)
        assert SENHA.encode() not in u.senha_hash
        assert u.senha_hash != SENHA.encode()

    def test_mesma_senha_gera_hashes_diferentes_por_usuario(self):
        u1 = Usuario.criar("a@empresa.com", SENHA)
        u2 = Usuario.criar("b@empresa.com", SENHA)
        assert u1.salt != u2.salt
        assert u1.senha_hash != u2.senha_hash

    def test_senha_confere_aceita_a_correta_e_rejeita_a_incorreta(self):
        u = Usuario.criar("x@empresa.com", SENHA)
        assert u.senha_confere(SENHA) is True
        assert u.senha_confere("outra") is False

    def test_cadastro_recusa_senha_vazia(self):
        with pytest.raises(ValueError):
            Usuario.criar("x@empresa.com", "")
