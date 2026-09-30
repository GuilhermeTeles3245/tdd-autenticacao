"""Autenticação de usuários (TDD: Red -> Green -> Refactor).

Fluxo de avaliação, na ordem (a primeira regra violada encerra o processo):

    1. Campos obrigatórios preenchidos   -> CAMPO_OBRIGATORIO
    2. Formato de e-mail válido          -> FORMATO_INVALIDO
    3. Usuário existe e a senha confere  -> CREDENCIAIS_INVALIDAS
    4. Usuário está ativo                -> USUARIO_INATIVO
    5. Usuário possui a permissão        -> SEM_PERMISSAO
    6. Tudo certo                        -> AUTORIZADO

Decisões de segurança:
  * A senha é guardada apenas como hash PBKDF2-HMAC-SHA256 com salt aleatório.
  * A comparação de hashes usa ``hmac.compare_digest`` (tempo constante).
  * E-mail inexistente e senha incorreta geram a mesma mensagem, e o status
    "inativo" só é revelado depois que a senha foi validada, para não expor
    quais contas existem.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from enum import Enum

PERMISSAO_ACESSO = "acessar_sistema"

_ALGORITMO_HASH = "sha256"
_ITERACOES_HASH = 100_000
_TAMANHO_SALT = 16
_PADRAO_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class CodigoResultado(Enum):
    """Motivo objetivo do resultado, útil para testes, logs e interface."""

    AUTORIZADO = "AUTORIZADO"
    CAMPO_OBRIGATORIO = "CAMPO_OBRIGATORIO"
    FORMATO_INVALIDO = "FORMATO_INVALIDO"
    CREDENCIAIS_INVALIDAS = "CREDENCIAIS_INVALIDAS"
    USUARIO_INATIVO = "USUARIO_INATIVO"
    SEM_PERMISSAO = "SEM_PERMISSAO"


_MENSAGENS = {
    CodigoResultado.AUTORIZADO: "Acesso autorizado.",
    CodigoResultado.CAMPO_OBRIGATORIO: "Informe e-mail e senha.",
    CodigoResultado.FORMATO_INVALIDO: "Formato de e-mail inválido.",
    CodigoResultado.CREDENCIAIS_INVALIDAS: "E-mail ou senha incorretos.",
    CodigoResultado.USUARIO_INATIVO: "Usuário inativo. Procure o administrador.",
    CodigoResultado.SEM_PERMISSAO: "Você não tem permissão para acessar.",
}


def normalizar_email(email: str) -> str:
    """Remove espaços nas pontas e padroniza em minúsculas."""
    return email.strip().lower()


def _gerar_hash(senha: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(_ALGORITMO_HASH, senha.encode("utf-8"),
                               salt, _ITERACOES_HASH)


@dataclass(frozen=True)
class Usuario:
    """Usuário cadastrado. Nunca guarda a senha em texto puro."""

    email: str
    senha_hash: bytes
    salt: bytes
    ativo: bool
    permissoes: frozenset

    @classmethod
    def criar(cls, email, senha, ativo=True, permissoes=()):
        if not senha:
            raise ValueError("A senha não pode ser vazia.")
        salt = os.urandom(_TAMANHO_SALT)
        return cls(normalizar_email(email), _gerar_hash(senha, salt), salt,
                   ativo, frozenset(permissoes))

    def senha_confere(self, senha: str) -> bool:
        return hmac.compare_digest(_gerar_hash(senha, self.salt),
                                   self.senha_hash)

    def possui_permissao(self, permissao: str) -> bool:
        return permissao in self.permissoes


@dataclass(frozen=True)
class ResultadoAutenticacao:
    autorizado: bool
    codigo: CodigoResultado
    mensagem: str
    usuario: Usuario | None = None


class RepositorioUsuarios:
    """Repositório em memória (substituível por banco de dados)."""

    def __init__(self):
        self._usuarios: dict[str, Usuario] = {}

    def adicionar(self, usuario: Usuario) -> None:
        self._usuarios[usuario.email] = usuario

    def buscar_por_email(self, email: str) -> Usuario | None:
        return self._usuarios.get(email)


class ServicoAutenticacao:
    """Regra de negócio de login."""

    def __init__(self, repositorio):
        self.repositorio = repositorio

    def autenticar(self, email, senha,
                   permissao_exigida: str = PERMISSAO_ACESSO
                   ) -> ResultadoAutenticacao:
        erro = self._validar_formulario(email, senha)
        if erro:
            return self._negar(erro)

        usuario = self.repositorio.buscar_por_email(normalizar_email(email))
        if usuario is None or not usuario.senha_confere(senha):
            return self._negar(CodigoResultado.CREDENCIAIS_INVALIDAS)
        if not usuario.ativo:
            return self._negar(CodigoResultado.USUARIO_INATIVO)
        if not usuario.possui_permissao(permissao_exigida):
            return self._negar(CodigoResultado.SEM_PERMISSAO)

        return ResultadoAutenticacao(True, CodigoResultado.AUTORIZADO,
                                     _MENSAGENS[CodigoResultado.AUTORIZADO],
                                     usuario)

    @staticmethod
    def _validar_formulario(email, senha) -> CodigoResultado | None:
        if not isinstance(email, str) or not email.strip() or not senha:
            return CodigoResultado.CAMPO_OBRIGATORIO
        if not _PADRAO_EMAIL.match(normalizar_email(email)):
            return CodigoResultado.FORMATO_INVALIDO
        return None

    @staticmethod
    def _negar(codigo: CodigoResultado) -> ResultadoAutenticacao:
        return ResultadoAutenticacao(False, codigo, _MENSAGENS[codigo])
