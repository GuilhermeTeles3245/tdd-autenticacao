"""Autenticação de usuários - implementação mínima (fase GREEN do TDD)."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from enum import Enum


class CodigoResultado(Enum):
    AUTORIZADO = "AUTORIZADO"
    CAMPO_OBRIGATORIO = "CAMPO_OBRIGATORIO"
    FORMATO_INVALIDO = "FORMATO_INVALIDO"
    CREDENCIAIS_INVALIDAS = "CREDENCIAIS_INVALIDAS"
    USUARIO_INATIVO = "USUARIO_INATIVO"
    SEM_PERMISSAO = "SEM_PERMISSAO"


PERMISSAO_ACESSO = "acessar_sistema"


@dataclass(frozen=True)
class Usuario:
    email: str
    senha_hash: bytes
    salt: bytes
    ativo: bool
    permissoes: frozenset

    @classmethod
    def criar(cls, email, senha, ativo=True, permissoes=()):
        if not senha:
            raise ValueError("A senha não pode ser vazia.")
        salt = os.urandom(16)
        senha_hash = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, 100_000)
        return cls(email.strip().lower(), senha_hash, salt, ativo,
                   frozenset(permissoes))

    def senha_confere(self, senha) -> bool:
        hash_informado = hashlib.pbkdf2_hmac("sha256", senha.encode(),
                                             self.salt, 100_000)
        return hmac.compare_digest(hash_informado, self.senha_hash)


@dataclass(frozen=True)
class ResultadoAutenticacao:
    autorizado: bool
    codigo: CodigoResultado
    mensagem: str
    usuario: Usuario | None = None


class RepositorioUsuarios:
    def __init__(self):
        self._usuarios = {}

    def adicionar(self, usuario):
        self._usuarios[usuario.email] = usuario

    def buscar_por_email(self, email):
        return self._usuarios.get(email)


class ServicoAutenticacao:
    def __init__(self, repositorio):
        self.repositorio = repositorio

    def autenticar(self, email, senha, permissao_exigida=PERMISSAO_ACESSO):
        if not isinstance(email, str) or not email.strip() or not senha:
            return ResultadoAutenticacao(False, CodigoResultado.CAMPO_OBRIGATORIO,
                                         "Informe e-mail e senha.")
        email = email.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return ResultadoAutenticacao(False, CodigoResultado.FORMATO_INVALIDO,
                                         "Formato de e-mail inválido.")
        usuario = self.repositorio.buscar_por_email(email)
        if usuario is None or not usuario.senha_confere(senha):
            return ResultadoAutenticacao(False,
                                         CodigoResultado.CREDENCIAIS_INVALIDAS,
                                         "E-mail ou senha incorretos.")
        if not usuario.ativo:
            return ResultadoAutenticacao(False, CodigoResultado.USUARIO_INATIVO,
                                         "Usuário inativo. Procure o administrador.")
        if permissao_exigida not in usuario.permissoes:
            return ResultadoAutenticacao(False, CodigoResultado.SEM_PERMISSAO,
                                         "Você não tem permissão para acessar.")
        return ResultadoAutenticacao(True, CodigoResultado.AUTORIZADO,
                                     "Acesso autorizado.", usuario)
