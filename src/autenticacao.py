"""Autenticação de usuários - esqueleto inicial (fase RED do TDD).

Somente as assinaturas existem; nenhum comportamento foi implementado.
"""
from __future__ import annotations

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
        raise NotImplementedError

    def senha_confere(self, senha) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class ResultadoAutenticacao:
    autorizado: bool
    codigo: CodigoResultado
    mensagem: str
    usuario: Usuario | None = None


class RepositorioUsuarios:
    def adicionar(self, usuario):
        raise NotImplementedError

    def buscar_por_email(self, email):
        raise NotImplementedError


class ServicoAutenticacao:
    def __init__(self, repositorio):
        self.repositorio = repositorio

    def autenticar(self, email, senha, permissao_exigida=PERMISSAO_ACESSO):
        raise NotImplementedError
