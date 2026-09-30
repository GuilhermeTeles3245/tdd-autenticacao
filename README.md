# Autenticação de usuários com TDD

Atividade de **Engenharia de Software (WYD6511 – 2026.2)** – Prof. Thalles Canela.
Autores: Guilherme Teles Pacheco (202502557051) e Lucas Paixão Cardoso Luis (202502325444).

Funcionalidade: autenticar o usuário verificando formulário (campos obrigatórios e
formato de e-mail), credenciais, se o usuário está **ativo**, e se possui a **permissão**
de acesso exigida. Desenvolvida com o ciclo **Red → Green → Refactor**
(veja `git log`: um commit por fase).

## Como executar

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest                                     # roda os 31 testes
python -m pytest --cov=autenticacao --cov-branch --cov-report=term-missing
```

## Estrutura

```
src/autenticacao.py          # regra de negócio (Usuario, RepositorioUsuarios, ServicoAutenticacao)
tests/test_autenticacao.py   # 31 testes automatizados (sucesso e erro)
pytest.ini                   # configura o caminho do código-fonte
```

## Exemplo de uso

```python
from autenticacao import Usuario, RepositorioUsuarios, ServicoAutenticacao

repo = RepositorioUsuarios()
repo.adicionar(Usuario.criar("ana@empresa.com", "Senha@123",
                             ativo=True, permissoes={"acessar_sistema"}))

resultado = ServicoAutenticacao(repo).autenticar("ana@empresa.com", "Senha@123")
print(resultado.autorizado, resultado.codigo.name, resultado.mensagem)
# True AUTORIZADO Acesso autorizado.
```
