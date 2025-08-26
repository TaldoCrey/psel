# PATOS PSEL

Opa, essa é a minha tentativa de passar o PSEL do Patos!

## Sobre Mim
Antes dos detalhes técnicos, uma breve apresentação. Meu nome é Renan Machado Santos, atualmente estou no segundo semestre do BCC e tenho intenções de entrar para o PATOS visando aprender mais sobre open source, cybersec e afins.

## Detalhes técnicos
A linguagem utilizada neste repositório tanto para o server quanto para o reverse proxy será o Rust.

### Por que Rust?
Eu escolhi Rust pois queria me desafiar a aprender uma linguagem nova do zero e também pois das linguagens recomendadas pelo pessoal do PATOS, após uma breve pesquisa, Rust me parece uma das mais interessantes.
Eu aprendi Rust totalmente do zero seguindo os vídeos gratuitos de um gringo, pelo site: https://learn.letsgetrusty.com

Vale ressaltar que toda a minha evolução na linguagem Rust pode ser acompanhada pelo meu Repositório público: https://github.com/TaldoCrey/RustStudies, o qual contém meus códigos do absoluto 0 em rust até um protótipo deste mesmo projeto.

### Features do Projeto
#### Servidor
- Recebe requisições com um padrão customizado, interpreta e devolve uma resposta.
- Valida se a requisição veio do reverse proxy usando uma 'criptografia' (não sei se da pra chamar disso) :
    - Ao se iniciar o server e o reverse proxy, o server vai mandar um POST request regitrando uma chave SHA-256 gerada aleatóriamente no reverse proxy.
    - Após o registro, o server começa a verificar todas as requests, procurando um valor de X-Proxy-Signature que seja equivalente a chave registrada no proxy    anteriormente.

#### Reverse Proxy
- Recebe requisições com o padrão do navegador, interpreta e customiza elas antes de repassá-las para o servidor.
- Recebe a chave SHA-256 do servidor ao ser iniciado, armazena ela, e assina todas suas requests personalizadas com ela.
- Faz o parsing das requests para torná-las customizadas

#### Gerais
- Ao tentar acessar o servidor direto pelo seu ip, é retornada uma página 403 - Forbidden.
- O server fica tentando registrar a chave de assinatura no reverse proxy até que ele consiga. Ele não funcionará enquanto a chave não for registrada.
- O reverse proxy foi programado usando multi-threads (sem limite máximo de usuários) para que possa ser acessado por múltiplos dispositivos simultaneamente.
- O reverse proxy está sendo hospedado em 0.0.0.0, o que possibilita que ele seja acessado pelo celular (achei que ia ser legal ver os arquivos pelo cel).

### Algumas especificações
- Foram feitos dois projetos utilizando o cargo: server e reverse-proxy, cada um deles armazenando seu respectivo sistema.
- Dentro de cada projeto foram utilizadas as seguintes libs:
  - rand = 0.9.2
  - sha2 = 0.10.9
  - digest = 0.10
  - hex = 0.4
  - colored = 3
  Além, claro, dos pacotes da standard lib do Rust:
  - std::fs
  - std::net
  - std::io::prelude;
  - std::thread
  - std::path
  - std::sync
- As páginas .html estão todas dentro de uma pasta chamada /pages/, dentro do projeto do servidor.
- Os arquivos que podem ser acessados devem estar dentro de uma pasta /data/, dentro do projeto do servidor.

## Minha jornada
Fazer esse projeto foi meu primeiro contato com essa parte da web, eu já havia feito sites com html e css, mas só isso. Nunca tinha mexido com requisições e tudo mais.
Antes de começar a estudar os fundamentos de rede, eu primeiro estudei a linguagem Rust (estudo esse que está todo documentado no repositório supracitado). Vendo os vídeos do gringo eu achei que ela tinha uma boa semelhança com C e achei que seria mais uma linguagem de programação útil de saber. Acaba que até o dado momento, Rust se tornou minha linguagem predileta, pois tem muitas funcionalidades que nunca tinha visto e poderosas. Depois de chegar em um bom tanto de conhecimento de Rust, decidir começar os estudos sobre o server e o reverse proxy em Rust.

Sobre o aprendizado web, li os sites que o próprio Patos recomenda no readme do psel, mas confesso que quem me ajudou mesmo a entender tudo foi o Gemini Pro (cortesia do email institucional). Primeiro fui pedindo pra ele me explicar o que eram sockets, requests, parsing, um proxy e um reverse proxy. Depois disso, vi um vídeo do gringo ensinando a fazer um servidor single-thread. Testei, funcionou e daí pra frente foram 5 horas seguidas totalmente imerso na programação de um servidor e reverse proxy de teste. Pedi ajuda para o Gemini também para me ajudar a mexer com as libs que geram o SHA-256 pois não encontrei nenhum lugar que falasse muito resumidamente sobre isso. Além disso, a I.A. do google me ajudou a resolver alguns erros das minhas requests - que estavam dando errado e cagando tudo. Além disso, por não conseguir fazer uma página que me agradasse, também pedi pra ela fazer um index.html e um style.css pra eu usar (o que ferrou um pouco o routing precarizado das requests que eu tava fazendo).

No meu server e reverse proxy de estudo, que ta no rep já citado, o código ta todo bagunçado e um regaço. Mas foi o suficiente pra eu entender a ideia do que eu preciso fazer pra chegar em um resultado minimamente decente pra apresentar para o psel. Mesmo agora tendo aprendido bastante coisa nova, sinto que ainda sou bastante leigo nessa questão de redes, mas minha motivação pra entrar no PATOS é justamente poder me aprofundar nessa área, rodeado de pessoas que entendem bem do assunto. Além disso, quero aprender sobre cybersec e acho que o PATOS vai ser um ótimo lugar para isso!!!
Considero minha jornada "do 0 ao reverse proxy" um bom aprendizado no qual eu me diverti muito produzindo ele.

### Algumas Fontes
Vou listar algumas fontes que me ajudaram a coletar conhecimentos e produzir meu projeto:
- https://doc.rust-lang.org/std/ -> Ajuda com alguns módulos da std
- https://learn.letsgetrusty.com -> Aprender o básico de Rust
- https://youtu.be/BHxmWTVFWxQ?si=mmlUYXunmAcU2gVL -> Aprender a fazer um server básico em Rust
- https://developer.mozilla.org/pt-BR/docs/Web/HTTP -> Aprender algumas coisas sobre requests
- Google Gemini Pro (Cortesia do email institucional):
    - Uso da biblioteca sha2 para gerar um SHA-256 a partir de uma string
    - Uso do ponteiro inteligente Arc pra armazenar o SHA-256 sem dar erro do borrowing checker por conta das threads
    - Dúvidas gerais sobre especificidades relacionadas a requests padrões e personalizadas
