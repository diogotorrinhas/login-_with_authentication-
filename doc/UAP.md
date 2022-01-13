# Funcionamento UAP
Quando a UAP é executada pela primeira vez é pedido uma password mestra que vai ser utilizada para poder iniciar a uap e para criptografar os elementos de autenticação.


Caso o utilizador se tenha esquecido da password, pode apagar o ficheiro credentials.json.


A UAP vai trabalhar no endereço http://localhost:5050, e, por essa razão, as redireções enviadas pelo servidor irão parar a esse endereço.
A redireção será para um endereço do género: http://localhost:5050/login/http://127.0.0.1:5000/connect, onde 'http://127.0.0.1:5000/connect' é o endereço que a UAP deve usar para comunicar com o servidor. O browser será então redirecionado para um endereço semelhante a 'http://localhost:5050/pYyETspq' em que 'pYyETspq' é um endpoint gerado aleatoriamente que ficará associado ao endereço do servidor. De seguida é apresentado um formulário em que o utilizador pode colocar as suas credenciais, e escolher salvá-las em 'credentials.json'. Caso as suas credenciais já estejam salvas no ficheiro, o formulário irá aparecer preenchido com as mesmas. 


Caso o utilizador deseje guardar outras credenciais basta alterar o conteudo do formulário e selecionar 'Save credentials to database'.


A UAP vai gerar respostas com base num hash da password por sha256. Logo ambas as partes devem ter acesso a esse mesmo hash, sem salt.


Quando o formulário é então enviado, a UAP vai efetuar o processo de autenticação com o servidor, usando as credenciais recebidas. Em caso de sucesso, o utilizador é então redirecionado para onde o servidor indicar. Caso a autenticação tenha falhado, a página é recarregada e é mostrada uma mensagem de erro com alguma informação sobre o mesmo.


Ambas as partes continuam o processo de autenticação até ao fim, mesmo que o username tenha enviado ao servidor esteja errado. Desta forma não é possível procurar por usernames que se encontram na base de dados.
