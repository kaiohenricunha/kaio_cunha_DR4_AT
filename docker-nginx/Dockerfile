# Usa a imagem oficial do Nginx baseada no Alpine
FROM nginx:alpine

# Copia a configuração customizada para o diretório do Nginx
COPY default.conf /etc/nginx/conf.d/default.conf

# Copia o arquivo HTML para o diretório padrão de conteúdo do Nginx
COPY index.html /usr/share/nginx/html/index.html
